//! How tinyvmm stops the VM when the user asks: by closing the --gpu window,
//! with Ctrl+A S on the console, or with Ctrl+C, Ctrl+Break or closing the
//! console when those reach tinyvmm rather than the guest. It asks the guest to
//! shut down, through VMBus's shutdown IC as Hyper-V does, and gives it a
//! minute. A guest it can't ask (no VMBus, or a kernel that hasn't opened the
//! IC) or that doesn't stop in time gets SysRq on hvc0 instead: it syncs and
//! remounts its filesystems read-only, and the VM stops once its disks settle.
//! Asking again stops at once, as Ctrl+A X does.

use crate::virtio::blk::BlockDevice;
use crate::virtio::console::ConsoleDevice;
use crate::vmbus::shutdown::Shutdown;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::core::BOOL;

/// How long the guest has to take a shutdown request, and then to stop.
#[derive(Clone, Copy)]
struct Patience {
    answer: Duration,
    stop: Duration,
}

const ASKED: Patience = Patience {
    answer: Duration::from_secs(5),
    stop: Duration::from_secs(60),
};
/// The console is closing, and Windows ends the process 5 s on.
const CLOSING: Patience = Patience {
    answer: Duration::from_secs(1),
    stop: Duration::from_secs(2),
};
const CLOSING_GRACE: Duration = Duration::from_millis(4500);

/// The SysRq fallback: hvc0, a kernel console, and the disks to watch settle.
pub struct SysRq {
    pub console: Arc<ConsoleDevice>,
    pub disks: Vec<Arc<BlockDevice>>,
}

/// Stops the VM when the user asks; see the module.
#[derive(Clone)]
pub struct GracefulStop(Arc<Inner>);

struct Inner {
    tag: &'static str,
    shutdown: Option<Shutdown>,
    /// None when hvc0 isn't a kernel console, so SysRq would reach a tty.
    sysrq: Option<SysRq>,
    /// The vCPUs' stop flags: one set means the VM is stopping, whyever.
    flags: Vec<Arc<AtomicBool>>,
    /// Stops every vCPU. Teardown takes it, so nothing stops a deleted
    /// partition.
    stop_all: Mutex<Option<Box<dyn Fn() + Send>>>,
    begun: AtomicBool,
}

/// Where Ctrl+C, Ctrl+Break and closing the console go while the VM runs.
static CONSOLE: Mutex<Option<GracefulStop>> = Mutex::new(None);

impl GracefulStop {
    pub fn new(
        tag: &'static str,
        shutdown: Option<Shutdown>,
        sysrq: Option<SysRq>,
        flags: Vec<Arc<AtomicBool>>,
        stop_all: impl Fn() + Send + 'static,
    ) -> Self {
        GracefulStop(Arc::new(Inner {
            tag,
            shutdown,
            sysrq,
            flags,
            stop_all: Mutex::new(Some(Box::new(stop_all))),
            begun: AtomicBool::new(false),
        }))
    }

    /// Take Ctrl+C, Ctrl+Break and closing the console until [`Self::disarm`].
    /// Ctrl+C reaches tinyvmm only when stdin isn't an interactive console,
    /// which passes it to the guest.
    pub fn take_console_events(&self) {
        static INSTALL: Once = Once::new();
        *CONSOLE.lock().unwrap() = Some(self.clone());
        INSTALL.call_once(|| {
            // SAFETY: the handler is a function, valid for the process's life.
            unsafe { SetConsoleCtrlHandler(Some(console_event), 1) };
        });
    }

    /// Teardown has begun: stop nothing from now on, and leave the console's
    /// events to Windows again.
    pub fn disarm(&self) {
        self.0.stop_all.lock().unwrap().take();
        CONSOLE.lock().unwrap().take();
    }

    /// Stop every vCPU now, unless teardown has begun.
    pub fn now(&self) {
        if let Some(stop_all) = &*self.0.stop_all.lock().unwrap() {
            stop_all();
        }
    }

    /// The user asked to stop, by `why`; see the module. Returns at once.
    pub fn begin(&self, why: &'static str) {
        self.start(why, ASKED);
    }

    fn stopping(&self) -> bool {
        self.0.flags.iter().any(|f| f.load(Ordering::Acquire))
    }

    fn start(&self, why: &'static str, patience: Patience) {
        if self.stopping() {
            return;
        }
        if self.0.begun.swap(true, Ordering::AcqRel) {
            eprintln!("\r\n[{}] {why} -- stopping now", self.0.tag);
            self.now();
            return;
        }
        let this = self.clone();
        let _ = std::thread::Builder::new()
            .name("graceful-stop".into())
            .spawn(move || this.run(why, patience));
    }

    fn run(&self, why: &str, patience: Patience) {
        let tag = self.0.tag;
        if let Some(shutdown) = &self.0.shutdown
            && shutdown.request(patience.answer)
        {
            eprintln!("\r\n[{tag}] {why} -- the guest is shutting down");
            let deadline = Instant::now() + patience.stop;
            while Instant::now() < deadline {
                if self.stopping() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!(
                "\r\n[{tag}] the guest is still running {} s later",
                patience.stop.as_secs()
            );
        }
        match &self.0.sysrq {
            Some(sysrq) => {
                eprintln!(
                    "\r\n[{tag}] {why} -- remounting the guest's filesystems read-only \
                     (SysRq s, u), then stopping"
                );
                sysrq.console.write_host_input(b"\x0fs\x0fu");
                wait_for_disks_to_settle(&sysrq.disks);
            }
            None => eprintln!(
                "\r\n[{tag}] {why} -- stopping (hvc0 is not a kernel console, so no SysRq sync)"
            ),
        }
        self.now();
    }
}

unsafe extern "system" fn console_event(event: u32) -> BOOL {
    let Some(stop) = CONSOLE.lock().unwrap().clone() else {
        return 0;
    };
    match event {
        CTRL_C_EVENT => stop.begin("Ctrl+C"),
        CTRL_BREAK_EVENT => stop.begin("Ctrl+Break"),
        // The console is closing, or the user logging off: Windows ends the
        // process when this returns, or 5 s on, so take the time.
        _ => {
            stop.start("console closed", CLOSING);
            std::thread::sleep(CLOSING_GRACE);
        }
    }
    1
}

/// Wait until the guest's disks have settled: nothing in flight and no write,
/// flush, discard or write-zeroes for a second. The SysRq work runs
/// asynchronously in the guest, so wait at least half a second first, and at
/// most 15 seconds in all.
fn wait_for_disks_to_settle(disks: &[Arc<BlockDevice>]) {
    const MIN_WAIT: Duration = Duration::from_millis(500);
    const QUIET: Duration = Duration::from_secs(1);
    const MAX_WAIT: Duration = Duration::from_secs(15);
    let writes = || -> u64 {
        disks
            .iter()
            .map(|d| d.ops_out() + d.ops_flush() + d.ops_discard() + d.ops_write_zeroes())
            .sum()
    };
    let start = Instant::now();
    let mut last = writes();
    let mut quiet_since = start;
    loop {
        std::thread::sleep(Duration::from_millis(50));
        let now = Instant::now();
        let w = writes();
        if w != last || disks.iter().any(|d| d.pending_count() > 0) {
            last = w;
            quiet_since = now;
        }
        let waited = now - start;
        if waited >= MAX_WAIT || (waited >= MIN_WAIT && now - quiet_since >= QUIET) {
            return;
        }
    }
}
