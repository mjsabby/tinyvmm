//! A single Win32 GDI window that presents the guest's virtio-gpu scanout via a
//! CPU blit (`StretchDIBits`). The window owns its own thread + message pump
//! (Win32 requires the creating thread to service the window's messages); the
//! device thread calls [`Display::present`] from outside.
//!
//! Threading model:
//! * The window thread creates the window, stores its `HWND` (so other threads
//!   can post to it), then runs `GetMessage`/`DispatchMessage` until quit.
//! * [`Display::present`] (called on the vCPU / virtio drain thread) copies the
//!   BGRA frame into a shared buffer under a short mutex, then `PostMessage`s a
//!   coalesced repaint/resize request to the window thread. The actual GDI blit
//!   happens on the window thread in `WM_PAINT`, so no GDI object is touched
//!   cross-thread.
//!
//! Input seam (for the separate virtio-input device): the window proc translates
//! raw Win32 keyboard/pointer/wheel/focus messages into a neutral
//! [`WindowEvent`] and hands them to an optional sink installed via
//! [`Display::set_input_sink`]. The window's client area is kept exactly equal
//! to the scanout framebuffer (non-resizable), so pointer client coordinates map
//! 1:1 onto guest-framebuffer pixels — convenient for an absolute-pointer
//! (`EV_ABS`) virtio-input backend.

#![allow(non_snake_case)]

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, InvalidateRect, SetStretchBltMode, StretchDIBits, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, COLORONCOLOR, DIB_RGB_COLORS, PAINTSTRUCT, SRCCOPY,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW,
    GetWindowLongPtrW, LoadCursorW, PostMessageW, PostQuitMessage, RegisterClassW,
    SetWindowLongPtrW, SetWindowPos, ShowWindow, TranslateMessage, CREATESTRUCTW, CW_USEDEFAULT,
    GWLP_USERDATA, IDC_ARROW, MSG, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SW_SHOW, WM_APP,
    WM_CLOSE, WM_DESTROY, WM_ERASEBKGND, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL,
    WM_NCCREATE, WM_PAINT, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SETFOCUS, WM_SIZE, WM_SYSKEYDOWN,
    WM_SYSKEYUP, WM_XBUTTONDOWN, WM_XBUTTONUP, WNDCLASSW, WS_CAPTION, WS_MINIMIZEBOX, WS_OVERLAPPED,
    WS_SYSMENU, WS_VISIBLE,
};

/// Custom messages posted from the present thread to the window thread.
const WM_APP_PAINT: u32 = WM_APP + 1;
const WM_APP_RESIZE: u32 = WM_APP + 2;

/// A mouse button, as reported in [`WindowEvent::Button`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    /// Side buttons (XBUTTON1 / XBUTTON2).
    X1,
    X2,
}

/// A neutral, backend-agnostic window input event. The virtio-input device
/// installs a sink (see [`Display::set_input_sink`]) to consume these. Pointer
/// coordinates are window-client pixels which, because the client area equals
/// the scanout framebuffer, are also guest-framebuffer pixels.
#[derive(Clone, Copy, Debug)]
pub enum WindowEvent {
    /// A key transition. `vkey` is the Win32 virtual-key code, `scancode` the
    /// set-1 make code, `extended` the E0 prefix flag, `repeat` true for
    /// auto-repeat (key was already down).
    Key {
        vkey: u16,
        scancode: u16,
        extended: bool,
        pressed: bool,
        repeat: bool,
    },
    /// Absolute pointer motion to client pixel (x, y).
    PointerMotion { x: i32, y: i32 },
    /// A pointer button transition at client pixel (x, y).
    Button {
        button: MouseButton,
        pressed: bool,
        x: i32,
        y: i32,
    },
    /// Wheel motion in WHEEL_DELTA (120) units. `dy` > 0 is scroll-up, `dx` > 0
    /// is scroll-right.
    Wheel { dx: i32, dy: i32 },
    /// Keyboard focus gained/lost.
    Focus { gained: bool },
    /// Client area resized to (width, height) pixels (tracks framebuffer size).
    Resized { width: u32, height: u32 },
    /// The user closed the window.
    CloseRequested,
}

type InputSink = Box<dyn FnMut(WindowEvent) + Send>;

struct Frame {
    /// BGRA, top-down, tightly packed (`stride == width * 4`).
    buf: Vec<u8>,
    width: u32,
    height: u32,
}

/// State shared between the window thread (via the `HWND`'s user-data pointer)
/// and the present/control threads.
struct Shared {
    frame: Mutex<Frame>,
    input: Mutex<Option<InputSink>>,
    hwnd: AtomicIsize,
    open: AtomicBool,
    /// True while a `WM_APP_PAINT` is already queued; bounds the post rate.
    paint_pending: AtomicBool,
}

/// A live display window. Dropping it (or calling [`Display::shutdown`]) closes
/// the window and joins its thread.
pub struct Display {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[inline]
fn lo_i16(v: u32) -> i32 {
    (v & 0xFFFF) as u16 as i16 as i32
}
#[inline]
fn hi_i16(v: u32) -> i32 {
    ((v >> 16) & 0xFFFF) as u16 as i16 as i32
}

impl Display {
    /// Create a window with an initial client size of `width`x`height` and the
    /// given title bar text, spawning its message-pump thread. Returns `None`
    /// if the window could not be created.
    pub fn new(title: &str, width: u32, height: u32) -> Option<Arc<Display>> {
        let width = width.max(1);
        let height = height.max(1);
        let shared = Arc::new(Shared {
            frame: Mutex::new(Frame {
                buf: vec![0u8; (width as usize) * (height as usize) * 4],
                width,
                height,
            }),
            input: Mutex::new(None),
            hwnd: AtomicIsize::new(0),
            open: AtomicBool::new(false),
            paint_pending: AtomicBool::new(false),
        });

        let (tx, rx) = std::sync::mpsc::channel::<isize>();
        let title = title.to_string();
        let thread_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("virtio-gpu-display".to_string())
            .spawn(move || window_thread(thread_shared, title, width, height, tx))
            .ok()?;

        // Block until the window thread reports the HWND (or 0 on failure).
        let hwnd = rx.recv().unwrap_or(0);
        if hwnd == 0 {
            let _ = thread.join();
            return None;
        }
        shared.open.store(true, Ordering::Release);

        Some(Arc::new(Display {
            shared,
            thread: Mutex::new(Some(thread)),
        }))
    }

    /// Whether the window is still open (not yet closed by the user / shutdown).
    pub fn is_open(&self) -> bool {
        self.shared.open.load(Ordering::Acquire)
    }

    /// Install (or replace) the input sink that receives translated
    /// [`WindowEvent`]s. Intended for the virtio-input device.
    pub fn set_input_sink(&self, sink: InputSink) {
        *self.shared.input.lock().unwrap() = Some(sink);
    }

    /// Present a BGRA (top-down, `stride == width*4`) frame of `width`x`height`.
    /// Cheap: copies into a shared buffer and posts a coalesced repaint to the
    /// window thread. A no-op once the window has closed.
    pub fn present(&self, bgra: &[u8], width: u32, height: u32) {
        if !self.shared.open.load(Ordering::Acquire) {
            return;
        }
        let hwnd = self.shared.hwnd.load(Ordering::Acquire);
        if hwnd == 0 {
            return;
        }
        let need = (width as usize) * (height as usize) * 4;
        if bgra.len() < need || need == 0 {
            return;
        }

        let mut resized = false;
        {
            let mut f = self.shared.frame.lock().unwrap();
            if f.width != width || f.height != height {
                resized = true;
                f.width = width;
                f.height = height;
            }
            if f.buf.len() != need {
                f.buf.resize(need, 0);
            }
            f.buf.copy_from_slice(&bgra[..need]);
        }

        let hwnd = hwnd as *mut c_void;
        unsafe {
            if resized {
                PostMessageW(hwnd, WM_APP_RESIZE, width as WPARAM, height as LPARAM);
            }
            // Coalesce: only post a paint if one isn't already queued.
            if !self.shared.paint_pending.swap(true, Ordering::AcqRel) {
                PostMessageW(hwnd, WM_APP_PAINT, 0, 0);
            }
        }
    }

    /// Close the window and join its thread. Idempotent.
    pub fn shutdown(&self) {
        if self.shared.open.swap(false, Ordering::AcqRel) {
            let hwnd = self.shared.hwnd.load(Ordering::Acquire);
            if hwnd != 0 {
                unsafe {
                    PostMessageW(hwnd as *mut c_void, WM_CLOSE, 0, 0);
                }
            }
        }
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn window_thread(
    shared: Arc<Shared>,
    title: String,
    width: u32,
    height: u32,
    ready: std::sync::mpsc::Sender<isize>,
) {
    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("tinyvmm_virtio_gpu_window");
        let cursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW);

        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: cursor,
            // Null background brush: we paint every pixel ourselves, so skipping
            // the system erase avoids flicker.
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        // RegisterClassW returns 0 on failure; a benign failure here is a class
        // that already exists (e.g. a second display), which is fine.
        RegisterClassW(&wc);

        // Fixed-size window: client area tracks the framebuffer exactly.
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
        let (ww, wh) = outer_size(width, height, style);

        let title_w = wide(&title);
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title_w.as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            ww,
            wh,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            Arc::as_ptr(&shared) as *const c_void,
        );

        if hwnd.is_null() {
            let _ = ready.send(0);
            return;
        }

        shared.hwnd.store(hwnd as isize, Ordering::Release);
        ShowWindow(hwnd, SW_SHOW);
        let _ = ready.send(hwnd as isize);

        // Standard message pump. GetMessageW returns 0 on WM_QUIT, -1 on error.
        let mut msg: MSG = std::mem::zeroed();
        loop {
            let r = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
            if r <= 0 {
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        shared.hwnd.store(0, Ordering::Release);
        shared.open.store(false, Ordering::Release);
    }
}

/// Compute the outer window size needed for a `cw`x`ch` client area.
fn outer_size(cw: u32, ch: u32, style: u32) -> (i32, i32) {
    let mut r = RECT {
        left: 0,
        top: 0,
        right: cw as i32,
        bottom: ch as i32,
    };
    unsafe {
        AdjustWindowRectEx(&mut r, style, 0, 0);
    }
    (r.right - r.left, r.bottom - r.top)
}

fn shared_ptr(hwnd: HWND) -> *const Shared {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Shared }
}

/// Deliver a translated event to the installed input sink, if any.
fn emit(shared: &Shared, ev: WindowEvent) {
    if let Ok(mut guard) = shared.input.lock() {
        if let Some(sink) = guard.as_mut() {
            sink(ev);
        }
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Stash the Shared pointer on first message so later messages can find it.
    if msg == WM_NCCREATE {
        let cs = lparam as *const CREATESTRUCTW;
        if !cs.is_null() {
            let p = (*cs).lpCreateParams as isize;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, p);
        }
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    let sp = shared_ptr(hwnd);
    if sp.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    let shared = &*sp;

    match msg {
        WM_APP_PAINT => {
            shared.paint_pending.store(false, Ordering::Release);
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_APP_RESIZE => {
            let cw = wparam as u32;
            let ch = lparam as u32;
            let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
            let (ww, wh) = outer_size(cw, ch, style);
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                0,
                0,
                ww,
                wh,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_ERASEBKGND => 1, // we paint everything; skip the erase to avoid flicker
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);
            if !hdc.is_null() {
                let f = shared.frame.lock().unwrap();
                if f.width > 0 && f.height > 0 && f.buf.len() >= (f.width * f.height * 4) as usize {
                    let mut bmi: BITMAPINFO = std::mem::zeroed();
                    bmi.bmiHeader = BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: f.width as i32,
                        // Negative height => top-down DIB (row 0 is the top).
                        biHeight: -(f.height as i32),
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB,
                        biSizeImage: 0,
                        biXPelsPerMeter: 0,
                        biYPelsPerMeter: 0,
                        biClrUsed: 0,
                        biClrImportant: 0,
                    };
                    SetStretchBltMode(hdc, COLORONCOLOR);
                    StretchDIBits(
                        hdc,
                        0,
                        0,
                        f.width as i32,
                        f.height as i32,
                        0,
                        0,
                        f.width as i32,
                        f.height as i32,
                        f.buf.as_ptr() as *const c_void,
                        &bmi,
                        DIB_RGB_COLORS,
                        SRCCOPY,
                    );
                }
            }
            EndPaint(hwnd, &ps);
            0
        }
        WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP => {
            let pressed = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
            let l = lparam as u32;
            let scancode = ((l >> 16) & 0xFF) as u16;
            let extended = (l >> 24) & 1 != 0;
            let repeat = pressed && ((l >> 30) & 1 != 0);
            emit(
                shared,
                WindowEvent::Key {
                    vkey: (wparam & 0xFFFF) as u16,
                    scancode,
                    extended,
                    pressed,
                    repeat,
                },
            );
            // Keep default behaviour (Alt+F4 close, system menu, WM_CHAR).
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_MOUSEMOVE => {
            let l = lparam as u32;
            emit(
                shared,
                WindowEvent::PointerMotion {
                    x: lo_i16(l),
                    y: hi_i16(l),
                },
            );
            0
        }
        WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_XBUTTONDOWN | WM_LBUTTONUP
        | WM_RBUTTONUP | WM_MBUTTONUP | WM_XBUTTONUP => {
            let pressed = matches!(
                msg,
                WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_XBUTTONDOWN
            );
            let button = match msg {
                WM_LBUTTONDOWN | WM_LBUTTONUP => MouseButton::Left,
                WM_RBUTTONDOWN | WM_RBUTTONUP => MouseButton::Right,
                WM_MBUTTONDOWN | WM_MBUTTONUP => MouseButton::Middle,
                _ => {
                    if hi_i16(wparam as u32) == 2 {
                        MouseButton::X2
                    } else {
                        MouseButton::X1
                    }
                }
            };
            // Capture during a drag so motion/up outside the window still arrive.
            if pressed {
                SetCapture(hwnd);
            } else {
                ReleaseCapture();
            }
            let l = lparam as u32;
            emit(
                shared,
                WindowEvent::Button {
                    button,
                    pressed,
                    x: lo_i16(l),
                    y: hi_i16(l),
                },
            );
            0
        }
        WM_MOUSEWHEEL => {
            emit(
                shared,
                WindowEvent::Wheel {
                    dx: 0,
                    dy: hi_i16(wparam as u32),
                },
            );
            0
        }
        WM_MOUSEHWHEEL => {
            emit(
                shared,
                WindowEvent::Wheel {
                    dx: hi_i16(wparam as u32),
                    dy: 0,
                },
            );
            0
        }
        WM_SETFOCUS => {
            emit(shared, WindowEvent::Focus { gained: true });
            0
        }
        WM_KILLFOCUS => {
            emit(shared, WindowEvent::Focus { gained: false });
            0
        }
        WM_SIZE => {
            let l = lparam as u32;
            emit(
                shared,
                WindowEvent::Resized {
                    width: (l & 0xFFFF),
                    height: ((l >> 16) & 0xFFFF),
                },
            );
            0
        }
        WM_CLOSE => {
            shared.open.store(false, Ordering::Release);
            emit(shared, WindowEvent::CloseRequested);
            // Destroy the window -> WM_DESTROY -> PostQuitMessage -> pump exits.
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runtime smoke test for the Win32 window pipeline. Opt-in (it spawns a
    /// real, briefly-visible window) so plain `cargo test` / CI never pops a
    /// window: run with `TINYVMM_DISPLAY_SELFTEST=1 cargo test display`.
    #[test]
    fn window_present_and_shutdown() {
        if std::env::var_os("TINYVMM_DISPLAY_SELFTEST").is_none() {
            return;
        }
        let (w, h) = (256u32, 128u32);
        let Some(d) = Display::new("tinyvmm gpu selftest", w, h) else {
            eprintln!("display unavailable (no window station?); skipping");
            return;
        };
        assert!(d.is_open());
        let mut buf = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 4) as usize;
                buf[i] = x as u8; // B
                buf[i + 1] = y as u8; // G
                buf[i + 2] = 0x80; // R
                buf[i + 3] = 0xFF; // X
            }
        }
        // Present a couple of frames and let the pump service the paints.
        d.present(&buf, w, h);
        std::thread::sleep(std::time::Duration::from_millis(120));
        d.present(&buf, w, h);
        std::thread::sleep(std::time::Duration::from_millis(120));
        d.shutdown();
        assert!(!d.is_open());
    }
}

