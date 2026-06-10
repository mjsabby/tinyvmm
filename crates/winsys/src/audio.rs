//! Minimal WASAPI (Windows Audio Session API) shared-mode render + capture,
//! hand-rolled over `windows-sys`.
//!
//! `windows-sys` ships the WASAPI *constants/structs/CLSIDs* but **no COM
//! interface vtables**, so the IMMDeviceEnumerator / IMMDevice / IAudioClient /
//! IAudioRenderClient / IAudioCaptureClient vtables are declared here by hand and
//! invoked through their function pointers. As with the rest of `winsys`, all of
//! the COM/FFI `unsafe` is concentrated and audited in this one module; callers
//! (the virtio-snd device) use the safe [`RenderClient`] / [`CaptureClient`] /
//! [`Event`] / [`ComInit`] wrappers and stay `unsafe`-free.
//!
//! Both clients are opened in **shared mode** at a fixed
//! 48 kHz / S16_LE / stereo format, with `AUTOCONVERTPCM | SRC_DEFAULT_QUALITY`
//! so the audio engine resamples/reformats to the endpoint's mix format. The
//! guest PCM and the WASAPI buffer therefore share the exact same byte layout and
//! the data path is a plain `copy_from_slice` (no per-buffer allocation, no DSP).

use core::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Media::Audio::WAVEFORMATEX;
use windows_sys::Win32::System::Com::{
    CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};
use windows_sys::core::{GUID, HRESULT};

/// Fixed guest/host PCM contract: 48 kHz, signed 16-bit LE, 2 channels.
pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: u16 = 2;
pub const BITS_PER_SAMPLE: u16 = 16;
/// Bytes per audio frame (one sample for every channel): 2ch * 16-bit = 4.
pub const FRAME_BYTES: u32 = (CHANNELS as u32) * (BITS_PER_SAMPLE as u32) / 8;

/// Wait "forever" (Win32 `INFINITE`).
pub const INFINITE: u32 = 0xFFFF_FFFF;

// ---- GUIDs (CLSID + IIDs not surfaced by windows-sys) ----
const CLSID_MM_DEVICE_ENUMERATOR: GUID = GUID::from_u128(0xBCDE0395_E52F_467C_8E3D_C4579291692E);
const IID_IMM_DEVICE_ENUMERATOR: GUID = GUID::from_u128(0xA95664D2_9614_4F35_A746_DE8DB63617E6);
const IID_IAUDIO_CLIENT: GUID = GUID::from_u128(0x1CB9AD4C_DBFA_4C32_B178_C2F568A703B2);
const IID_IAUDIO_RENDER_CLIENT: GUID = GUID::from_u128(0xF294ACFC_3146_4483_A7BF_ADDCA7C260E2);
const IID_IAUDIO_CAPTURE_CLIENT: GUID = GUID::from_u128(0xC8ADBD64_E71E_48A0_A4DE_185C395CD317);

// ---- EDataFlow / ERole ----
const E_RENDER: i32 = 0;
const E_CAPTURE: i32 = 1;
const E_CONSOLE: i32 = 0;

// ---- AUDCLNT_SHAREMODE / stream flags / buffer flags ----
const AUDCLNT_SHAREMODE_SHARED: i32 = 0;
const AUDCLNT_STREAMFLAGS_EVENTCALLBACK: u32 = 0x0004_0000;
const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x8000_0000;
const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x0800_0000;
const AUDCLNT_BUFFERFLAGS_SILENT: u32 = 0x2;

const WAVE_FORMAT_PCM: u16 = 1;
/// Shared-mode buffer capacity request, in 100-ns units (40 ms). The engine
/// rounds this; the actual size is read back via `GetBufferSize`.
const BUFFER_DURATION_HNS: i64 = 400_000;

#[inline]
fn failed(hr: HRESULT) -> bool {
    hr < 0
}

// =====================================================================
// Hand-rolled COM vtables. Only the methods we call are typed; the slots
// before them are pointer-sized placeholders so the vtable offsets line up.
// =====================================================================

#[repr(C)]
struct IMMDeviceEnumeratorVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    enum_audio_endpoints: usize,
    get_default_audio_endpoint:
        unsafe extern "system" fn(*mut c_void, i32, i32, *mut *mut c_void) -> HRESULT,
    get_device: usize,
    register_endpoint_notification_callback: usize,
    unregister_endpoint_notification_callback: usize,
}
#[repr(C)]
struct IMMDeviceEnumerator {
    vtbl: *const IMMDeviceEnumeratorVtbl,
}

#[repr(C)]
struct IMMDeviceVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    activate: unsafe extern "system" fn(
        *mut c_void,
        *const GUID,
        u32,
        *const c_void,
        *mut *mut c_void,
    ) -> HRESULT,
    open_property_store: usize,
    get_id: usize,
    get_state: usize,
}
#[repr(C)]
struct IMMDevice {
    vtbl: *const IMMDeviceVtbl,
}

#[repr(C)]
struct IAudioClientVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    initialize: unsafe extern "system" fn(
        *mut c_void,
        i32,
        u32,
        i64,
        i64,
        *const WAVEFORMATEX,
        *const GUID,
    ) -> HRESULT,
    get_buffer_size: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT,
    get_stream_latency: usize,
    get_current_padding: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT,
    is_format_supported: usize,
    get_mix_format: usize,
    get_device_period: usize,
    start: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    stop: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    reset: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    set_event_handle: unsafe extern "system" fn(*mut c_void, HANDLE) -> HRESULT,
    get_service: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
}
#[repr(C)]
struct IAudioClient {
    vtbl: *const IAudioClientVtbl,
}

#[repr(C)]
struct IAudioRenderClientVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    get_buffer: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u8) -> HRESULT,
    release_buffer: unsafe extern "system" fn(*mut c_void, u32, u32) -> HRESULT,
}
#[repr(C)]
struct IAudioRenderClient {
    vtbl: *const IAudioRenderClientVtbl,
}

#[repr(C)]
struct IAudioCaptureClientVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    get_buffer: unsafe extern "system" fn(
        *mut c_void,
        *mut *mut u8,
        *mut u32,
        *mut u32,
        *mut u64,
        *mut u64,
    ) -> HRESULT,
    release_buffer: unsafe extern "system" fn(*mut c_void, u32) -> HRESULT,
    get_next_packet_size: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT,
}
#[repr(C)]
struct IAudioCaptureClient {
    vtbl: *const IAudioCaptureClientVtbl,
}

/// Build the fixed 48 kHz / S16 / stereo `WAVEFORMATEX`.
fn wave_format() -> WAVEFORMATEX {
    WAVEFORMATEX {
        wFormatTag: WAVE_FORMAT_PCM,
        nChannels: CHANNELS,
        nSamplesPerSec: SAMPLE_RATE,
        nAvgBytesPerSec: SAMPLE_RATE * FRAME_BYTES,
        nBlockAlign: FRAME_BYTES as u16,
        wBitsPerSample: BITS_PER_SAMPLE,
        cbSize: 0,
    }
}

/// Open the default endpoint for `data_flow` and activate its `IAudioClient`,
/// initialised in shared event-driven mode with auto-conversion. Returns the
/// initialised client pointer + its buffer size in frames. `unsafe` internally;
/// returns `None` on any failure (caller falls back to silent mode).
fn open_audio_client(data_flow: i32, event: HANDLE) -> Option<(*mut IAudioClient, u32)> {
    unsafe {
        let mut enumerator: *mut IMMDeviceEnumerator = core::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_MM_DEVICE_ENUMERATOR,
            core::ptr::null_mut(),
            CLSCTX_ALL,
            &IID_IMM_DEVICE_ENUMERATOR,
            (&mut enumerator as *mut *mut IMMDeviceEnumerator).cast(),
        );
        if failed(hr) || enumerator.is_null() {
            return None;
        }

        let mut device: *mut IMMDevice = core::ptr::null_mut();
        let hr = ((*(*enumerator).vtbl).get_default_audio_endpoint)(
            enumerator.cast(),
            data_flow,
            E_CONSOLE,
            (&mut device as *mut *mut IMMDevice).cast(),
        );
        ((*(*enumerator).vtbl).release)(enumerator.cast());
        if failed(hr) || device.is_null() {
            return None;
        }

        let mut client: *mut IAudioClient = core::ptr::null_mut();
        let hr = ((*(*device).vtbl).activate)(
            device.cast(),
            &IID_IAUDIO_CLIENT,
            CLSCTX_ALL,
            core::ptr::null(),
            (&mut client as *mut *mut IAudioClient).cast(),
        );
        ((*(*device).vtbl).release)(device.cast());
        if failed(hr) || client.is_null() {
            return None;
        }

        let fmt = wave_format();
        let flags = AUDCLNT_STREAMFLAGS_EVENTCALLBACK
            | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
            | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
        let hr = ((*(*client).vtbl).initialize)(
            client.cast(),
            AUDCLNT_SHAREMODE_SHARED,
            flags,
            BUFFER_DURATION_HNS,
            0,
            &fmt,
            core::ptr::null(),
        );
        if failed(hr) {
            ((*(*client).vtbl).release)(client.cast());
            return None;
        }

        let mut frames: u32 = 0;
        if failed(((*(*client).vtbl).get_buffer_size)(
            client.cast(),
            &mut frames,
        )) || frames == 0
        {
            ((*(*client).vtbl).release)(client.cast());
            return None;
        }
        if failed(((*(*client).vtbl).set_event_handle)(client.cast(), event)) {
            ((*(*client).vtbl).release)(client.cast());
            return None;
        }
        Some((client, frames))
    }
}

/// Shared-mode WASAPI render (playback) endpoint. Single-threaded: created and
/// used only on the owning worker thread.
pub struct RenderClient {
    client: *mut IAudioClient,
    render: *mut IAudioRenderClient,
    buffer_frames: u32,
}

impl RenderClient {
    /// Open the default render endpoint, signalling `event` when the engine
    /// needs more data. `None` if no endpoint is available.
    pub fn open(event: &Event) -> Option<RenderClient> {
        let (client, buffer_frames) = open_audio_client(E_RENDER, event.handle())?;
        unsafe {
            let mut render: *mut IAudioRenderClient = core::ptr::null_mut();
            let hr = ((*(*client).vtbl).get_service)(
                client.cast(),
                &IID_IAUDIO_RENDER_CLIENT,
                (&mut render as *mut *mut IAudioRenderClient).cast(),
            );
            if failed(hr) || render.is_null() {
                ((*(*client).vtbl).release)(client.cast());
                return None;
            }
            Some(RenderClient {
                client,
                render,
                buffer_frames,
            })
        }
    }

    /// Total endpoint buffer capacity in frames.
    pub fn buffer_frames(&self) -> u32 {
        self.buffer_frames
    }

    /// Frames currently free in the endpoint buffer (`buffer - padding`), or
    /// `None` if the device was invalidated (caller should drop the client).
    pub fn available_frames(&self) -> Option<u32> {
        unsafe {
            let mut padding: u32 = 0;
            if failed(((*(*self.client).vtbl).get_current_padding)(
                self.client.cast(),
                &mut padding,
            )) {
                return None;
            }
            Some(self.buffer_frames.saturating_sub(padding))
        }
    }

    /// Acquire a writable slice for exactly `frames` frames
    /// (`frames * FRAME_BYTES` bytes). Must be paired with [`Self::commit`].
    pub fn begin(&mut self, frames: u32) -> Option<&mut [u8]> {
        if frames == 0 {
            return None;
        }
        unsafe {
            let mut data: *mut u8 = core::ptr::null_mut();
            if failed(((*(*self.render).vtbl).get_buffer)(
                self.render.cast(),
                frames,
                &mut data,
            )) || data.is_null()
            {
                return None;
            }
            Some(core::slice::from_raw_parts_mut(
                data,
                frames as usize * FRAME_BYTES as usize,
            ))
        }
    }

    /// Release a buffer previously returned by [`Self::begin`]. `silent` marks
    /// the buffer as silence (used when the guest underran).
    pub fn commit(&mut self, frames: u32, silent: bool) {
        let flags = if silent {
            AUDCLNT_BUFFERFLAGS_SILENT
        } else {
            0
        };
        unsafe {
            let _ = ((*(*self.render).vtbl).release_buffer)(self.render.cast(), frames, flags);
        }
    }

    pub fn start(&self) -> bool {
        unsafe { !failed(((*(*self.client).vtbl).start)(self.client.cast())) }
    }

    pub fn stop(&self) {
        unsafe {
            let _ = ((*(*self.client).vtbl).stop)(self.client.cast());
            let _ = ((*(*self.client).vtbl).reset)(self.client.cast());
        }
    }
}

impl Drop for RenderClient {
    fn drop(&mut self) {
        unsafe {
            let _ = ((*(*self.client).vtbl).stop)(self.client.cast());
            ((*(*self.render).vtbl).release)(self.render.cast());
            ((*(*self.client).vtbl).release)(self.client.cast());
        }
    }
}

// The COM pointers are created and consumed entirely on one worker thread; the
// struct never crosses threads, so no Send/Sync is asserted (and none is needed).

/// Shared-mode WASAPI capture (microphone) endpoint.
pub struct CaptureClient {
    client: *mut IAudioClient,
    capture: *mut IAudioCaptureClient,
    cur_frames: u32,
}

impl CaptureClient {
    /// Open the default capture endpoint, signalling `event` when data is
    /// available. `None` if no endpoint is available.
    pub fn open(event: &Event) -> Option<CaptureClient> {
        let (client, _frames) = open_audio_client(E_CAPTURE, event.handle())?;
        unsafe {
            let mut capture: *mut IAudioCaptureClient = core::ptr::null_mut();
            let hr = ((*(*client).vtbl).get_service)(
                client.cast(),
                &IID_IAUDIO_CAPTURE_CLIENT,
                (&mut capture as *mut *mut IAudioCaptureClient).cast(),
            );
            if failed(hr) || capture.is_null() {
                ((*(*client).vtbl).release)(client.cast());
                return None;
            }
            Some(CaptureClient {
                client,
                capture,
                cur_frames: 0,
            })
        }
    }

    pub fn start(&self) -> bool {
        unsafe { !failed(((*(*self.client).vtbl).start)(self.client.cast())) }
    }

    pub fn stop(&self) {
        unsafe {
            let _ = ((*(*self.client).vtbl).stop)(self.client.cast());
            let _ = ((*(*self.client).vtbl).reset)(self.client.cast());
        }
    }

    /// Fetch the next captured packet as S16 stereo bytes, its frame count, and
    /// a `silent` flag (the engine reports a gap as silence with no valid data,
    /// in which case the returned slice is empty but `frames` is still set).
    /// Returns `None` when no packet is ready. Each `Some(..)` must be paired
    /// with [`Self::release_packet`].
    pub fn next_packet(&mut self) -> Option<(&[u8], u32, bool)> {
        unsafe {
            let mut next: u32 = 0;
            if failed(((*(*self.capture).vtbl).get_next_packet_size)(
                self.capture.cast(),
                &mut next,
            )) || next == 0
            {
                return None;
            }
            let mut data: *mut u8 = core::ptr::null_mut();
            let mut frames: u32 = 0;
            let mut flags: u32 = 0;
            let hr = ((*(*self.capture).vtbl).get_buffer)(
                self.capture.cast(),
                &mut data,
                &mut frames,
                &mut flags,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if failed(hr) {
                return None;
            }
            if frames == 0 {
                // GetBuffer succeeded with an empty packet (AUDCLNT_S_BUFFER_EMPTY):
                // we still must ReleaseBuffer(0) to keep the GetBuffer/ReleaseBuffer
                // pairing intact, or the capture client desyncs.
                let _ = ((*(*self.capture).vtbl).release_buffer)(self.capture.cast(), 0);
                return None;
            }
            self.cur_frames = frames;
            let silent = flags & AUDCLNT_BUFFERFLAGS_SILENT != 0 || data.is_null();
            let slice = if silent {
                &[][..]
            } else {
                core::slice::from_raw_parts(data, frames as usize * FRAME_BYTES as usize)
            };
            Some((slice, frames, silent))
        }
    }

    /// Release the packet most recently returned by [`Self::next_packet`].
    pub fn release_packet(&mut self) {
        unsafe {
            let _ = ((*(*self.capture).vtbl).release_buffer)(self.capture.cast(), self.cur_frames);
        }
        self.cur_frames = 0;
    }
}

impl Drop for CaptureClient {
    fn drop(&mut self) {
        unsafe {
            let _ = ((*(*self.client).vtbl).stop)(self.client.cast());
            ((*(*self.capture).vtbl).release)(self.capture.cast());
            ((*(*self.client).vtbl).release)(self.client.cast());
        }
    }
}

/// A Win32 event handle (RAII). Auto-reset events are used for the WASAPI
/// buffer notification and the per-worker wake; a manual-reset event is used for
/// the broadcast stop signal.
pub struct Event {
    handle: HANDLE,
}

// SAFETY: the only field is an OS event handle (an opaque token, safe to use
// from any thread). Sharing/Sending it is sound; the audio workers wait on it
// from a different thread than the one that signals it.
unsafe impl Send for Event {}
unsafe impl Sync for Event {}

impl Event {
    /// Create an event. `manual_reset` selects manual- vs auto-reset semantics.
    pub fn new(manual_reset: bool) -> Option<Event> {
        let handle =
            unsafe { CreateEventW(core::ptr::null(), manual_reset as i32, 0, core::ptr::null()) };
        if handle.is_null() {
            None
        } else {
            Some(Event { handle })
        }
    }

    pub fn set(&self) {
        unsafe {
            let _ = SetEvent(self.handle);
        }
    }

    pub fn reset(&self) {
        unsafe {
            let _ = ResetEvent(self.handle);
        }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Outcome of [`wait_any`].
pub enum WaitOutcome {
    /// Event at this index (into the passed slice) was signalled.
    Signaled(usize),
    /// The timeout elapsed with nothing signalled.
    Timeout,
    /// The wait failed (e.g. an invalid handle).
    Failed,
}

/// Wait until one of `events` is signalled or `timeout_ms` elapses. Supports up
/// to 8 events (sufficient for the audio workers' {stop, wake, wasapi} set).
pub fn wait_any(events: &[&Event], timeout_ms: u32) -> WaitOutcome {
    let mut handles = [core::ptr::null_mut::<c_void>() as HANDLE; 8];
    let n = events.len().min(handles.len());
    for (i, e) in events.iter().take(n).enumerate() {
        handles[i] = e.handle;
    }
    let r = unsafe { WaitForMultipleObjects(n as u32, handles.as_ptr(), 0, timeout_ms) };
    if r == WAIT_TIMEOUT {
        return WaitOutcome::Timeout;
    }
    let idx = r.wrapping_sub(WAIT_OBJECT_0);
    if idx < n as u32 {
        WaitOutcome::Signaled(idx as usize)
    } else {
        WaitOutcome::Failed
    }
}

/// Per-thread COM apartment guard. Initialises COM (MTA) on construction and
/// uninitialises it on drop, but only if this guard performed the initialisation.
pub struct ComInit {
    owned: bool,
}

impl ComInit {
    /// Join the multithreaded apartment for the current thread.
    pub fn mta() -> ComInit {
        let hr = unsafe { CoInitializeEx(core::ptr::null(), COINIT_MULTITHREADED as u32) };
        // S_OK / S_FALSE => we initialised it; RPC_E_CHANGED_MODE (and other
        // failures) => COM is already up in another mode, so we must not undo it.
        ComInit { owned: !failed(hr) }
    }
}

impl Drop for ComInit {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the hand-rolled COM vtables against the live Windows runtime:
    /// enumerate the default render endpoint, activate + initialise the audio
    /// client, and read back its buffer size / padding. The endpoint may be
    /// absent (a headless CI runner), in which case `open` returns `None` — the
    /// test only requires that the vtable calls use the correct ABI/offsets and
    /// don't fault. A wrong vtable layout would access-violate here.
    #[test]
    fn render_vtable_roundtrip() {
        let _com = ComInit::mta();
        let ev = Event::new(false).expect("create event");
        if let Some(client) = RenderClient::open(&ev) {
            assert!(client.buffer_frames() > 0);
            // GetCurrentPadding through the client vtable must succeed.
            assert!(client.available_frames().is_some());
        }
    }

    #[test]
    fn capture_vtable_roundtrip() {
        let _com = ComInit::mta();
        let ev = Event::new(false).expect("create event");
        // Open + drop (Activate/Initialize/GetService/Release vtable slots).
        let _ = CaptureClient::open(&ev);
    }

    #[test]
    fn event_signal_and_wait() {
        let a = Event::new(false).expect("auto-reset event");
        let b = Event::new(true).expect("manual-reset event");
        b.set();
        // `b` is index 1 and already signalled; `a` (index 0) is not.
        assert!(matches!(wait_any(&[&a, &b], 0), WaitOutcome::Signaled(1)));
        // Nothing signalled now (auto-reset `a` never set, `b` reset).
        b.reset();
        assert!(matches!(wait_any(&[&a, &b], 0), WaitOutcome::Timeout));
    }
}
