//! Minimal Media Foundation MP4 writer: H.264 video + AAC audio through the MF
//! sink writer, hand-rolled over raw COM in the style of [`crate::audio`].
//!
//! `windows-sys` ships no Media Foundation bindings, so the few mfplat /
//! mfreadwrite entry points are resolved at runtime with `LoadLibraryExW`
//! (System32 only). Media Foundation is absent on Windows "N" editions and
//! Server Core; a static import would stop tinyvmm from starting there even when
//! nothing is being recorded. The IMFAttributes / IMFMediaType / IMFSample /
//! IMFMediaBuffer / IMFSinkWriter(Ex) / IMFTransform vtables are declared by hand
//! (slot order checked against the Windows SDK's mfobjects.h, mfreadwrite.h and
//! mftransform.h). All of the COM/FFI `unsafe` is concentrated in this module;
//! callers use the safe [`Mp4Writer`].
//!
//! The sink writer owns the whole pipeline: it loads an H.264 encoder MFT (a
//! hardware encoder when one accepts the stream, else Microsoft's software
//! encoder), the AAC encoder MFT and the MPEG-4 media sink, plain or fragmented.
//! Input is NV12 video and the fixed virtio-snd PCM contract (48 kHz / S16LE /
//! stereo). Timestamps and durations are in 100-ns units.

use crate::audio::{BITS_PER_SAMPLE, CHANNELS, ComInit, FRAME_BYTES, SAMPLE_RATE};
use crate::error::{Error, Result, check_hr};
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::null_mut;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::{GUID, HRESULT};

/// `MF_VERSION`: MF_SDK_VERSION (2) << 16 | MF_API_VERSION (0x70).
const MF_VERSION: u32 = 0x0002_0070;
/// `MFSTARTUP_LITE`: no network-source support; we only write a local file.
const MFSTARTUP_LITE: u32 = 1;

const MF_VIDEO_INTERLACE_PROGRESSIVE: u32 = 2;
const MF_VIDEO_TRANSFER_MATRIX_BT709: u32 = 1;
const MF_NOMINAL_RANGE_16_235: u32 = 2;
const MF_VIDEO_PRIMARIES_BT709: u32 = 2;
const MF_VIDEO_TRANSFUNC_709: u32 = 5;
const H264_PROFILE_HIGH: u32 = 100;
const RATE_CONTROL_UNCONSTRAINED_VBR: u32 = 2;
/// AAC-LC, level 2 (the encoder's default `MF_MT_AAC_AUDIO_PROFILE_LEVEL_INDICATION`).
const AAC_PROFILE_LEVEL_LC_L2: u32 = 0x29;
/// AAC output rate in bytes/s. The Microsoft encoder accepts 12000, 16000,
/// 20000 or 24000; 24000 is 192 kbps.
const AAC_BYTES_PER_SEC: u32 = 24_000;
/// Seconds between H.264 keyframes (seek granularity / fragment cadence).
const KEYFRAME_SECS: u32 = 2;

// ---- GUIDs (mfapi.h, mfidl.h, mfreadwrite.h, mftransform.h, codecapi.h) ----
const MF_MT_MAJOR_TYPE: GUID = GUID::from_u128(0x48eba18e_f8c9_4687_bf11_0a74c9f96a8f);
const MF_MT_SUBTYPE: GUID = GUID::from_u128(0xf7e34c9a_42e8_4714_b74b_cb29d72c35e5);
const MF_MT_AVG_BITRATE: GUID = GUID::from_u128(0x20332624_fb0d_4d9e_bd0d_cbf6786c102e);
const MF_MT_INTERLACE_MODE: GUID = GUID::from_u128(0xe2724bb8_e676_4806_b4b2_a8d6efb44ccd);
const MF_MT_FRAME_SIZE: GUID = GUID::from_u128(0x1652c33d_d6b2_4012_b834_72030849a37d);
const MF_MT_FRAME_RATE: GUID = GUID::from_u128(0xc459a2e8_3d2c_4e44_b132_fee5156c7bb0);
const MF_MT_PIXEL_ASPECT_RATIO: GUID = GUID::from_u128(0xc6376a1e_8d0a_4027_be45_6d9a0ad39bb6);
const MF_MT_DEFAULT_STRIDE: GUID = GUID::from_u128(0x644b4e48_1e02_4516_b0eb_c01ca9d49ac6);
const MF_MT_ALL_SAMPLES_INDEPENDENT: GUID = GUID::from_u128(0xc9173739_5e56_461c_b713_46fb995cb95f);
const MF_MT_MPEG2_PROFILE: GUID = GUID::from_u128(0xad76a80b_2d5c_4e0b_b375_64e520137036);
const MF_MT_YUV_MATRIX: GUID = GUID::from_u128(0x3e23d450_2c75_4d25_a00e_b91670d12327);
const MF_MT_VIDEO_NOMINAL_RANGE: GUID = GUID::from_u128(0xc21b8ee5_b956_4071_8daf_325edf5cab11);
const MF_MT_VIDEO_PRIMARIES: GUID = GUID::from_u128(0xdbfbe4d7_0740_4ee0_8192_850ab0e21935);
const MF_MT_TRANSFER_FUNCTION: GUID = GUID::from_u128(0x5fb0fce9_be5c_4935_a811_ec838f8eed93);
const MF_MT_AUDIO_NUM_CHANNELS: GUID = GUID::from_u128(0x37e48bf5_645e_4c5b_89de_ada9e29b696a);
const MF_MT_AUDIO_SAMPLES_PER_SECOND: GUID =
    GUID::from_u128(0x5faeeae7_0290_4c31_9e8a_c534f68d9dba);
const MF_MT_AUDIO_BITS_PER_SAMPLE: GUID = GUID::from_u128(0xf2deb57f_40fa_4764_aa33_ed4f2d1ff669);
const MF_MT_AUDIO_BLOCK_ALIGNMENT: GUID = GUID::from_u128(0x322de230_9eeb_43bd_ab7a_ff412251541d);
const MF_MT_AUDIO_AVG_BYTES_PER_SECOND: GUID =
    GUID::from_u128(0x1aab75c8_cfef_451c_ab95_ac034b8e1731);
const MF_MT_AAC_PAYLOAD_TYPE: GUID = GUID::from_u128(0xbfbabe79_7434_4d1c_94f0_72a3b9e17188);
const MF_MT_AAC_AUDIO_PROFILE_LEVEL_INDICATION: GUID =
    GUID::from_u128(0x7632f0e6_9538_4d61_acda_ea29c8c14456);
const MF_MEDIA_TYPE_VIDEO: GUID = GUID::from_u128(0x73646976_0000_0010_8000_00aa00389b71);
const MF_MEDIA_TYPE_AUDIO: GUID = GUID::from_u128(0x73647561_0000_0010_8000_00aa00389b71);
const MF_VIDEO_FORMAT_H264: GUID = GUID::from_u128(0x34363248_0000_0010_8000_00aa00389b71);
const MF_VIDEO_FORMAT_NV12: GUID = GUID::from_u128(0x3231564e_0000_0010_8000_00aa00389b71);
const MF_AUDIO_FORMAT_AAC: GUID = GUID::from_u128(0x00001610_0000_0010_8000_00aa00389b71);
const MF_AUDIO_FORMAT_PCM: GUID = GUID::from_u128(0x00000001_0000_0010_8000_00aa00389b71);
const MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS: GUID =
    GUID::from_u128(0xa634a91c_822b_41b9_a494_4de4643612b0);
const MF_TRANSCODE_CONTAINERTYPE: GUID = GUID::from_u128(0x150ff23f_4abc_478b_ac4f_e1916fba1cca);
const MF_TRANSCODE_CONTAINER_MPEG4: GUID = GUID::from_u128(0xdc6cd05d_b9d0_40ef_bd35_fa622c1ab28a);
const MF_TRANSCODE_CONTAINER_FMPEG4: GUID = GUID::from_u128(0x9ba876f1_419f_4b77_a1e0_35959d9d4004);
const CODECAPI_AVENC_MPV_GOP_SIZE: GUID = GUID::from_u128(0x95f31b26_95a4_41aa_9303_246a7fc6eef1);
const CODECAPI_AVENC_COMMON_RATE_CONTROL_MODE: GUID =
    GUID::from_u128(0x1c0608e9_370c_4710_8a58_cb6181c42423);
const CODECAPI_AVENC_COMMON_MEAN_BIT_RATE: GUID =
    GUID::from_u128(0xf7222374_2144_4815_b550_a37f8e12ee52);
const CODECAPI_AVENC_MPV_DEFAULT_B_PICTURE_COUNT: GUID =
    GUID::from_u128(0x8d390aac_dc5c_4200_b57f_814d04babab2);
const IID_IMF_SINK_WRITER_EX: GUID = GUID::from_u128(0x588d72ab_5bc1_496a_8714_b70617141b25);
const MFT_CATEGORY_VIDEO_ENCODER: GUID = GUID::from_u128(0xf79eac7d_e545_4387_bdee_d647d7bde42a);
const MFT_FRIENDLY_NAME_ATTRIBUTE: GUID = GUID::from_u128(0x314ffbae_5b41_4c95_9c19_4e7d586face3);
const MFT_ENUM_HARDWARE_URL_ATTRIBUTE: GUID =
    GUID::from_u128(0x2fb866ac_b078_4942_ab6c_003d05cda674);
const MFT_ENUM_HARDWARE_VENDOR_ID_ATTRIBUTE: GUID =
    GUID::from_u128(0x3aecb0cc_035b_4bcc_8185_2b8d551ef3af);

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

// =====================================================================
// Runtime-resolved entry points.
// =====================================================================

type StartupFn = unsafe extern "system" fn(u32, u32) -> HRESULT;
type ShutdownFn = unsafe extern "system" fn() -> HRESULT;
type CreateAttributesFn = unsafe extern "system" fn(*mut *mut c_void, u32) -> HRESULT;
/// `MFCreateMediaType` / `MFCreateSample`: one out-pointer.
type CreateObjectFn = unsafe extern "system" fn(*mut *mut c_void) -> HRESULT;
type CreateMemoryBufferFn = unsafe extern "system" fn(u32, *mut *mut c_void) -> HRESULT;
type CreateSinkWriterFn =
    unsafe extern "system" fn(*const u16, *mut c_void, *mut c_void, *mut *mut c_void) -> HRESULT;

struct MfApi {
    startup: StartupFn,
    shutdown: ShutdownFn,
    create_attributes: CreateAttributesFn,
    create_media_type: CreateObjectFn,
    create_sample: CreateObjectFn,
    create_memory_buffer: CreateMemoryBufferFn,
    create_sink_writer_from_url: CreateSinkWriterFn,
}

/// The process-wide Media Foundation entry points, loaded on first use. The
/// DLLs stay loaded for the life of the process.
fn api() -> Result<&'static MfApi> {
    static API: OnceLock<std::result::Result<MfApi, String>> = OnceLock::new();
    API.get_or_init(load_api)
        .as_ref()
        .map_err(|e| Error::msg(e.clone()))
}

fn load_api() -> std::result::Result<MfApi, String> {
    fn module(dll: &str) -> std::result::Result<HMODULE, String> {
        let wide: Vec<u16> = dll.encode_utf16().chain([0]).collect();
        // SAFETY: NUL-terminated name; System32-only search (no DLL planting).
        let m = unsafe { LoadLibraryExW(wide.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if m.is_null() {
            Err(format!(
                "Media Foundation is unavailable ({dll}: err={}); on Windows N editions \
                 install the Media Feature Pack, on Windows Server the Media Foundation feature",
                // SAFETY: plain thread-local error query.
                unsafe { GetLastError() }
            ))
        } else {
            Ok(m)
        }
    }
    fn sym(m: HMODULE, dll: &str, name: &str) -> std::result::Result<*const (), String> {
        let c: Vec<u8> = name.bytes().chain([0]).collect();
        // SAFETY: `m` is a loaded module and `c` a NUL-terminated export name.
        match unsafe { GetProcAddress(m, c.as_ptr()) } {
            Some(f) => Ok(f as *const ()),
            None => Err(format!("{dll} is missing export {name}")),
        }
    }
    let plat = module("mfplat.dll")?;
    let rw = module("mfreadwrite.dll")?;
    // SAFETY: each pointer is the named export, whose C signature matches the
    // function-pointer type it is transmuted to (mfapi.h / mfreadwrite.h).
    unsafe {
        Ok(MfApi {
            startup: core::mem::transmute::<*const (), StartupFn>(sym(
                plat,
                "mfplat.dll",
                "MFStartup",
            )?),
            shutdown: core::mem::transmute::<*const (), ShutdownFn>(sym(
                plat,
                "mfplat.dll",
                "MFShutdown",
            )?),
            create_attributes: core::mem::transmute::<*const (), CreateAttributesFn>(sym(
                plat,
                "mfplat.dll",
                "MFCreateAttributes",
            )?),
            create_media_type: core::mem::transmute::<*const (), CreateObjectFn>(sym(
                plat,
                "mfplat.dll",
                "MFCreateMediaType",
            )?),
            create_sample: core::mem::transmute::<*const (), CreateObjectFn>(sym(
                plat,
                "mfplat.dll",
                "MFCreateSample",
            )?),
            create_memory_buffer: core::mem::transmute::<*const (), CreateMemoryBufferFn>(sym(
                plat,
                "mfplat.dll",
                "MFCreateMemoryBuffer",
            )?),
            create_sink_writer_from_url: core::mem::transmute::<*const (), CreateSinkWriterFn>(
                sym(rw, "mfreadwrite.dll", "MFCreateSinkWriterFromURL")?,
            ),
        })
    }
}

/// One `MFStartup` reference, released (`MFShutdown`) on drop.
struct MfRuntime {
    api: &'static MfApi,
}

impl MfRuntime {
    fn start(api: &'static MfApi) -> Result<MfRuntime> {
        // SAFETY: plain call; balanced by MFShutdown in Drop.
        check_hr(
            unsafe { (api.startup)(MF_VERSION, MFSTARTUP_LITE) },
            "MFStartup",
        )?;
        Ok(MfRuntime { api })
    }
}

impl Drop for MfRuntime {
    fn drop(&mut self) {
        // SAFETY: balances the successful MFStartup in `start`.
        unsafe {
            let _ = (self.api.shutdown)();
        }
    }
}

// =====================================================================
// Hand-rolled COM vtables. Unused slots are pointer-sized placeholders so the
// typed slots land at the right offsets (layouts per the Windows SDK headers).
// =====================================================================

#[repr(C)]
struct IUnknownVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// IMFAttributes (33 slots). IMFMediaType and IMFSample extend it, so their
/// vtables start with this exact layout.
#[repr(C)]
struct IMFAttributesVtbl {
    unknown: IUnknownVtbl,
    /// GetItem, GetItemType, CompareItem, Compare, GetUINT32, GetUINT64,
    /// GetDouble, GetGUID, GetStringLength.
    _get: [usize; 9],
    get_string:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut u16, u32, *mut u32) -> HRESULT,
    /// GetAllocatedString, GetBlobSize, GetBlob, GetAllocatedBlob, GetUnknown,
    /// SetItem, DeleteItem, DeleteAllItems.
    _get_blobs: [usize; 8],
    set_uint32: unsafe extern "system" fn(*mut c_void, *const GUID, u32) -> HRESULT,
    set_uint64: unsafe extern "system" fn(*mut c_void, *const GUID, u64) -> HRESULT,
    /// SetDouble.
    _set_double: usize,
    set_guid: unsafe extern "system" fn(*mut c_void, *const GUID, *const GUID) -> HRESULT,
    /// SetString, SetBlob, SetUnknown, LockStore, UnlockStore, GetCount,
    /// GetItemByIndex, CopyAllItems.
    _rest: [usize; 8],
}
const _: () = assert!(size_of::<IMFAttributesVtbl>() == size_of::<[usize; 33]>());

/// IMFSample (47 slots).
#[repr(C)]
struct IMFSampleVtbl {
    attributes: IMFAttributesVtbl,
    /// GetSampleFlags, SetSampleFlags, GetSampleTime.
    _flags: [usize; 3],
    set_sample_time: unsafe extern "system" fn(*mut c_void, i64) -> HRESULT,
    /// GetSampleDuration.
    _get_duration: usize,
    set_sample_duration: unsafe extern "system" fn(*mut c_void, i64) -> HRESULT,
    /// GetBufferCount, GetBufferByIndex, ConvertToContiguousBuffer.
    _buffers: [usize; 3],
    add_buffer: unsafe extern "system" fn(*mut c_void, *mut c_void) -> HRESULT,
    /// RemoveBufferByIndex, RemoveAllBuffers, GetTotalLength, CopyToBuffer.
    _rest: [usize; 4],
}
const _: () = assert!(size_of::<IMFSampleVtbl>() == size_of::<[usize; 47]>());

/// IMFMediaBuffer (8 slots).
#[repr(C)]
struct IMFMediaBufferVtbl {
    unknown: IUnknownVtbl,
    lock: unsafe extern "system" fn(*mut c_void, *mut *mut u8, *mut u32, *mut u32) -> HRESULT,
    unlock: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    /// GetCurrentLength.
    _get_current_length: usize,
    set_current_length: unsafe extern "system" fn(*mut c_void, u32) -> HRESULT,
    /// GetMaxLength.
    _get_max_length: usize,
}
const _: () = assert!(size_of::<IMFMediaBufferVtbl>() == size_of::<[usize; 8]>());

/// IMFSinkWriter (14 slots).
#[repr(C)]
struct IMFSinkWriterVtbl {
    unknown: IUnknownVtbl,
    add_stream: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u32) -> HRESULT,
    set_input_media_type:
        unsafe extern "system" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> HRESULT,
    begin_writing: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    write_sample: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> HRESULT,
    /// SendStreamTick, PlaceMarker, NotifyEndOfSegment, Flush.
    _stream_control: [usize; 4],
    finalize: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    /// GetServiceForStream, GetStatistics.
    _service: [usize; 2],
}
const _: () = assert!(size_of::<IMFSinkWriterVtbl>() == size_of::<[usize; 14]>());

/// IMFSinkWriterEx (15 slots): IMFSinkWriter + GetTransformForStream.
#[repr(C)]
struct IMFSinkWriterExVtbl {
    base: IMFSinkWriterVtbl,
    get_transform_for_stream:
        unsafe extern "system" fn(*mut c_void, u32, u32, *mut GUID, *mut *mut c_void) -> HRESULT,
}

/// Prefix of IMFTransform up to GetAttributes (slot 8); later slots unused.
#[repr(C)]
struct IMFTransformVtbl {
    unknown: IUnknownVtbl,
    /// GetStreamLimits, GetStreamCount, GetStreamIDs, GetInputStreamInfo,
    /// GetOutputStreamInfo.
    _streams: [usize; 5],
    get_attributes: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT,
}

/// An owned COM interface pointer (one reference), released on drop. `V` is the
/// interface's vtable layout (or a prefix of it).
struct Com<V> {
    raw: *mut c_void,
    _vtbl: PhantomData<*const V>,
}

type Attributes = Com<IMFAttributesVtbl>;

impl<V> Com<V> {
    /// Run a creation call that fills an interface out-pointer and take
    /// ownership of the reference it hands back.
    fn create(what: &str, f: impl FnOnce(*mut *mut c_void) -> HRESULT) -> Result<Com<V>> {
        let mut raw: *mut c_void = null_mut();
        check_hr(f(&mut raw), what)?;
        if raw.is_null() {
            return Err(Error::msg(format!("{what}: null interface")));
        }
        Ok(Com {
            raw,
            _vtbl: PhantomData,
        })
    }

    fn vt(&self) -> &V {
        // SAFETY: `raw` is a live COM object; its first field is the vtable
        // pointer and `V` matches (a prefix of) that vtable's layout.
        unsafe { &**(self.raw as *const *const V) }
    }

    /// `QueryInterface` for another interface of the same object.
    fn query<W>(&self, iid: &GUID) -> Option<Com<W>> {
        let mut raw: *mut c_void = null_mut();
        // SAFETY: every COM vtable starts with IUnknown.
        let hr = unsafe {
            ((**(self.raw as *const *const IUnknownVtbl)).query_interface)(self.raw, iid, &mut raw)
        };
        if hr < 0 || raw.is_null() {
            return None;
        }
        Some(Com {
            raw,
            _vtbl: PhantomData,
        })
    }
}

impl<V> Drop for Com<V> {
    fn drop(&mut self) {
        // SAFETY: we own one reference; every COM vtable starts with IUnknown.
        unsafe {
            ((**(self.raw as *const *const IUnknownVtbl)).release)(self.raw);
        }
    }
}

impl Attributes {
    fn new(api: &MfApi) -> Result<Attributes> {
        // SAFETY: plain creation call with a valid out-pointer.
        Com::create("MFCreateAttributes", |p| unsafe {
            (api.create_attributes)(p, 4)
        })
    }

    fn new_media_type(api: &MfApi) -> Result<Attributes> {
        // SAFETY: as above. IMFMediaType extends IMFAttributes, so the same
        // pointer serves both interfaces.
        Com::create("MFCreateMediaType", |p| unsafe {
            (api.create_media_type)(p)
        })
    }

    fn set_u32(&self, key: &GUID, value: u32) -> Result<()> {
        // SAFETY: live object, valid key pointer.
        check_hr(
            unsafe { (self.vt().set_uint32)(self.raw, key, value) },
            "IMFAttributes::SetUINT32",
        )
    }

    fn set_u64(&self, key: &GUID, value: u64) -> Result<()> {
        // SAFETY: as above.
        check_hr(
            unsafe { (self.vt().set_uint64)(self.raw, key, value) },
            "IMFAttributes::SetUINT64",
        )
    }

    /// A packed `hi:lo` pair (frame size, frame rate, aspect ratio).
    fn set_pair(&self, key: &GUID, hi: u32, lo: u32) -> Result<()> {
        self.set_u64(key, ((hi as u64) << 32) | lo as u64)
    }

    fn set_guid(&self, key: &GUID, value: &GUID) -> Result<()> {
        // SAFETY: as above.
        check_hr(
            unsafe { (self.vt().set_guid)(self.raw, key, value) },
            "IMFAttributes::SetGUID",
        )
    }

    fn get_string(&self, key: &GUID) -> Option<String> {
        let mut buf = [0u16; 256];
        let mut len = 0u32;
        // SAFETY: `buf` holds `buf.len()` UTF-16 units; MF writes at most that
        // many (including the NUL) and fails if the value doesn't fit.
        let hr = unsafe {
            (self.vt().get_string)(self.raw, key, buf.as_mut_ptr(), buf.len() as u32, &mut len)
        };
        (hr >= 0).then(|| String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]))
    }
}

impl Com<IMFSinkWriterVtbl> {
    fn add_stream(&self, output_type: &Attributes) -> Result<u32> {
        let mut index = 0u32;
        // SAFETY: live writer + media type; valid out pointer.
        check_hr(
            unsafe { (self.vt().add_stream)(self.raw, output_type.raw, &mut index) },
            "IMFSinkWriter::AddStream",
        )?;
        Ok(index)
    }

    fn set_input_type(
        &self,
        stream: u32,
        input_type: &Attributes,
        params: Option<&Attributes>,
    ) -> Result<()> {
        let params = params.map_or(null_mut(), |p| p.raw);
        // SAFETY: live writer + media type (+ optional attribute store).
        check_hr(
            unsafe { (self.vt().set_input_media_type)(self.raw, stream, input_type.raw, params) },
            "IMFSinkWriter::SetInputMediaType",
        )
    }

    fn begin_writing(&self) -> Result<()> {
        // SAFETY: live writer.
        check_hr(
            unsafe { (self.vt().begin_writing)(self.raw) },
            "IMFSinkWriter::BeginWriting",
        )
    }
}

// =====================================================================
// Public API.
// =====================================================================

/// H.264 stream parameters. Frames passed to [`Mp4Writer::write_video`] are NV12
/// (`width*height` luma bytes, then `width*height/2` interleaved CbCr bytes,
/// stride == width) in BT.709 limited range. `width`/`height` must be even.
#[derive(Clone, Copy, Debug)]
pub struct VideoFormat {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// Mean bitrate, bits per second.
    pub bitrate: u32,
}

impl VideoFormat {
    /// Bytes in one NV12 frame.
    pub fn nv12_len(&self) -> usize {
        self.width as usize * self.height as usize * 3 / 2
    }
}

/// The H.264 encoder MFT the sink writer loaded.
#[derive(Clone, Debug)]
pub struct EncoderInfo {
    /// The MFT's friendly name, when it publishes one.
    pub name: Option<String>,
    /// A hardware encoder's PCI vendor id (e.g. `VEN_10DE`), when published.
    pub vendor: Option<String>,
    pub hardware: bool,
}

impl core::fmt::Display for EncoderInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = if self.hardware {
            "hardware"
        } else {
            "software"
        };
        let vendor = match self.vendor.as_deref() {
            Some(v) if v.eq_ignore_ascii_case("VEN_10DE") => Some("NVIDIA"),
            Some(v) if v.eq_ignore_ascii_case("VEN_8086") => Some("Intel"),
            Some(v) if v.eq_ignore_ascii_case("VEN_1002") => Some("AMD"),
            Some(v) => Some(v),
            None => None,
        };
        match (vendor, &self.name) {
            (Some(v), Some(n)) => write!(f, "{v} {kind} H.264 encoder ({n})"),
            (Some(v), None) => write!(f, "{v} {kind} H.264 encoder"),
            (None, Some(n)) => write!(f, "{kind} H.264 encoder ({n})"),
            (None, None) => write!(f, "{kind} H.264 encoder"),
        }
    }
}

/// Container/stream options for [`Mp4Writer::create`].
#[derive(Clone, Copy, Debug)]
pub struct Mp4Options {
    /// Add an AAC stream fed with [`Mp4Writer::write_audio`].
    pub audio: bool,
    /// Write a fragmented MP4, which stays playable while it grows and if the
    /// process dies before [`Mp4Writer::finalize`].
    pub fragmented: bool,
    /// Try hardware H.264 encoders before Microsoft's software encoder.
    pub hardware: bool,
}

/// An MP4 file being written: one H.264 stream plus an optional AAC stream fed
/// the fixed 48 kHz / S16LE / stereo PCM contract. Used from the thread that
/// created it (it owns that thread's COM + Media Foundation references).
pub struct Mp4Writer {
    // Field order is drop order: release the writer before MFShutdown and
    // CoUninitialize.
    writer: Com<IMFSinkWriterVtbl>,
    _mf: MfRuntime,
    _com: ComInit,
    api: &'static MfApi,
    video: VideoFormat,
    video_stream: u32,
    audio_stream: Option<u32>,
    encoder: Option<EncoderInfo>,
}

impl Mp4Writer {
    /// Create (truncate) `path` and start writing. A hardware H.264 encoder is
    /// preferred when allowed; if none accepts the stream (or its tuning
    /// parameters), the writer falls back to Microsoft's software encoder.
    pub fn create(path: &Path, video: &VideoFormat, opts: Mp4Options) -> Result<Mp4Writer> {
        if video.width == 0
            || video.height == 0
            || !video.width.is_multiple_of(2)
            || !video.height.is_multiple_of(2)
            || video.fps == 0
        {
            return Err(Error::msg(format!(
                "unsupported video format {}x{} @ {} fps (dimensions must be even)",
                video.width, video.height, video.fps
            )));
        }
        let com = ComInit::mta();
        let api = api()?;
        let mf = MfRuntime::start(api)?;
        let url: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut last = Error::msg("no sink writer configuration attempted");
        for (hardware, tuned) in [(true, true), (true, false), (false, true), (false, false)] {
            if hardware && !opts.hardware {
                continue;
            }
            match open_writer(api, &url, video, opts, hardware, tuned) {
                Ok((writer, video_stream, audio_stream)) => {
                    let encoder = probe_encoder(&writer, video_stream);
                    return Ok(Mp4Writer {
                        writer,
                        _mf: mf,
                        _com: com,
                        api,
                        video: *video,
                        video_stream,
                        audio_stream,
                        encoder,
                    });
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The video encoder in use, if the sink writer exposes it.
    pub fn encoder(&self) -> Option<&EncoderInfo> {
        self.encoder.as_ref()
    }

    pub fn has_audio(&self) -> bool {
        self.audio_stream.is_some()
    }

    /// Queue one NV12 frame shown from `time` for `duration` (100-ns units).
    /// Interleave video and audio writes in timestamp order: the sink writer
    /// blocks `WriteSample` on a stream that runs far ahead of the other (3 s of
    /// video written before any audio stalled ~20 s in testing).
    pub fn write_video(&mut self, nv12: &[u8], time: i64, duration: i64) -> Result<()> {
        if nv12.len() != self.video.nv12_len() {
            return Err(Error::msg(format!(
                "write_video: {} bytes, want {} for {}x{} NV12",
                nv12.len(),
                self.video.nv12_len(),
                self.video.width,
                self.video.height
            )));
        }
        self.write(self.video_stream, nv12, time, duration)
    }

    /// Queue S16LE stereo PCM starting at `time` (100-ns units). See
    /// [`Self::write_video`] on interleaving.
    pub fn write_audio(&mut self, pcm: &[u8], time: i64, duration: i64) -> Result<()> {
        let Some(stream) = self.audio_stream else {
            return Err(Error::msg("write_audio: no audio stream"));
        };
        if !pcm.len().is_multiple_of(FRAME_BYTES as usize) {
            return Err(Error::msg("write_audio: partial PCM frame"));
        }
        self.write(stream, pcm, time, duration)
    }

    fn write(&mut self, stream: u32, data: &[u8], time: i64, duration: i64) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let len = u32::try_from(data.len()).map_err(|_| Error::msg("sample too large"))?;
        let api = self.api;
        // SAFETY: plain creation call with a valid out-pointer.
        let buffer: Com<IMFMediaBufferVtbl> = Com::create("MFCreateMemoryBuffer", |p| unsafe {
            (api.create_memory_buffer)(len, p)
        })?;
        // SAFETY: Lock hands out `max` writable bytes until Unlock; we copy at
        // most `data.len() <= max` of them.
        unsafe {
            let mut dst: *mut u8 = null_mut();
            let mut max = 0u32;
            check_hr(
                (buffer.vt().lock)(buffer.raw, &mut dst, &mut max, null_mut()),
                "IMFMediaBuffer::Lock",
            )?;
            if dst.is_null() || (max as usize) < data.len() {
                let _ = (buffer.vt().unlock)(buffer.raw);
                return Err(Error::msg("IMFMediaBuffer::Lock: buffer too small"));
            }
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
            let _ = (buffer.vt().unlock)(buffer.raw);
            check_hr(
                (buffer.vt().set_current_length)(buffer.raw, len),
                "IMFMediaBuffer::SetCurrentLength",
            )?;
        }
        // SAFETY: plain creation call with a valid out-pointer.
        let sample: Com<IMFSampleVtbl> =
            Com::create("MFCreateSample", |p| unsafe { (api.create_sample)(p) })?;
        // SAFETY: live sample/buffer/writer; AddBuffer takes its own reference.
        unsafe {
            check_hr(
                (sample.vt().add_buffer)(sample.raw, buffer.raw),
                "IMFSample::AddBuffer",
            )?;
            check_hr(
                (sample.vt().set_sample_time)(sample.raw, time),
                "IMFSample::SetSampleTime",
            )?;
            check_hr(
                (sample.vt().set_sample_duration)(sample.raw, duration),
                "IMFSample::SetSampleDuration",
            )?;
            check_hr(
                (self.writer.vt().write_sample)(self.writer.raw, stream, sample.raw),
                "IMFSinkWriter::WriteSample",
            )
        }
    }

    /// Drain the encoders and complete the file.
    pub fn finalize(self) -> Result<()> {
        // SAFETY: live writer; Finalize blocks until every queued sample is written.
        check_hr(
            unsafe { (self.writer.vt().finalize)(self.writer.raw) },
            "IMFSinkWriter::Finalize",
        )
    }
}

/// Build a sink writer for `url` with one H.264 stream and optionally one AAC
/// stream. `tuned` adds the keyframe-interval / rate-control / B-frame encoder
/// parameters (some encoders reject one of them).
fn open_writer(
    api: &MfApi,
    url: &[u16],
    video: &VideoFormat,
    opts: Mp4Options,
    hardware: bool,
    tuned: bool,
) -> Result<(Com<IMFSinkWriterVtbl>, u32, Option<u32>)> {
    let attrs = Attributes::new(api)?;
    attrs.set_guid(
        &MF_TRANSCODE_CONTAINERTYPE,
        if opts.fragmented {
            &MF_TRANSCODE_CONTAINER_FMPEG4
        } else {
            &MF_TRANSCODE_CONTAINER_MPEG4
        },
    )?;
    attrs.set_u32(
        &MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS,
        u32::from(hardware),
    )?;
    let writer: Com<IMFSinkWriterVtbl> = Com::create("MFCreateSinkWriterFromURL", |p| {
        // SAFETY: NUL-terminated URL, live attribute store, valid out-pointer.
        unsafe { (api.create_sink_writer_from_url)(url.as_ptr(), null_mut(), attrs.raw, p) }
    })?;

    let video_stream = writer.add_stream(&video_type(api, video, &MF_VIDEO_FORMAT_H264)?)?;
    let params = if tuned {
        let p = Attributes::new(api)?;
        p.set_u32(&CODECAPI_AVENC_MPV_GOP_SIZE, video.fps * KEYFRAME_SECS)?;
        p.set_u32(&CODECAPI_AVENC_MPV_DEFAULT_B_PICTURE_COUNT, 0)?;
        p.set_u32(
            &CODECAPI_AVENC_COMMON_RATE_CONTROL_MODE,
            RATE_CONTROL_UNCONSTRAINED_VBR,
        )?;
        p.set_u32(&CODECAPI_AVENC_COMMON_MEAN_BIT_RATE, video.bitrate)?;
        Some(p)
    } else {
        None
    };
    writer.set_input_type(
        video_stream,
        &video_type(api, video, &MF_VIDEO_FORMAT_NV12)?,
        params.as_ref(),
    )?;

    let audio_stream = if opts.audio {
        let stream = writer.add_stream(&audio_type(api, &MF_AUDIO_FORMAT_AAC)?)?;
        writer.set_input_type(stream, &audio_type(api, &MF_AUDIO_FORMAT_PCM)?, None)?;
        Some(stream)
    } else {
        None
    };
    writer.begin_writing()?;
    Ok((writer, video_stream, audio_stream))
}

/// A progressive BT.709 video media type: the H.264 output type or the NV12
/// input type.
fn video_type(api: &MfApi, video: &VideoFormat, subtype: &GUID) -> Result<Attributes> {
    let t = Attributes::new_media_type(api)?;
    t.set_guid(&MF_MT_MAJOR_TYPE, &MF_MEDIA_TYPE_VIDEO)?;
    t.set_guid(&MF_MT_SUBTYPE, subtype)?;
    t.set_u32(&MF_MT_INTERLACE_MODE, MF_VIDEO_INTERLACE_PROGRESSIVE)?;
    t.set_pair(&MF_MT_FRAME_SIZE, video.width, video.height)?;
    t.set_pair(&MF_MT_FRAME_RATE, video.fps, 1)?;
    t.set_pair(&MF_MT_PIXEL_ASPECT_RATIO, 1, 1)?;
    t.set_u32(&MF_MT_YUV_MATRIX, MF_VIDEO_TRANSFER_MATRIX_BT709)?;
    t.set_u32(&MF_MT_VIDEO_NOMINAL_RANGE, MF_NOMINAL_RANGE_16_235)?;
    t.set_u32(&MF_MT_VIDEO_PRIMARIES, MF_VIDEO_PRIMARIES_BT709)?;
    t.set_u32(&MF_MT_TRANSFER_FUNCTION, MF_VIDEO_TRANSFUNC_709)?;
    if guid_eq(subtype, &MF_VIDEO_FORMAT_H264) {
        t.set_u32(&MF_MT_AVG_BITRATE, video.bitrate)?;
        t.set_u32(&MF_MT_MPEG2_PROFILE, H264_PROFILE_HIGH)?;
    } else {
        // Positive stride: top-down rows, `width` bytes per luma row.
        t.set_u32(&MF_MT_DEFAULT_STRIDE, video.width)?;
        t.set_u32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 1)?;
    }
    Ok(t)
}

/// The 48 kHz / 16-bit / stereo audio media type: the AAC-LC output type or
/// the PCM input type.
fn audio_type(api: &MfApi, subtype: &GUID) -> Result<Attributes> {
    let t = Attributes::new_media_type(api)?;
    t.set_guid(&MF_MT_MAJOR_TYPE, &MF_MEDIA_TYPE_AUDIO)?;
    t.set_guid(&MF_MT_SUBTYPE, subtype)?;
    t.set_u32(&MF_MT_AUDIO_BITS_PER_SAMPLE, BITS_PER_SAMPLE as u32)?;
    t.set_u32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, SAMPLE_RATE)?;
    t.set_u32(&MF_MT_AUDIO_NUM_CHANNELS, CHANNELS as u32)?;
    if guid_eq(subtype, &MF_AUDIO_FORMAT_AAC) {
        t.set_u32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, AAC_BYTES_PER_SEC)?;
        // Raw AAC (no ADTS headers), as the MP4 sink requires.
        t.set_u32(&MF_MT_AAC_PAYLOAD_TYPE, 0)?;
        t.set_u32(
            &MF_MT_AAC_AUDIO_PROFILE_LEVEL_INDICATION,
            AAC_PROFILE_LEVEL_LC_L2,
        )?;
    } else {
        t.set_u32(&MF_MT_AUDIO_BLOCK_ALIGNMENT, FRAME_BYTES)?;
        t.set_u32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, SAMPLE_RATE * FRAME_BYTES)?;
        t.set_u32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 1)?;
    }
    Ok(t)
}

/// Ask the sink writer which video encoder MFT it loaded for `stream` (needs
/// IMFSinkWriterEx, Windows 8+). Hardware MFTs carry a hardware URL attribute.
fn probe_encoder(writer: &Com<IMFSinkWriterVtbl>, stream: u32) -> Option<EncoderInfo> {
    let ex: Com<IMFSinkWriterExVtbl> = writer.query(&IID_IMF_SINK_WRITER_EX)?;
    for index in 0..8 {
        let mut category = GUID::default();
        let mut raw: *mut c_void = null_mut();
        // SAFETY: live IMFSinkWriterEx; valid out pointers.
        let hr = unsafe {
            (ex.vt().get_transform_for_stream)(ex.raw, stream, index, &mut category, &mut raw)
        };
        if hr < 0 || raw.is_null() {
            return None;
        }
        let mft: Com<IMFTransformVtbl> = Com {
            raw,
            _vtbl: PhantomData,
        };
        if !guid_eq(&category, &MFT_CATEGORY_VIDEO_ENCODER) {
            continue;
        }
        // SAFETY: live transform; valid out-pointer.
        let attrs: Option<Attributes> = Com::create("IMFTransform::GetAttributes", |p| unsafe {
            (mft.vt().get_attributes)(mft.raw, p)
        })
        .ok();
        let get = |key: &GUID| attrs.as_ref().and_then(|a| a.get_string(key));
        return Some(EncoderInfo {
            name: get(&MFT_FRIENDLY_NAME_ATTRIBUTE),
            vendor: get(&MFT_ENUM_HARDWARE_VENDOR_ID_ATTRIBUTE),
            hardware: get(&MFT_ENUM_HARDWARE_URL_ATTRIBUTE).is_some(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk the top-level MP4 boxes of `bytes`: (type, size) pairs.
    fn top_boxes(bytes: &[u8]) -> Vec<([u8; 4], usize)> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 8 <= bytes.len() {
            let size = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            let kind: [u8; 4] = bytes[off + 4..off + 8].try_into().unwrap();
            if size < 8 || off + size > bytes.len() {
                break;
            }
            out.push((kind, size));
            off += size;
        }
        out
    }

    /// Encode one second of synthetic video + audio through the hand-rolled
    /// vtables and check the container structure. Skipped (with a note) on a
    /// host without Media Foundation or an H.264 encoder (e.g. Server Core).
    fn roundtrip(name: &str, opts: Mp4Options) {
        let path =
            std::env::temp_dir().join(format!("winsys-media-{}-{name}.mp4", std::process::id()));
        let fmt = VideoFormat {
            width: 320,
            height: 240,
            fps: 30,
            bitrate: 1_000_000,
        };
        let mut w = match Mp4Writer::create(&path, &fmt, opts) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("skipping: Media Foundation unusable here: {e}");
                return;
            }
        };
        let encoder = w.encoder().cloned();
        eprintln!("{name}: {encoder:?}");
        if !opts.hardware {
            assert!(encoder.is_none_or(|e| !e.hardware));
        }
        assert_eq!(w.has_audio(), opts.audio);
        {
            // An unsupported interface must not release a null pointer.
            let attrs = Attributes::new(w.api).expect("attributes");
            assert!(
                attrs
                    .query::<IMFSinkWriterExVtbl>(&IID_IMF_SINK_WRITER_EX)
                    .is_none()
            );
        }
        let mut frame = vec![0u8; fmt.nv12_len()];
        let luma = (fmt.width * fmt.height) as usize;
        let mut pcm = vec![0u8; 1600 * FRAME_BYTES as usize];
        for k in 0..30i64 {
            for (i, px) in frame[..luma].iter_mut().enumerate() {
                *px = ((i as i64 + k * 8) % 220 + 16) as u8;
            }
            frame[luma..].fill(128);
            let t = k * 10_000_000 / 30;
            let next = (k + 1) * 10_000_000 / 30;
            w.write_video(&frame, t, next - t).expect("write video");
            // Interleave: the sink writer stalls a stream that runs far ahead.
            if opts.audio {
                for (n, f) in pcm.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                    let s = (k as f64 * 1600.0 + n as f64) / 48_000.0;
                    let v = ((s * 440.0 * std::f64::consts::TAU).sin() * 8000.0) as i16;
                    f[0..2].copy_from_slice(&v.to_le_bytes());
                    f[2..4].copy_from_slice(&v.to_le_bytes());
                }
                w.write_audio(&pcm, t, next - t).expect("write audio");
            }
        }
        // Wrong-sized input is rejected before it reaches Media Foundation.
        assert!(w.write_video(&frame[1..], 0, 1).is_err());
        assert!(w.write_audio(&pcm[1..], 0, 1).is_err());
        w.finalize().expect("finalize");

        let bytes = std::fs::read(&path).expect("read mp4");
        let _ = std::fs::remove_file(&path);
        let boxes = top_boxes(&bytes);
        let has = |k: &[u8; 4]| boxes.iter().any(|(t, _)| t == k);
        assert_eq!(boxes.first().map(|b| &b.0), Some(b"ftyp"), "{boxes:?}");
        assert!(has(b"moov") && has(b"mdat"), "{boxes:?}");
        assert_eq!(has(b"moof"), opts.fragmented, "{boxes:?}");
    }

    #[test]
    fn mp4_roundtrip_plain() {
        let opts = Mp4Options {
            audio: true,
            fragmented: false,
            hardware: true,
        };
        roundtrip("plain", opts);
    }

    #[test]
    fn mp4_roundtrip_fragmented() {
        let opts = Mp4Options {
            audio: true,
            fragmented: true,
            hardware: true,
        };
        roundtrip("frag", opts);
    }

    #[test]
    fn mp4_roundtrip_software_video_only() {
        let opts = Mp4Options {
            audio: false,
            fragmented: true,
            hardware: false,
        };
        roundtrip("sw", opts);
    }

    #[test]
    fn rejects_odd_dimensions() {
        let fmt = VideoFormat {
            width: 321,
            height: 240,
            fps: 30,
            bitrate: 1_000_000,
        };
        let opts = Mp4Options {
            audio: false,
            fragmented: false,
            hardware: false,
        };
        let path = std::env::temp_dir().join("winsys-media-odd.mp4");
        assert!(Mp4Writer::create(&path, &fmt, opts).is_err());
        assert!(!path.exists());
    }
}
