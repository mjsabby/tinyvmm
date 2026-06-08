//! Small constructors for the `WHV_REGISTER_VALUE` union so callers don't have
//! to write `unsafe`/union-literal boilerplate at every register set.

use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_VALUE, WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0,
    WHV_X64_TABLE_REGISTER,
};

#[inline]
pub fn reg64(v: u64) -> WHV_REGISTER_VALUE {
    WHV_REGISTER_VALUE { Reg64: v }
}

#[inline]
pub fn seg(base: u64, limit: u32, selector: u16, attributes: u16) -> WHV_REGISTER_VALUE {
    WHV_REGISTER_VALUE {
        Segment: WHV_X64_SEGMENT_REGISTER {
            Base: base,
            Limit: limit,
            Selector: selector,
            Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                Attributes: attributes,
            },
        },
    }
}

#[inline]
pub fn table(base: u64, limit: u16) -> WHV_REGISTER_VALUE {
    WHV_REGISTER_VALUE {
        Table: WHV_X64_TABLE_REGISTER {
            Pad: [0; 3],
            Limit: limit,
            Base: base,
        },
    }
}
