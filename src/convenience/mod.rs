//! Conveniences layered on the VMM. Nothing here is needed to run a VM; these
//! turn inputs that would otherwise need preparation by hand (such as a
//! distribution's ISO) into what the boot path takes.

pub mod grub_cfg;
pub mod iso9660;
pub mod iso_boot;
