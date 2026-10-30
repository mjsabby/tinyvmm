//! Host-side user-mode networking: the NAT backend and its wire helpers.
//!
//! The guest network both host-side backends use: 172.29.255.0/29, gateway .1,
//! guest .2. The NAT hands it out by DHCP; WinTun's host adapter takes the
//! gateway address. It sits in 172.16.0.0/12 like the networks Hyper-V's
//! Default Switch and WSL create, which take a random /20 there on each boot.
//! The NAT's network exists only inside the guest, so an overlap can at most
//! hide these eight addresses from it. It is the last /24 of its /20, while
//! Hyper-V takes a /20's first address, and clear of the ranges Docker
//! (172.17-20, also inside the guest), OpenShift (172.30) and AWS (172.31)
//! default to.

pub mod dhcp;
pub mod nat;
pub mod sys;
pub mod wintun;
pub mod wire;

pub const GATEWAY_IP: [u8; 4] = [172, 29, 255, 1];
pub const GUEST_IP: [u8; 4] = [172, 29, 255, 2];
pub const PREFIX_LEN: u8 = 29;
pub const NETMASK: [u8; 4] = (u32::MAX << (32 - PREFIX_LEN as u32)).to_be_bytes();
