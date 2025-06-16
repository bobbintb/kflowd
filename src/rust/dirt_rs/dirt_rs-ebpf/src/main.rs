#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn dirt_rs(ctx: ProbeContext) -> u32 {
    match try_dirt_rs(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt_rs(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
