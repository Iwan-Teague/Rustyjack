
#[cfg(target_os = "linux")]
fn main() {
    use linux_embedded_hal as hal;
    // Check if SpidevDevice exists
    // let _ = hal::SpidevDevice; 
}

#[cfg(not(target_os = "linux"))]
fn main() {}
