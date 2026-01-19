use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;

pub struct PcapWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W) -> io::Result<Self> {
        write_global_header(&mut w)?;
        Ok(Self { w })
    }

    pub fn write_packet(&mut self, ts: SystemTime, data: &[u8]) -> io::Result<()> {
        let (sec, usec) = system_time_to_sec_usec(ts)?;
        write_record_header(&mut self.w, sec, usec, data.len() as u32)?;
        self.w.write_all(data)?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

fn write_global_header<W: Write>(w: &mut W) -> io::Result<()> {
    w.write_all(&PCAP_MAGIC.to_le_bytes())?;
    w.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
    w.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
    w.write_all(&LINKTYPE_IEEE802_11_RADIOTAP.to_le_bytes())?;
    Ok(())
}

fn write_record_header<W: Write>(
    w: &mut W,
    sec: u32,
    usec: u32,
    len: u32,
) -> io::Result<()> {
    w.write_all(&sec.to_le_bytes())?;
    w.write_all(&usec.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&len.to_le_bytes())?;
    Ok(())
}

fn system_time_to_sec_usec(ts: SystemTime) -> io::Result<(u32, u32)> {
    let dur = match ts.duration_since(UNIX_EPOCH) {
        Ok(dur) => dur,
        Err(_) => Duration::from_secs(0),
    };
    let sec = dur.as_secs().min(u32::MAX as u64) as u32;
    let usec = dur.subsec_micros();
    Ok((sec, usec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_header_and_record() {
        let mut writer = PcapWriter::new(Vec::new()).unwrap();
        let packet = vec![0x01, 0x02, 0x03, 0x04];
        let ts = UNIX_EPOCH + Duration::from_secs(1) + Duration::from_micros(2);
        writer.write_packet(ts, &packet).unwrap();

        let buf = writer.into_inner();
        assert_eq!(buf.len(), 24 + 16 + packet.len());

        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(magic, PCAP_MAGIC);

        let incl_len = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        let orig_len = u32::from_le_bytes(buf[36..40].try_into().unwrap());
        assert_eq!(incl_len, packet.len() as u32);
        assert_eq!(orig_len, packet.len() as u32);
    }
}
