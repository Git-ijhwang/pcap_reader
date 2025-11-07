use std::net::Ipv4Addr;
use crate::port::*;
use crate::{IP_HDR_LEN, MIN_ETH_HDR_LEN};

pub fn parse_ipv4(ip_hdr: &[u8], short:bool) -> usize
{
    let mut next_hdr: usize = 0;
    let mut offset: usize = 0;

    let version_ihl = ip_hdr[offset];
    let version = (version_ihl & 0xf0)>>4;
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl != IP_HDR_LEN {
        return 0;
    }
    offset += 2; //IHL(1byte) + Service Field(1byte)

    let total_len: u16 = u16::from_be_bytes( [
        ip_hdr[offset], ip_hdr[offset+1]
    ]);
    offset += 2; //Total Length (2bytes)

    let id = u16::from_be_bytes([
        ip_hdr[offset], ip_hdr[offset+1]
    ]);
    offset += 2; //ID Field (2 bytes)

    let frag : u16 = u16::from_ne_bytes([
        ip_hdr[offset], ip_hdr[offset+1]
    ]);

    let frag_flag: u8 = ((frag & 0x40)>>5) as u8;
    let mut frag_offset: u16 = 0;
    if frag_flag == 0x02 {
        frag_offset = frag & 0x1f;
    }
    offset += 2; //Fragment flag and offset (2bytes)

    let ttl = ip_hdr[offset];
    offset += 1; //Time to Live (1byte)

    next_hdr = ip_hdr[offset] as usize;
    let mut str_proto = String::new();
    if let Some(v) = protocol_to_str(next_hdr) {
        str_proto = v;
    }
    else {
        eprintln!("Unknown protocol type {}", next_hdr);
    }

    offset += 1; //Next Protocol (1byte)

    let hdr_chk = u16::from_be_bytes([
        ip_hdr[offset], ip_hdr[offset+1]
    ]);
    offset += 2; //Header Checksum Field (2bytes)

    let mut src_addr = Ipv4Addr::new(0,0,0,0);
    if let Ok(octets) = ip_hdr[offset..offset+4].try_into() {
        src_addr = Ipv4Addr::from_octets(octets);
    }
    else {
        eprintln!("Failure to read Src Addr");
    }
    offset += 4;

    let mut dst_addr = Ipv4Addr::new(0,0,0,0);
    if let Ok(octets) = ip_hdr[offset..offset+4].try_into() {
        dst_addr = Ipv4Addr::from_octets(octets);
    }
    else {
        eprintln!("Failure to read Src Addr");
    }

    let mut ip_print = "".to_string();
    if short {
        ip_print = format!("\tIP\tSrc: {}  Dst:{}", src_addr, dst_addr);
    }
    else {
        ip_print = format!("\tIP\tVer:{}\n\t\tLen:{}bytes\n\t\tTotalLen:{}bytes\n\t\tID:0x{:04x}\n\t\tF:0x{:02x}\n\t\tTTL:{} \n\t\tNext_Proto:{}[{}]\n\t\tChkSum: 0x{:04x}\n\t\tSrc Addr:{}\n\t\tDst Addr: {}",
        version, ihl, total_len, id, frag_flag, ttl, next_hdr, str_proto, hdr_chk, src_addr, dst_addr);
    }
    println!("{}", ip_print);

    next_hdr
}