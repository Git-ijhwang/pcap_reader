use std::net::Ipv6Addr;
use crate::port::*;

fn parse_ipv6_ext(mut next_hdr: usize, packet: &[u8]) {
    let mut offset = 0;

    // extension header가 계속 있는 동안 반복
    while let Some(name) = v6_ext_hdr_to_str(next_hdr) {
        println!("Found extension header: {}", name);

         if packet.len() < offset + 2 {
            println!("Malformed packet");
            return;
        }

        let ext_hdr_type = packet[offset];
        // 실제 헤더 길이 가져오기 (필드는 offset+1 위치에 있음)
        let hdr_len = packet[offset + 1] as usize;
        let hdr_total = (hdr_len + 1) * 8;

        if packet.len() < offset + hdr_total {
            println!("Truncated extension header");
            return;
        }

        println!("{} {}", ext_hdr_type, hdr_total);

        offset += hdr_total;

        next_hdr = packet[offset] as usize; // 다음 헤더 값 업데이트
    }

    println!("No more extension headers. Next protocol = {}", next_hdr);
}

pub fn parse_ipv6(ip_hdr: &[u8], short:bool) -> usize
{
    let mut offset: usize = 0;

    let head = u32::from_be_bytes([
        ip_hdr[offset], ip_hdr[offset+1],
        ip_hdr[offset+2], ip_hdr[offset+3],
        ]);

    let version  = ((head & 0xf0000000)>>28) as u8;
    let tc       = ((head & 0x0ff00000)>>20) as u8;
    let fl      = head & 0x000fffff;
    offset += 4;

    let len  = u16::from_be_bytes([
        ip_hdr[offset], ip_hdr[offset+1], ]);
    offset += 2;

    let mut ext_hdr_flag = false;
    let next_hdr = ip_hdr[offset] as usize;

    let mut str_proto = protocol_to_str(next_hdr).unwrap_or_default(); 
    offset += 1;

    let hl = ip_hdr[offset];
    offset += 1;

    let mut src_addr6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    if let Ok(v) = ip_hdr[offset..offset+15].try_into() {
        src_addr6  = Ipv6Addr::from_octets(v);
    }
    else {
        eprintln!("failure to read src addr")
    }
    offset += 16;

    let mut dst_addr6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    if let Ok(v) = ip_hdr[offset..offset+15].try_into() {
        dst_addr6  = Ipv6Addr::from_octets(v);
    }
    else {
        eprintln!("failure to read dst addr")
    }
    offset += 16;

    let mut ip_print = String::new();
    if short {
        ip_print = format!("\tI6\t
        Src: {}  Dst:{}", src_addr6, dst_addr6
    );
    }
    else {
        if str_proto.len() > 0 {
            ip_print = format!("
            \tIP6\tVer:{}, TC:{}, FL:{}, Len:{}, Next:{}[{}] HL:{} Src: {}  Dst:{} ",
            version, tc, fl, len, next_hdr, str_proto, hl, src_addr6, dst_addr6)
        }
        else {
            ip_print = format!("
            \tIP6\tVer:{}, TC:{}, FL:{}, Len:{}, Next:{} HL:{} Src: {}  Dst:{} ",
            version, tc, fl, len, next_hdr, hl, src_addr6, dst_addr6)

        }
    }
    println!("{}", ip_print);

    if str_proto.is_empty() {
        parse_ipv6_ext(next_hdr, &ip_hdr[offset..]);
    }


    next_hdr
}