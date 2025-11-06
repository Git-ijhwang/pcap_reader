use crate::port::*;


pub fn parse_tcp(tcp: &[u8])
{
    if tcp.len() < 20 {
        println!( "TCP header too short");
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

    let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);

    let data_offset = (tcp[12] >> 4) * 4;
    let flags = tcp[13];

    let syn = (flags & 0x02) != 0;
    let ack = (flags & 0x10) != 0;
    let fin = (flags & 0x01) != 0;
    let rst = (flags & 0x04) != 0;

    let win_size = u16::from_be_bytes([tcp[14], tcp[15]]);
    let chksum   = u16::from_be_bytes([tcp[16], tcp[17]]);

    let mut str_src_port = "".to_string();
    if let Some(v) = port_to_str(src_port) {
        str_src_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    let mut str_dst_port = "".to_string();
    if let Some(v) = port_to_str(dst_port) {
        str_dst_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", dst_port);
    }

    println!(
        "\tSrc:{}[{}]\tDst:{}[{}]\tSeq:{}, Ack:{}, Win:{}, ChkSum:0x{:04x} Flags:[{}{}{}{}]",
        src_port, str_src_port,
        dst_port, str_dst_port,
        seq_num, ack_num, win_size, chksum,
        if syn{"SYN "} else {""},
        if ack{"ACK "} else {""},
        if fin{"FIN "} else {""},
        if rst{"RST "} else {""},
    );

}

fn parse_udp(udp: &[u8])
{
    let mut pos = 0;

    let src_port = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    // let str_src_port = port_to_str(src_port);
    let mut str_src_port = "".to_string();
    if let Some(v) = port_to_str(src_port) {
        str_src_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    pos += 2;

    let dst_port = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    // let str_dst_port = port_to_str(dst_port);
    let mut str_dst_port = "".to_string();
    if let Some(v) = port_to_str(dst_port) {
        str_dst_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", dst_port);
    }

    pos += 2;

    let len = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    pos += 2;

    let chksum = u16::from_be_bytes([udp[pos], udp[pos+1]]);

    let print = format!("\tUDP\tSrc:{}[{}]\n\t\tDst:{}[{}]\n\t\tLen:{}\n\t\tChkSum:0x{:04x}",
        src_port, str_src_port, dst_port, str_dst_port, len, chksum);

    println!("{}", print);
}

pub fn preparse_layer4(proto_num:usize, l4: &[u8])
{
    match proto_num {
        6   => parse_tcp(l4),
        17  => parse_udp(l4),
        1   => println!("ICMP"),
        _   => println!("IP proto {}", proto_num)
    };

    // proto
}
