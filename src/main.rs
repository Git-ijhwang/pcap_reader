use std::env;
use std::process;

use chrono::format::format;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use pcap::{Capture, Packet};

mod ipv4;
use ipv4::*;
mod ipv6;
use ipv6::*;
mod l4;
use l4::*;
mod port;
mod gtpv2_types;
mod gtp;
use gtp::*;

pub const IP_HDR_LEN:usize = 20;
pub const MIN_ETH_HDR_LEN:usize = 14;

fn format_timestamp(packet: &Packet) -> String
{
    // pcap::Packet has a header with ts (timeval) fields on most platforms:
    // packet.header.ts.tv_sec and packet.header.ts.tv_usec
    // Use safe fallback if not present.
    let sec = packet.header.ts.tv_sec as i64;
    let usec = packet.header.ts.tv_usec as u32; // microseconds

    // Create naive datetime from seconds + microseconds
    let naive = NaiveDateTime::from_timestamp_opt(sec, usec * 1000)
        .unwrap_or_else(|| NaiveDateTime::from_timestamp_opt(sec, 0).unwrap());

    // let dt: DateTime<Local> = TimeZone::from_utc_datetime(naive, *Local::now().offset());
    let dt: DateTime<Local> = Local.from_local_datetime(&naive).unwrap();

    dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}


fn parse_ethernet(data: &[u8]) -> usize
{
    // let mut ethertype_str = String::from("N/A");
    let mut offset = 0;

    let src_mac = format!("Src Mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
    data[offset+0], data[offset+1], data[offset+2],
    data[offset+3], data[offset+4], data[offset+5]);

    offset += 6;

    let dst_mac = format!("Dst Mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
    data[offset+0], data[offset+1], data[offset+2],
    data[offset+3], data[offset+4], data[offset+5]);

    offset += 6;

    let next_type = u16::from_be_bytes([data[offset], data[offset+1]]) as usize;
    println!("\tMAC\t{}\n\t\t{}", src_mac, dst_mac );

    next_type
}

fn print_timestamp(idx:usize, packet: &Packet)
{
    let ts = format_timestamp(packet);
    println!( "[{:05}] {}\tlen:{}", idx, ts, packet.header.len );
}

fn main()
{
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage {} Filename of pacp file short|long", args[0]);
        process::exit(1);
    }

    let filename = &args[1];
    let detail = &args[2];
    let mut short: bool = false;

    if detail.eq("short") {
        short = true;
    } else {
        short = false;
    }
    println!("short {}", short);

    //read pcap file line by line
    let mut cap = match Capture::from_file(filename) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open pcap file {}", filename);
            process::exit(1);
        }
    };

    let mut idx: usize = 1;

    while let Ok(packet) = cap.next_packet() {
        // Print Time stamp
        print_timestamp(idx, &packet);

        //Parse Layer 2 Ethernet
        let mut next_type = 0;
        if packet.data.len() >= MIN_ETH_HDR_LEN {
            //get next protocol from Ethernet
            next_type = parse_ethernet(&packet.data);
        }

        //Parse Layer 3
        // next_type
        let v= match next_type {
            //IPv4
            0x0800  => Some(parse_ipv4(&packet.data[14..], short)),
            //IPv6
            0x86dd  => Some(parse_ipv6(&packet.data[14..], short)),
            //ARP
            0x0806  => Some(parse_ipv4(&packet.data[14..], short)),
            _       => None,
        };
        if v.is_none() {
            break;
        }
        next_type = v.unwrap();

        //Parse Layer 4
        let protocol = preparse_layer4(next_type,
                         &packet.data[(MIN_ETH_HDR_LEN+IP_HDR_LEN)..]);

        idx += 1;

        match protocol {
            2123 => {
                match parse_gtpc(packet.data) {
                    Ok((_rest, hdr)) =>  {
                        println!("{:#?}", hdr);

                        let ies: Vec<GtpIe> = parse_all_ies(hdr.payload);
                        for ie in ies {
                            println!("IE: Type:{}, len:{}, inst:{}", ie.ie_type, ie.length, ie.instance);
                        }
                    }
                    Err(e) => println!("ERR {:?}", e),
                }
            }
            _ => {}
        }

    }
}
