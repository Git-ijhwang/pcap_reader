pub fn v6_ext_hdr_to_str(ext_hdr: usize) -> Option<String>
{
    match ext_hdr {
        0	=> Some("Hop-by-Hop Extension Header".to_string()),
        43	=> Some("Routing Extension Header".to_string()),
        44	=> Some("Fragment Extension Header".to_string()),
        51	=> Some("Authentication Header (AH) Extension Header".to_string()),
        50	=> Some("Encapsulating Security Payload (ESP) Extension Header".to_string()),
        60	=> Some("Destination Extension Header".to_string()),
        135	=> Some("Mobility Extension Header".to_string()),
        139	=> Some("Host Identity Protocol Extension Header".to_string()),
        140	=> Some("Shim6 Protocol Extension Header".to_string()),
        _   => None,
    }

}

pub fn protocol_to_str(next_hdr: usize) -> Option<String>
{
    match next_hdr {
        1   => Some("ICMP".to_string()),
        4   => Some("IP in IP".to_string()),
        6   => Some("TCP".to_string()),
        17  => Some("UDP".to_string()),
        58  => Some("ICMPv6".to_string()),
        _   => None,
    }

}

pub fn port_to_str(port: u16) -> Option<String>
{
    match port {
        20  => Some("FTP-Data".to_string()),
        21  => Some("FTP-Control".to_string()),
        22  => Some("SSH".to_string()),
        23  => Some("Telnet".to_string()),
        25  => Some("SMTP".to_string()),
        53  => Some("DNS".to_string()),
        67  => Some("DHCP-Server".to_string()),
        68  => Some("DHCP-Client".to_string()),
        69  => Some("TFTP".to_string()),
        80  => Some("HTTP".to_string()),
        110 => Some("POP3".to_string()),
        123 => Some("NTP".to_string()),
        143 => Some("IMAP".to_string()),
        161 => Some("SNMP".to_string()),
        443 => Some("HTTPS".to_string()),
        587 => Some("SMTP-SSL".to_string()),

        // LTE / Mobile Core
        1812 => Some("RADIUS-Auth".to_string()),
        1813 => Some("RADIUS-Acc".to_string()),
        3868 => Some("Diameter".to_string()),
        2123 => Some("GTPv2-C".to_string()),
        2152 => Some("GTP-U".to_string()),

        // 5G
        8805 => Some("PFCP".to_string()),
        9091 => Some("HTTP2 (Common for SBA)".to_string()),
        _       => None,
    }
}