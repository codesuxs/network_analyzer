use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Information extracted from a packet
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub source_mac: Option<MacAddr>,
    pub dest_mac: Option<MacAddr>,
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: Option<String>,
    pub length: usize,
}

impl Default for PacketInfo {
    fn default() -> Self {
        PacketInfo {
            source_mac: None,
            dest_mac: None,
            source_ip: None,
            dest_ip: None,
            source_port: None,
            dest_port: None,
            protocol: None,
            length: 0,
        }
    }
}

/// Parse a packet received from a pnet receive thread
pub fn parse_packet(packet_data: &[u8]) -> PacketInfo {
    let mut packet_info = PacketInfo {
        length: packet_data.len(),
        ..Default::default()
    };

    if let Some(ethernet_packet) = EthernetPacket::new(packet_data) {
        packet_info.source_mac = Some(ethernet_packet.get_source());
        packet_info.dest_mac = Some(ethernet_packet.get_destination());

        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                    handle_ipv4_packet(ipv4_packet, &mut packet_info);
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                    handle_ipv6_packet(ipv6_packet, &mut packet_info);
                }
            }
            other => {
                packet_info.protocol = Some(format!("Other EtherType: {:?}", other));
            }
        }
    }

    packet_info
}

/// Format a MAC address into a human-readable string
//fn format_mac(mac: &[u8]) -> String {
//    mac.iter()
//        .map(|byte| format!("{:02x}", byte))
//        .collect::<Vec<String>>()
//        .join(":")
//}

/// Handle an IPv4 packet, extracting relevant information
fn handle_ipv4_packet(ipv4_packet: Ipv4Packet, packet_info: &mut PacketInfo) {
    packet_info.source_ip = Some(IpAddr::V4(Ipv4Addr::from(ipv4_packet.get_source())));
    packet_info.dest_ip = Some(IpAddr::V4(Ipv4Addr::from(ipv4_packet.get_destination())));

    handle_transport_protocol(
        ipv4_packet.get_next_level_protocol(),
        ipv4_packet.payload(),
        packet_info,
    );
}

/// Handle an IPv6 packet, extracting relevant information
fn handle_ipv6_packet(ipv6_packet: Ipv6Packet, packet_info: &mut PacketInfo) {
    packet_info.source_ip = Some(IpAddr::V6(Ipv6Addr::from(ipv6_packet.get_source())));
    packet_info.dest_ip = Some(IpAddr::V6(Ipv6Addr::from(ipv6_packet.get_destination())));

    handle_transport_protocol(
        ipv6_packet.get_next_header(),
        ipv6_packet.payload(),
        packet_info,
    );
}

/// Handle the transport layer protocol (TCP, UDP, etc.)
fn handle_transport_protocol(
    next_header: IpNextHeaderProtocol,
    payload: &[u8],
    packet_info: &mut PacketInfo,
) {
    match next_header {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(payload) {
                packet_info.protocol = Some("TCP".to_string());
                packet_info.source_port = Some(tcp_packet.get_source());
                packet_info.dest_port = Some(tcp_packet.get_destination());
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_packet) = UdpPacket::new(payload) {
                packet_info.protocol = Some("UDP".to_string());
                packet_info.source_port = Some(udp_packet.get_source());
                packet_info.dest_port = Some(udp_packet.get_destination());
            }
        }
        protocol => {
            packet_info.protocol = Some(format!("Other Protocol: {:?}", protocol));
        }
    }
}

/// A simple packet filter to determine if a packet matches certain criteria
pub struct PacketFilter {
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: Option<String>,
}

impl PacketFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        PacketFilter {
            source_ip: None,
            dest_ip: None,
            source_port: None,
            dest_port: None,
            protocol: None,
        }
    }

    /// Check if a packet matches this filter
    pub fn matches(&self, packet_info: &PacketInfo) -> bool {
        // Source IP check
        if let Some(filter_ip) = &self.source_ip {
            if let Some(packet_ip) = &packet_info.source_ip {
                if filter_ip != packet_ip {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Destination IP check
        if let Some(filter_ip) = &self.dest_ip {
            if let Some(packet_ip) = &packet_info.dest_ip {
                if filter_ip != packet_ip {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Source port check
        if let Some(filter_port) = &self.source_port {
            if let Some(packet_port) = &packet_info.source_port {
                if filter_port != packet_port {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Destination port check
        if let Some(filter_port) = &self.dest_port {
            if let Some(packet_port) = &packet_info.dest_port {
                if filter_port != packet_port {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Protocol check
        if let Some(filter_protocol) = &self.protocol {
            if let Some(packet_protocol) = &packet_info.protocol {
                if filter_protocol != packet_protocol {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}
