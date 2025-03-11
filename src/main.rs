use pnet::datalink::{self, NetworkInterface};
use std::env;
use std::thread;
pub mod parse;

fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet_info = parse::parse_packet(packet);

                // Only process packets that match our filter
                println!("Received packet: {:?}", packet_info);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
                break;
            }
        }
    }
    let parser = thread::spawn(move || {
        loop {
            match rx.next() {
                Ok(packet) => {
                    let packet_info = parse::parse_packet(packet);

                    // Only process packets that match our filter
                    println!("Received packet: {:?}", packet_info);
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
    });
    parser.join().unwrap();
}
