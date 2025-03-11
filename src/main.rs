use pnet::datalink::{self};
use std::env;
use std::thread;

pub mod parse;

fn main() {
    // Get a list of all network interfaces
    let interfaces = datalink::interfaces();

    // Parse command line arguments
    let interface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            eprintln!("USAGE: cargo run --release -- <INTERFACE_NAME>");
            eprintln!("Available interfaces:");
            for interface in interfaces.iter() {
                eprintln!("- {}: {:?}", interface.name, interface.mac);
            }
            return;
        }
    };

    // Find the specified interface
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == interface_name)
        .next()
        .expect("Could not find specified interface");

    // Create a new channel to receive packets from the interface
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    println!("Listening on interface: {}", interface_name);

    thread::spawn(move || {
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
}
