use super::*;
use crate::{
    codec::providers::{CodecCatalog, ProfileId, ProviderSelection},
    information_elements::{
        InformationElement, parse_information_elements, serialize_information_elements,
    },
    protocol::{
        FullFrameHeader, IaxCommand, decode_iax_command, parse_full_frame_packet,
        serialize_full_frame,
    },
};
use std::{net::UdpSocket, path::PathBuf, thread};

fn catalog() -> Arc<FormatCatalog> {
    let directory = PathBuf::from(std::env::var_os("RPTADV_CODEC_DIR").unwrap_or_default());
    let codecs = Arc::new(
        CodecCatalog::load(&[ProviderSelection {
            path: directory.join("librptadv_codec_g711.so.1"),
            profiles: vec![ProfileId::G711Mu],
        }])
        .unwrap(),
    );
    Arc::new(FormatCatalog::new(codecs, &[ProfileId::G711Mu]).unwrap())
}

fn response(command: u8, sequence: u8, acknowledgement: u8, payload: &[u8]) -> Vec<u8> {
    serialize_full_frame(
        &FullFrameHeader {
            source_call_number: 5678,
            destination_call_number: 1234,
            retransmission: false,
            timestamp: 0,
            outgoing_sequence: sequence,
            incoming_sequence: acknowledgement,
            frame_type: 6,
            subclass: command,
            subclass_is_log: false,
        },
        payload,
    )
    .unwrap()
}

#[test]
fn provider_account_username_and_destination_are_distinct_from_radio_nodes() {
    for authenticate in [false, true] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let remote = socket.local_addr().unwrap();
        let responder = thread::spawn(move || -> std::io::Result<()> {
            let mut bytes = [0; 1500];
            let (length, address) = socket.recv_from(&mut bytes)?;
            let packet = parse_full_frame_packet(&bytes[..length]).unwrap();
            assert_eq!(
                decode_iax_command(&packet.header).unwrap(),
                Some(IaxCommand::New)
            );
            let elements = parse_information_elements(packet.payload).unwrap();
            for (kind, expected) in [
                (6, "club-account"),
                (1, "+18005550123*9#"),
                (2, "KG0BP"),
                (4, "Radio club"),
                (5, "outbound"),
            ] {
                assert_eq!(
                    elements.iter().find(|ie| ie.kind == kind).unwrap().data,
                    expected.as_bytes()
                );
            }
            assert!(
                !bytes[..length]
                    .windows(12)
                    .any(|value| value == b"fixture-only")
            );
            let sequence = u8::from(authenticate);
            if authenticate {
                let payload = serialize_information_elements(&[
                    InformationElement {
                        kind: 14,
                        data: &2u16.to_be_bytes(),
                    },
                    InformationElement {
                        kind: 15,
                        data: b"fixture-challenge",
                    },
                ])
                .unwrap();
                socket.send_to(&response(8, 0, 1, &payload), address)?;
                let (length, _) = socket.recv_from(&mut bytes)?;
                let packet = parse_full_frame_packet(&bytes[..length]).unwrap();
                assert_eq!(
                    decode_iax_command(&packet.header).unwrap(),
                    Some(IaxCommand::AuthRep)
                );
                let elements = parse_information_elements(packet.payload).unwrap();
                assert!(crate::authentication::verify_md5_authrep(
                    "fixture-challenge",
                    "fixture-only",
                    elements.iter().find(|ie| ie.kind == 16).unwrap().data,
                ));
            }
            socket.send_to(
                &response(7, sequence, sequence + 1, &[9, 4, 0, 0, 0, 4]),
                address,
            )?;
            let (length, _) = socket.recv_from(&mut bytes)?;
            assert_eq!(
                decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header)
                    .unwrap(),
                Some(IaxCommand::Ack)
            );
            let mut answer = response(4, sequence + 1, sequence + 1, &[]);
            answer[10] = 4;
            socket.send_to(&answer, address)?;
            let (length, _) = socket.recv_from(&mut bytes)?;
            assert_eq!(
                decode_iax_command(&parse_full_frame_packet(&bytes[..length]).unwrap().header)
                    .unwrap(),
                Some(IaxCommand::Ack)
            );
            Ok(())
        });
        let result = dial(
            DialOptions {
                remote,
                local_call: 1234,
                username: "club-account",
                destination: "+18005550123*9#",
                caller_number: "KG0BP",
                caller_name: "Radio club",
                context: "outbound",
                secret: "fixture-only",
                timeout: Duration::from_secs(2),
            },
            catalog(),
        );
        let observed = responder.join().unwrap();
        assert!(
            result.is_ok(),
            "provider call failed: {:?}",
            result.as_ref().err()
        );
        observed.unwrap();
        let mut peer = result.unwrap();
        assert_eq!((peer.format(), peer.sample_rate_hz()), (4, 8000));
        peer.hangup().unwrap();
    }
}

#[test]
fn provider_identity_rejects_overlong_fields_and_unrepresentable_deadlines() {
    let oversized = "x".repeat(256);
    for field in 0..7 {
        let mut options = DialOptions {
            remote: "127.0.0.1:9".parse().unwrap(),
            local_call: 1,
            username: "account",
            destination: "911",
            caller_number: "",
            caller_name: "",
            context: "",
            secret: "",
            timeout: Duration::from_millis(1),
        };
        match field {
            0 => options.username = &oversized,
            1 => options.destination = &oversized,
            2 => options.caller_number = &oversized,
            3 => options.caller_name = &oversized,
            4 => options.context = &oversized,
            5 => options.local_call = 0x8000,
            6 => options.timeout = Duration::MAX,
            _ => unreachable!(),
        }
        assert!(matches!(
            dial(options, catalog()),
            Err(DialError::InvalidOptions)
        ));
    }
}
