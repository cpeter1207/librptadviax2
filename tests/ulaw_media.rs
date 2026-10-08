use rptadviax2::codec::{CodecAdapter, G711Ulaw, IAX_FORMAT_ULAW};
use rptadviax2::media::{VoiceFrame, encode_mini_voice_frame, parse_voice_frame};
use rptadviax2::network::UdpEndpoint;
use rptadviax2::protocol::MiniFrameHeader;
use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn ulaw_mini_frame_crosses_the_udp_boundary_as_opaque_payload() {
    let codec = G711Ulaw;
    let sender = UdpEndpoint::bind(loopback()).unwrap();
    let receiver = UdpEndpoint::bind(loopback()).unwrap();
    let pcm = [-32124.0 / 32768.0, 0.0, 32124.0 / 32768.0];
    let mut datagram = [0; 7];
    let length = encode_mini_voice_frame(
        &codec,
        MiniFrameHeader {
            source_call_number: 7,
            timestamp: 160,
        },
        &pcm,
        &mut datagram,
    )
    .unwrap();
    assert_eq!(datagram, [0x00, 0x07, 0x00, 0xa0, 0x00, 0xff, 0x80]);
    sender
        .send_to(&datagram[..length], receiver.local_addr().unwrap())
        .unwrap();

    let mut received = [0; 64];
    let deadline = Instant::now() + Duration::from_secs(1);
    let (length, _) = loop {
        if let Some(datagram) = receiver.try_receive(&mut received).unwrap() {
            break datagram;
        }
        assert!(Instant::now() < deadline, "loopback media timed out");
        thread::sleep(Duration::from_millis(1));
    };
    let frame = parse_voice_frame(&received[..length], codec.iax_format()).unwrap();
    let VoiceFrame::Mini {
        header,
        format,
        payload,
    } = frame
    else {
        panic!("sent mini frame should arrive as mini voice media");
    };

    assert_eq!(header.source_call_number, 7);
    assert_eq!(header.timestamp, 160);
    assert_eq!(format, IAX_FORMAT_ULAW);
    assert_eq!(payload, &datagram[4..length]);

    let mut received_pcm = [0.0; 3];
    assert_eq!(codec.decode(payload, &mut received_pcm), Ok(3));
    assert_eq!(received_pcm, pcm);
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}
