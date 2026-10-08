use crate::call_token::{
    CallTokenError, CallTokenRetryError, InitialNewError, build_initial_new,
    replace_empty_call_token, retry_new_call_with_token,
};
use crate::information_elements::{InformationElement, parse_information_elements};
use crate::protocol::{FrameEncodeError, IaxCommand, decode_iax_command, parse_full_frame_packet};

fn fixture(name: &str) -> Vec<u8> {
    let text = match name {
        "new-empty-token.hex" => include_str!("../tests/fixtures/iax2/new-empty-token.hex"),
        "calltoken-response.hex" => include_str!("../tests/fixtures/iax2/calltoken-response.hex"),
        "new-with-calltoken.hex" => include_str!("../tests/fixtures/iax2/new-with-calltoken.hex"),
        "new-with-calltoken-retry.hex" => {
            include_str!("../tests/fixtures/iax2/new-with-calltoken-retry.hex")
        }
        _ => panic!("unknown fixture"),
    };
    text.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn builds_initial_new_with_final_empty_calltoken_ie() {
    let information_elements = [
        InformationElement {
            kind: 1,
            data: b"555",
        },
        InformationElement {
            kind: 6,
            data: b"node",
        },
    ];

    assert_eq!(
        build_initial_new(1, 0, &information_elements),
        Ok(fixture("new-empty-token.hex"))
    );
}

#[test]
fn rejects_initial_new_with_duplicate_calltoken_or_invalid_fields() {
    assert_eq!(
        build_initial_new(
            1,
            0,
            &[InformationElement {
                kind: 54,
                data: &[],
            }]
        ),
        Err(InitialNewError::CallTokenAlreadyPresent)
    );
    assert_eq!(
        build_initial_new(
            1,
            0,
            &[InformationElement {
                kind: 7,
                data: &[0; 256],
            }]
        ),
        Err(InitialNewError::InformationElements(
            crate::information_elements::InformationElementError::DataTooLong {
                element_index: 0,
                data_length: 256,
            }
        ))
    );
    assert_eq!(
        build_initial_new(0x8000, 0, &[]),
        Err(InitialNewError::Frame(
            FrameEncodeError::CallNumberOutOfRange {
                field: "source",
                value: 0x8000,
            }
        ))
    );
}

#[test]
fn replaces_only_final_empty_calltoken_ie_from_asterisk_exchange() {
    let initial = fixture("new-empty-token.hex");
    let response = fixture("calltoken-response.hex");
    let expected = fixture("new-with-calltoken.hex");
    let initial_packet = parse_full_frame_packet(&initial).unwrap();
    let response_packet = parse_full_frame_packet(&response).unwrap();

    assert_eq!(
        decode_iax_command(&initial_packet.header),
        Ok(Some(IaxCommand::New))
    );
    assert_eq!(
        decode_iax_command(&response_packet.header),
        Ok(Some(IaxCommand::CallToken))
    );
    let token = parse_information_elements(response_packet.payload)
        .unwrap()
        .into_iter()
        .find(|element| element.kind == 54)
        .unwrap()
        .data;
    let replacement = replace_empty_call_token(initial_packet.payload, token).unwrap();
    let mut header = initial_packet.header;
    header.outgoing_sequence = 0;
    header.incoming_sequence = 0;

    assert_eq!(
        crate::protocol::serialize_full_frame(&header, &replacement).unwrap(),
        expected
    );
}

#[test]
fn rejects_invalid_initial_token_ie_and_oversized_returned_token() {
    assert_eq!(
        replace_empty_call_token(&[1, 0], b"token"),
        Err(CallTokenError::MissingEmptyCallToken)
    );
    assert_eq!(
        replace_empty_call_token(&[54, 1, b'x'], b"token"),
        Err(CallTokenError::MissingEmptyCallToken)
    );
    assert_eq!(
        replace_empty_call_token(&[54, 0], b""),
        Err(CallTokenError::EmptyReturnedToken)
    );
    assert!(matches!(
        replace_empty_call_token(&[54], b"token"),
        Err(CallTokenError::MalformedInformationElements(_))
    ));
    assert_eq!(
        replace_empty_call_token(&[54, 0], &[0; 256]),
        Err(CallTokenError::TokenTooLong { length: 256 })
    );
}

#[test]
fn retries_new_after_calltoken_with_fresh_timestamp_and_sequence_state() {
    let mut initial = fixture("new-empty-token.hex");
    initial[4..8].copy_from_slice(&1_u32.to_be_bytes());
    initial[8] = 4;
    initial[9] = 7;
    let response = fixture("calltoken-response.hex");
    let expected = fixture("new-with-calltoken-retry.hex");

    assert_eq!(
        retry_new_call_with_token(&initial, &response, 42),
        Ok(expected.clone())
    );

    let mut response_with_other_ie = response;
    response_with_other_ie.splice(12..12, [1, 0]);
    assert_eq!(
        retry_new_call_with_token(&initial, &response_with_other_ie, 42),
        Ok(expected)
    );
}

#[test]
fn rejects_invalid_calltoken_exchange_frames_and_payloads() {
    let initial = fixture("new-empty-token.hex");
    let response = fixture("calltoken-response.hex");
    assert_eq!(
        retry_new_call_with_token(&initial[..11], &response, 0),
        Err(CallTokenRetryError::InvalidFrame)
    );
    assert_eq!(
        retry_new_call_with_token(&initial, &response[..11], 0),
        Err(CallTokenRetryError::InvalidFrame)
    );
    assert_eq!(
        retry_new_call_with_token(&[0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0], &response, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut zero_source = initial.clone();
    zero_source[1] = 0;
    assert_eq!(
        retry_new_call_with_token(&zero_source, &response, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut nonzero_destination = initial.clone();
    nonzero_destination[3] = 1;
    assert_eq!(
        retry_new_call_with_token(&nonzero_destination, &response, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut invalid_initial_subclass = initial.clone();
    invalid_initial_subclass[11] = 0xc0;
    assert_eq!(
        retry_new_call_with_token(&invalid_initial_subclass, &response, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut invalid_response_subclass = response.clone();
    invalid_response_subclass[11] = 0xc0;
    assert_eq!(
        retry_new_call_with_token(&initial, &invalid_response_subclass, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut wrong_response = response.clone();
    wrong_response[11] = 2;
    assert_eq!(
        retry_new_call_with_token(&initial, &wrong_response, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut wrong_call = response.clone();
    wrong_call[3] = 2;
    assert_eq!(
        retry_new_call_with_token(&initial, &wrong_call, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut no_token = response.clone();
    no_token.truncate(12);
    assert_eq!(
        retry_new_call_with_token(&initial, &no_token, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut duplicate_token = response.clone();
    duplicate_token.extend_from_slice(&[54, 1, b'x']);
    assert_eq!(
        retry_new_call_with_token(&initial, &duplicate_token, 0),
        Err(CallTokenRetryError::InvalidExchange)
    );

    let mut empty_token = response.clone();
    empty_token[13] = 0;
    empty_token.truncate(14);
    assert_eq!(
        retry_new_call_with_token(&initial, &empty_token, 0),
        Err(CallTokenRetryError::InvalidInitialPayload(
            CallTokenError::EmptyReturnedToken
        ))
    );

    let mut malformed_token_ies = response.clone();
    malformed_token_ies[13] = 0xff;
    assert!(matches!(
        retry_new_call_with_token(&initial, &malformed_token_ies, 0),
        Err(CallTokenRetryError::MalformedInformationElements(_))
    ));

    let mut malformed_initial_ies = initial.clone();
    malformed_initial_ies.pop();
    assert!(matches!(
        retry_new_call_with_token(&malformed_initial_ies, &response, 0),
        Err(CallTokenRetryError::InvalidInitialPayload(_))
    ));
}
