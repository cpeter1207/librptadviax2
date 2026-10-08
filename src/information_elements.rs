//! Zero-copy parsing for IAX information elements in full-frame payloads.

/// One length-delimited IAX information element borrowing from its packet.
#[derive(Debug, Eq, PartialEq)]
pub struct InformationElement<'a> {
    /// IAX information element identifier.
    pub kind: u8,
    /// Element body, without its identifier or length octets.
    pub data: &'a [u8],
}

/// Why an information-element payload is malformed.
#[derive(Debug, Eq, PartialEq)]
pub enum InformationElementError {
    /// A final element identifier has no following length octet.
    MissingLength {
        /// Byte offset of the element identifier.
        offset: usize,
    },
    /// Element data ends before the encoded length.
    TruncatedData {
        /// Byte offset of the malformed element identifier.
        offset: usize,
        /// Length declared by the packet.
        expected_length: usize,
        /// Number of element bytes remaining in the packet.
        available_length: usize,
    },
    /// Element data cannot fit in its one-octet length field.
    DataTooLong {
        /// Index of the element in the serialization input.
        element_index: usize,
        /// Supplied data length in octets.
        data_length: usize,
    },
}

/// Parse all IAX information elements while borrowing element data.
pub fn parse_information_elements(
    payload: &[u8],
) -> Result<Vec<InformationElement<'_>>, InformationElementError> {
    let mut elements = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        if payload.len() - offset < 2 {
            return Err(InformationElementError::MissingLength { offset });
        }

        let kind = payload[offset];
        let expected_length = usize::from(payload[offset + 1]);
        let data_start = offset + 2;
        let available_length = payload.len() - data_start;
        if expected_length > available_length {
            return Err(InformationElementError::TruncatedData {
                offset,
                expected_length,
                available_length,
            });
        }

        let data_end = data_start + expected_length;
        elements.push(InformationElement {
            kind,
            data: &payload[data_start..data_end],
        });
        offset = data_end;
    }

    Ok(elements)
}

/// Serialize IAX information elements into a full-frame payload.
pub fn serialize_information_elements(
    elements: &[InformationElement<'_>],
) -> Result<Vec<u8>, InformationElementError> {
    let mut payload = Vec::new();
    for (element_index, element) in elements.iter().enumerate() {
        if element.data.len() > usize::from(u8::MAX) {
            return Err(InformationElementError::DataTooLong {
                element_index,
                data_length: element.data.len(),
            });
        }
        payload.extend_from_slice(&[element.kind, element.data.len() as u8]);
        payload.extend_from_slice(element.data);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{
        InformationElement, InformationElementError, parse_information_elements,
        serialize_information_elements,
    };

    #[test]
    fn preserves_multiple_known_and_unknown_elements() {
        let payload = [0x06, 3, b'u', b's', b'r', 0xfe, 2, 0x00, 0xff];

        assert_eq!(
            parse_information_elements(&payload),
            Ok(vec![
                InformationElement {
                    kind: 0x06,
                    data: b"usr",
                },
                InformationElement {
                    kind: 0xfe,
                    data: &[0x00, 0xff],
                },
            ])
        );
    }

    #[test]
    fn accepts_empty_payload_and_zero_length_element() {
        assert_eq!(parse_information_elements(&[]), Ok(Vec::new()));
        assert_eq!(
            parse_information_elements(&[0x05, 0]),
            Ok(vec![InformationElement {
                kind: 0x05,
                data: &[],
            }])
        );
    }

    #[test]
    fn rejects_missing_length_at_element_offset() {
        assert_eq!(
            parse_information_elements(&[0x06, 1, b'x', 0xfe]),
            Err(InformationElementError::MissingLength { offset: 3 })
        );
    }

    #[test]
    fn rejects_truncated_element_data_with_exact_lengths() {
        assert_eq!(
            parse_information_elements(&[0x06, 3, b'u', b's']),
            Err(InformationElementError::TruncatedData {
                offset: 0,
                expected_length: 3,
                available_length: 2,
            })
        );
    }

    #[test]
    fn serializes_concatenated_elements_in_wire_order() {
        let elements = [
            InformationElement {
                kind: 0x06,
                data: b"usr",
            },
            InformationElement {
                kind: 0xfe,
                data: &[0x00, 0xff],
            },
        ];

        assert_eq!(
            serialize_information_elements(&elements),
            Ok(vec![0x06, 3, b'u', b's', b'r', 0xfe, 2, 0x00, 0xff])
        );
    }

    #[test]
    fn rejects_element_data_that_cannot_fit_length_octet() {
        let data = [0_u8; 256];
        let elements = [InformationElement {
            kind: 1,
            data: &data,
        }];

        assert_eq!(
            serialize_information_elements(&elements),
            Err(InformationElementError::DataTooLong {
                element_index: 0,
                data_length: 256,
            })
        );
    }

    #[test]
    fn accepts_maximum_length_field_value() {
        let data = [0xa5; 255];
        let elements = [InformationElement {
            kind: 0x2d,
            data: &data,
        }];
        let encoded = serialize_information_elements(&elements).unwrap();

        assert_eq!(encoded[0..2], [0x2d, 255]);
        assert_eq!(parse_information_elements(&encoded).unwrap(), elements);
    }
}
