//! Reject invalid descriptors before any operation/context can be advertised.
use super::*;

#[test]
fn contract_rejects_bad_tables_and_unknown_profiles() {
    assert!(unsafe { table(std::ptr::null()) }.is_err());
    assert!(unsafe { table(std::ptr::dangling::<u8>().cast()) }.is_err());
    let mut raw = RawDescriptor::default();
    assert!(unsafe { table(&raw) }.is_err());
    raw.struct_size = size_of::<RawDescriptor>() as u32;
    raw.abi_version = 1;
    raw.capability = *b"rptadv.codec.v1\0";
    assert!(unsafe { table(&raw) }.is_err());
    assert_eq!(ProfileId::from_raw(0), None);
    assert_eq!(ProfileId::from_raw(17), None);
    for id in 1..=16 {
        assert_eq!(ProfileId::from_raw(id).unwrap() as u32, id);
    }
}

#[test]
fn contract_profile_copies_modes_and_rejects_invalid_metadata() {
    let mode = RawMode {
        struct_size: size_of::<RawMode>() as u32,
        id: 0,
        bitrate_bps: 64000,
        frame_samples: 1,
        frame_bytes: 1,
    };
    let mut raw = RawProfile {
        struct_size: size_of::<RawProfile>() as u32,
        id: 1,
        sample_rate_hz: 8000,
        channels: 1,
        directions: 3,
        lookahead_frames: 0,
        maximum_frame_samples: 1,
        maximum_frame_bytes: 1,
        mode_count: 1,
        modes: &mode,
    };
    assert_eq!(
        unsafe { copy_profile(&raw) }.unwrap().modes[0].frame_samples,
        1
    );
    raw.directions = 1;
    assert!(unsafe { copy_profile(&raw) }.is_err());
    raw.directions = 3;
    raw.sample_rate_hz = 16000;
    assert!(unsafe { copy_profile(&raw) }.is_err());
}
