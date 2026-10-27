//! Owned client of the installed protocol-neutral codec ABI. No wire IDs or codecs.
//! Load at composition startup, never during an audio callback or ordinary reload.

use libloading::Library;
use std::{
    collections::BTreeMap, ffi::c_void, mem::size_of, path::PathBuf, ptr::NonNull, sync::Arc,
};

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    missing_docs
)]
mod abi {
    include!(concat!(env!("OUT_DIR"), "/codec_abi.rs"));
}
type RawDescriptor = abi::rptadv_codec_descriptor_v1_table;
type RawProfile = abi::rptadv_codec_profile_v1;
type RawMode = abi::rptadv_codec_mode_v1;
type RawConfig = abi::rptadv_codec_config_v1;
type RawPacket = abi::rptadv_codec_packet_info_v1;
type RawEncoded = abi::rptadv_codec_encode_result_v1;

/// Stable neutral identity, independent of any protocol format bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProfileId {
    /// G.711 mu-law.
    G711Mu = 1,
    /// G.711 A-law.
    G711A,
    /// GSM FR, not WAV49.
    GsmFr,
    /// G.723.1.
    G723,
    /// G.726 AAL2 32 kb/s.
    G726Aal2,
    /// Dialogic ADPCM.
    Dialogic,
    /// Signed PCM16 big endian, 8 kHz.
    Pcm8,
    /// LPC10.
    Lpc10,
    /// G.729A.
    G729,
    /// Narrowband Speex.
    Speex,
    /// Explicit-mode iLBC.
    Ilbc,
    /// G.726 RFC packing, 32 kb/s.
    G726,
    /// G.722, 16 kHz PCM.
    G722,
    /// Signed PCM16 little endian, 16 kHz.
    Pcm16,
    /// Wideband Speex.
    Speex16,
    /// Mono Opus, 48 kHz PCM.
    Opus,
}
impl ProfileId {
    /// Source PCM clock fixed by the approved neutral profile.
    pub fn sample_rate_hz(self) -> u32 {
        match self {
            Self::G722 | Self::Pcm16 | Self::Speex16 => 16000,
            Self::Opus => 48000,
            _ => 8000,
        }
    }
    /// Reject unknown IDs rather than treating them as protocol bits.
    pub fn from_raw(id: u32) -> Option<Self> {
        const IDS: [ProfileId; 16] = [
            ProfileId::G711Mu,
            ProfileId::G711A,
            ProfileId::GsmFr,
            ProfileId::G723,
            ProfileId::G726Aal2,
            ProfileId::Dialogic,
            ProfileId::Pcm8,
            ProfileId::Lpc10,
            ProfileId::G729,
            ProfileId::Speex,
            ProfileId::Ilbc,
            ProfileId::G726,
            ProfileId::G722,
            ProfileId::Pcm16,
            ProfileId::Speex16,
            ProfileId::Opus,
        ];
        id.checked_sub(1)
            .and_then(|index| IDS.get(index as usize))
            .copied()
    }
}

/// Provider operation outcome; progress is not a failure or a voice packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Completed, possibly with no output during finite flush.
    Complete,
    /// More PCM is needed to complete a coding unit.
    NeedInput,
    /// Capacity failure, without consuming input/state.
    OutputFull,
    /// Invalid record, count or packet.
    Malformed,
    /// Missing profile, mode or direction.
    Unsupported,
    /// Backend/load/contract failure.
    Failed,
}
impl Status {
    fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Complete,
            1 => Self::NeedInput,
            2 => Self::OutputFull,
            3 => Self::Malformed,
            4 => Self::Unsupported,
            _ => Self::Failed,
        }
    }
}
/// Value-free diagnostic plus capacity needed for a safe retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Operation outcome.
    pub status: Status,
    /// Required bytes or PCM frames for output-full.
    pub required_capacity: usize,
    /// Stable operation/classification; no packet data or credentials.
    pub operation: &'static str,
}
pub(super) fn error(operation: &'static str) -> Error {
    Error {
        status: Status::Failed,
        required_capacity: 0,
        operation,
    }
}
fn completed(code: i32, required_capacity: usize) -> Result<(), Error> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error {
            status: Status::from_raw(code),
            required_capacity,
            operation: "codec operation",
        })
    }
}

/// Selected DSO and the neutral profiles it must supply bidirectionally.
pub struct ProviderSelection {
    /// Dynamic provider path copied by the composition owner.
    pub path: PathBuf,
    /// Explicit profiles; no inferred fallback when a selection fails.
    pub profiles: Vec<ProfileId>,
}
/// Copied mode metadata; never borrows a provider-owned pointer.
#[derive(Clone, Debug)]
pub struct Mode {
    /// Profile-local mode identity.
    pub id: u32,
    /// Bits per second.
    pub bitrate_bps: u32,
    /// PCM frames per coding unit.
    pub frame_samples: u32,
    /// Fixed bytes per unit, or zero for variable length.
    pub frame_bytes: u32,
}
/// Validated, owned metadata for one selected neutral profile.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Neutral identity.
    pub id: ProfileId,
    /// Actual source PCM clock.
    pub sample_rate_hz: u32,
    /// Encoder lookahead at that source clock.
    pub lookahead_frames: u32,
    /// Largest legal coding-unit PCM count.
    pub maximum_frame_samples: u32,
    /// Largest legal coding-unit encoded size.
    pub maximum_frame_bytes: u32,
    /// Explicit supported modes, in provider preference order.
    pub modes: Vec<Mode>,
}
struct Provider {
    api: RawDescriptor,
    _library: Library,
}
struct Selected {
    profile: Profile,
    provider: Arc<Provider>,
}
/// Immutable composition catalog. Contexts independently retain their provider DSO.
#[derive(Default)]
pub struct CodecCatalog {
    selected: BTreeMap<ProfileId, Selected>,
}
impl CodecCatalog {
    /// Load only explicitly configured providers and reject invalid/missing contracts.
    pub fn load(selections: &[ProviderSelection]) -> Result<Self, Error> {
        let mut catalog = Self::default();
        for selection in selections {
            if selection.profiles.is_empty() {
                return Err(error("empty provider selection"));
            }
            // Loading code is an explicit trusted composition operation, outside audio.
            let library =
                unsafe { Library::new(&selection.path) }.map_err(|_| error("load provider"))?;
            let entry = unsafe {
                library.get::<unsafe extern "C" fn() -> *const RawDescriptor>(
                    b"rptadv_codec_descriptor_v1\0",
                )
            }
            .map_err(|_| error("provider symbol"))?;
            let api = unsafe { table(entry())? };
            let count = unsafe { (api.profile_count.unwrap())() };
            if count == 0 || count > 16 {
                return Err(error("provider profile count"));
            }
            let provider = Arc::new(Provider {
                api,
                _library: library,
            });
            let mut profiles = BTreeMap::new();
            for index in 0..count {
                let mut raw = RawProfile {
                    struct_size: size_of::<RawProfile>() as u32,
                    ..Default::default()
                };
                completed(unsafe { (api.profile_at.unwrap())(index, &mut raw) }, 0)?;
                let profile = unsafe { copy_profile(&raw)? };
                if profiles.insert(profile.id, profile).is_some() {
                    return Err(error("duplicate provider profile"));
                }
            }
            for &id in &selection.profiles {
                let profile = profiles
                    .get(&id)
                    .ok_or_else(|| error("selected profile missing"))?
                    .clone();
                if catalog
                    .selected
                    .insert(
                        id,
                        Selected {
                            profile,
                            provider: Arc::clone(&provider),
                        },
                    )
                    .is_some()
                {
                    return Err(error("duplicate selected profile"));
                }
            }
        }
        // A bidirectional claim is not sufficient: both selected directions must
        // initialize before this composition can advertise them. No media work.
        for selected in catalog.selected.values() {
            let profile = &selected.profile;
            let mode = &profile.modes[0];
            let _encoder = catalog.encoder(
                profile.id,
                mode.id,
                mode.frame_samples,
                profile.maximum_frame_bytes as usize,
            )?;
            let _decoder = catalog.decoder(
                profile.id,
                mode.id,
                mode.frame_samples,
                profile.maximum_frame_bytes as usize,
            )?;
        }
        Ok(catalog)
    }
    /// Only these verified bidirectional profiles may be advertised.
    pub fn profiles(&self) -> impl Iterator<Item = &Profile> {
        self.selected.values().map(|s| &s.profile)
    }
    /// Lookup without loading libraries or allocating.
    pub fn profile(&self, id: ProfileId) -> Option<&Profile> {
        self.selected.get(&id).map(|s| &s.profile)
    }
    fn open(
        &self,
        id: ProfileId,
        mode: u32,
        packet: u32,
        maximum: usize,
        encoder: bool,
    ) -> Result<Context, Error> {
        let selected = self
            .selected
            .get(&id)
            .ok_or_else(|| error("unselected profile"))?;
        let config = RawConfig {
            struct_size: size_of::<RawConfig>() as u32,
            profile_id: id as u32,
            mode_id: mode,
            packet_frames: packet,
            max_packet_bytes: maximum,
        };
        let provider = Arc::clone(&selected.provider);
        let open = if encoder {
            provider.api.open_encoder
        } else {
            provider.api.open_decoder
        }
        .unwrap();
        let mut raw = std::ptr::null_mut();
        completed(unsafe { open(&config, &mut raw) }, 0)?;
        let raw = NonNull::new(raw).ok_or_else(|| error("null codec context"))?;
        Ok(Context { raw, provider })
    }
    /// Prepare one exclusive encoder off audio.
    pub fn encoder(
        &self,
        id: ProfileId,
        mode: u32,
        packet: u32,
        maximum: usize,
    ) -> Result<Encoder, Error> {
        self.open(id, mode, packet, maximum, true).map(Encoder)
    }
    /// Prepare one exclusive decoder off audio.
    pub fn decoder(
        &self,
        id: ProfileId,
        mode: u32,
        packet: u32,
        maximum: usize,
    ) -> Result<Decoder, Error> {
        self.open(id, mode, packet, maximum, false).map(Decoder)
    }
}

unsafe fn table(raw: *const RawDescriptor) -> Result<RawDescriptor, Error> {
    if raw.is_null() || raw as usize % std::mem::align_of::<RawDescriptor>() != 0 {
        return Err(error("provider table pointer"));
    }
    if unsafe { raw.cast::<u32>().read() } < size_of::<RawDescriptor>() as u32 {
        return Err(error("provider table size"));
    }
    let api = unsafe { *raw };
    if api.abi_version != 1
        || api.capability != *b"rptadv.codec.v1\0"
        || api.profile_count.is_none()
        || api.profile_at.is_none()
        || api.open_encoder.is_none()
        || api.open_decoder.is_none()
        || api.inspect.is_none()
        || api.encode.is_none()
        || api.decode.is_none()
        || api.reset.is_none()
        || api.destroy.is_none()
        || api.conceal.is_none()
    {
        return Err(error("provider table contract"));
    }
    Ok(api)
}
unsafe fn copy_profile(raw: &RawProfile) -> Result<Profile, Error> {
    let id = ProfileId::from_raw(raw.id).ok_or_else(|| error("unknown neutral profile"))?;
    if raw.struct_size < size_of::<RawProfile>() as u32
        || raw.channels != 1
        || raw.directions != 3
        || raw.sample_rate_hz != id.sample_rate_hz()
        || raw.maximum_frame_samples == 0
        || raw.maximum_frame_bytes == 0
        || raw.mode_count == 0
        || raw.mode_count > 16
        || raw.modes.is_null()
        || raw.modes as usize % std::mem::align_of::<RawMode>() != 0
    {
        return Err(error("provider profile contract"));
    }
    let mut modes = Vec::with_capacity(raw.mode_count);
    for raw_mode in unsafe { std::slice::from_raw_parts(raw.modes, raw.mode_count) } {
        if raw_mode.struct_size < size_of::<RawMode>() as u32
            || raw_mode.frame_samples == 0
            || raw_mode.frame_samples > raw.maximum_frame_samples
            || raw_mode.frame_bytes > raw.maximum_frame_bytes
            || modes.iter().any(|mode: &Mode| mode.id == raw_mode.id)
        {
            return Err(error("provider mode contract"));
        }
        modes.push(Mode {
            id: raw_mode.id,
            bitrate_bps: raw_mode.bitrate_bps,
            frame_samples: raw_mode.frame_samples,
            frame_bytes: raw_mode.frame_bytes,
        });
    }
    Ok(Profile {
        id,
        sample_rate_hz: raw.sample_rate_hz,
        lookahead_frames: raw.lookahead_frames,
        maximum_frame_samples: raw.maximum_frame_samples,
        maximum_frame_bytes: raw.maximum_frame_bytes,
        modes,
    })
}
struct Context {
    raw: NonNull<c_void>,
    provider: Arc<Provider>,
}
// The ABI allows owner-task migration, but never concurrent calls on a context.
unsafe impl Send for Context {}
impl Context {
    fn reset(&mut self) -> Result<(), Error> {
        completed(
            unsafe { (self.provider.api.reset.unwrap())(self.raw.as_ptr()) },
            0,
        )
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            (self.provider.api.destroy.unwrap())(self.raw.as_ptr());
        }
    }
}
/// Non-consuming packet metadata at the profile's source clock.
#[derive(Debug, PartialEq, Eq)]
pub struct PacketInfo {
    /// Decoded source frames.
    pub frames: u32,
    /// Profile-local mode.
    pub mode: u32,
}
/// Encoder progress with real PCM span separate from padded wire duration.
#[derive(Debug, PartialEq, Eq)]
pub struct EncodeResult {
    /// Completed or needs more input.
    pub status: Status,
    /// Input PCM consumed in this call.
    pub consumed_frames: usize,
    /// Encoded bytes produced.
    pub encoded_bytes: usize,
    /// Real start position since reset.
    pub source_start_frames: u64,
    /// Real source frames represented.
    pub source_frames: u32,
    /// Decoded packet frames including padding.
    pub packet_frames: u32,
}
/// Independent, non-real-time encoder owner.
pub struct Encoder(Context);
impl Encoder {
    /// Accept bounded PCM, returning at most one packet. Capacity failure consumes nothing.
    pub fn encode(
        &mut self,
        pcm: &[f32],
        out: &mut [u8],
        flush: bool,
    ) -> Result<EncodeResult, Error> {
        let mut raw = RawEncoded {
            struct_size: size_of::<RawEncoded>() as u32,
            ..Default::default()
        };
        let code = unsafe {
            (self.0.provider.api.encode.unwrap())(
                self.0.raw.as_ptr(),
                pcm.as_ptr(),
                pcm.len(),
                out.as_mut_ptr(),
                out.len(),
                u32::from(flush),
                &mut raw,
            )
        };
        if code != 1 {
            completed(code, raw.required_capacity)?;
        }
        if raw.status != code as u32
            || raw.consumed_frames > pcm.len()
            || raw.encoded_bytes > out.len()
            || raw.source_frames > raw.packet_frames
            || (raw.encoded_bytes != 0 && raw.packet_frames == 0)
        {
            return Err(error("provider encode result"));
        }
        Ok(EncodeResult {
            status: Status::from_raw(code),
            consumed_frames: raw.consumed_frames,
            encoded_bytes: raw.encoded_bytes,
            source_start_frames: raw.source_start_frames,
            source_frames: raw.source_frames,
            packet_frames: raw.packet_frames,
        })
    }
    /// Deliberately abandon buffered media/history after expiry or discontinuity.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.0.reset()
    }
}
/// Independent, non-real-time decoder owner.
pub struct Decoder(Context);
impl Decoder {
    /// Preserve native damaged-packet recovery, then request explicit native
    /// PLC only if decode reports malformed input with a known source span.
    /// Zero means the codec could not supply that span; the caller uses its ring.
    pub fn decode_recovering(&mut self, packet: &[u8], pcm: &mut [f32]) -> Result<usize, Error> {
        match self.decode(packet, pcm) {
            Err(error) if error.status == Status::Malformed => {
                let frames = self.inspect(packet)?.frames;
                self.conceal(frames, pcm)
            }
            result => result,
        }
    }
    /// Prefer the backend's native PLC for a supported missing source span.
    /// Unsupported spans return zero samples and leave shared-ring fallback to
    /// the caller; successful native output must not be concealed a second time.
    pub fn conceal(&mut self, requested: u32, pcm: &mut [f32]) -> Result<usize, Error> {
        let mut frames = 0;
        let code = unsafe {
            (self.0.provider.api.conceal.unwrap())(
                self.0.raw.as_ptr(),
                requested,
                pcm.as_mut_ptr(),
                pcm.len(),
                &mut frames,
            )
        };
        if code == 4 && frames == 0 {
            return Ok(0);
        }
        completed(code, frames)?;
        if frames != requested as usize || frames > pcm.len() {
            return Err(error("provider conceal result"));
        }
        Ok(frames)
    }
    /// Inspect framing without advancing decoder history or invoking PLC.
    pub fn inspect(&self, packet: &[u8]) -> Result<PacketInfo, Error> {
        let mut raw = RawPacket {
            struct_size: size_of::<RawPacket>() as u32,
            ..Default::default()
        };
        completed(
            unsafe {
                (self.0.provider.api.inspect.unwrap())(
                    self.0.raw.as_ptr(),
                    packet.as_ptr(),
                    packet.len(),
                    &mut raw,
                )
            },
            raw.required_capacity,
        )?;
        Ok(PacketInfo {
            frames: raw.frames,
            mode: raw.mode,
        })
    }
    /// Decode the entire compressed packet before any PCM overlap trimming.
    pub fn decode(&mut self, packet: &[u8], pcm: &mut [f32]) -> Result<usize, Error> {
        let mut frames = 0;
        completed(
            unsafe {
                (self.0.provider.api.decode.unwrap())(
                    self.0.raw.as_ptr(),
                    packet.as_ptr(),
                    packet.len(),
                    pcm.as_mut_ptr(),
                    pcm.len(),
                    &mut frames,
                )
            },
            frames,
        )?;
        if frames > pcm.len() {
            return Err(error("provider decode result"));
        }
        Ok(frames)
    }
    /// Reset history between independent source generations.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.0.reset()
    }
}

#[cfg(test)]
mod tests;
