/** @file
 * @brief Test-only media result script over a real retained codec provider.
 */
#include "rptadv_codec.h"
#include <dlfcn.h>
#include <string.h>

static void *library;
static rptadv_codec_descriptor_v1_table fixture;
static int inspect_code, decode_code, conceal_code;
static size_t result_frames;
static unsigned calls;
static int fail_decoder;
static unsigned opened, closed;
static int32_t (*provider_open_encoder)(const rptadv_codec_config_v1 *, void **);
static int32_t (*provider_open_decoder)(const rptadv_codec_config_v1 *, void **);
static void (*provider_destroy)(void *);
static int32_t open_encoder(const rptadv_codec_config_v1 *config, void **output) {
  int32_t result = provider_open_encoder(config, output);
  if (result == 0)
    ++opened;
  return result;
}
static int32_t open_decoder(const rptadv_codec_config_v1 *config, void **output) {
  if (fail_decoder) {
    *output = NULL;
    return 5;
  }
  int32_t result = provider_open_decoder(config, output);
  if (result == 0)
    ++opened;
  return result;
}
static void destroy_context(void *context) {
  provider_destroy(context);
  ++closed;
}
/** Fail actual per-call decoder creation after successful catalog probing. */
void rptadv_test_fail_decoder(int fail) { fail_decoder = fail; }
/** High32 bits successful opens; low32 actual destructor receipts. */
uint64_t rptadv_test_context_counts(void) {
  return ((uint64_t)opened << 32) | closed;
}

static uint32_t frame_unit;
static rptadv_codec_mode_v1 overridden_modes[2];
static int32_t (*provider_profile_at)(size_t, rptadv_codec_profile_v1 *);

static int32_t profile_at(size_t index, rptadv_codec_profile_v1 *out) {
  int32_t result = provider_profile_at(index, out);
  if (result == 0 && frame_unit != 0) {
    overridden_modes[index] = out->modes[0];
    overridden_modes[index].frame_samples = frame_unit;
    overridden_modes[index].frame_bytes = frame_unit;
    out->maximum_frame_samples = frame_unit;
    out->maximum_frame_bytes = frame_unit;
    out->mode_count = 1;
    out->modes = &overridden_modes[index];
  }
  return result;
}

/** A valid declared coding unit that may not satisfy the phone packet profile. */
void rptadv_test_frame_unit(uint32_t unit) { frame_unit = unit; }


static int32_t inspect_packet(void *context, const uint8_t *packet,
                              size_t length, rptadv_codec_packet_info_v1 *out) {
  (void)context;
  (void)packet;
  (void)length;
  calls = calls * 10 + 2;
  out->frames = 160;
  out->required_capacity = 123;
  return inspect_code;
}

static int32_t decode_packet(void *context, const uint8_t *packet,
                             size_t length, float *pcm, size_t capacity,
                             size_t *frames) {
  (void)context;
  (void)packet;
  (void)length;
  (void)pcm;
  (void)capacity;
  calls = calls * 10 + 1;
  *frames = result_frames;
  return decode_code;
}

static int32_t conceal_packet(void *context, uint32_t requested, float *pcm,
                              size_t capacity, size_t *frames) {
  (void)context;
  (void)requested;
  (void)pcm;
  (void)capacity;
  calls = calls * 10 + 3;
  *frames = result_frames;
  return conceal_code;
}

/** Retain the real provider for all context operations and metadata. */
int rptadv_test_open(const char *path) {
  library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!library)
    return -1;
  const rptadv_codec_descriptor_v1_table *(*entry)(void);
  const void *symbol = dlsym(library, "rptadv_codec_descriptor_v1");
  if (!symbol)
    return -1;
  memcpy(&entry, &symbol, sizeof(entry));
  fixture = *entry();
  provider_open_encoder = fixture.open_encoder;
  provider_open_decoder = fixture.open_decoder;
  provider_destroy = fixture.destroy;
  fixture.open_encoder = open_encoder;
  fixture.open_decoder = open_decoder;
  fixture.destroy = destroy_context;
  provider_profile_at = fixture.profile_at;
  fixture.profile_at = profile_at;
  fixture.inspect = inspect_packet;
  fixture.decode = decode_packet;
  fixture.conceal = conceal_packet;
  return 0;
}

/** Set one turn's results, without replacing framing or codec algorithms. */
void rptadv_test_results(int inspect, int decode, int conceal, size_t frames) {
  inspect_code = inspect;
  decode_code = decode;
  conceal_code = conceal;
  result_frames = frames;
  calls = 0;
}

/** Decimal operation trace: decode=1, inspect=2, conceal=3. */
unsigned rptadv_test_calls(void) { return calls; }

const rptadv_codec_descriptor_v1_table *rptadv_codec_descriptor_v1(void) {
  return &fixture;
}

__attribute__((destructor)) static void close_provider(void) {
  if (library)
    dlclose(library);
}
