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
