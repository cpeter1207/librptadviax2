/** @file
 * @brief Test-only metadata adapter around a retained real provider descriptor.
 * No codec state or algorithms are substituted by this loader fixture.
 */
#include "rptadv_codec.h"

static rptadv_codec_descriptor_v1_table original, fixture;
static int fault;

static size_t profile_count(void) {
  if (fault == 1)
    return 0;
  if (fault == 2)
    return 17;
  return fault == 4 ? 2 : 1;
}

static int32_t profile_at(size_t index, rptadv_codec_profile_v1 *profile) {
  (void)index;
  if (fault == 3)
    return RPTADV_CODEC_FAILED;
  return original.profile_at(0, profile);
}

/** Copy callbacks while the test retains their real provider's library owner.
 */
void rptadv_test_configure(const rptadv_codec_descriptor_v1_table *api,
                           int selected_fault) {
  original = *api;
  fixture = original;
  fault = selected_fault;
  fixture.profile_count = profile_count;
  fixture.profile_at = profile_at;
}

const rptadv_codec_descriptor_v1_table *rptadv_codec_descriptor_v1(void) {
  return &fixture;
}
