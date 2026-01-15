// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/chrome_h2_profile.h"

namespace holytls {
namespace http2 {

namespace {

// Chrome 143 profile (latest, default)
ChromeH2Profile CreateChrome143Profile() {
  ChromeH2Profile profile;
  profile.version = ChromeVersion::kChrome143;
  profile.settings = kChrome143H2Settings;  // Only 4 settings sent
  profile.connection_window_update = 15663105;
  profile.pseudo_header_order = ChromeH2Profile::PseudoHeaderOrder::kMASP;
  profile.send_priority_frames = false;
  profile.default_priority_weight = 256;
  return profile;
}

// Static profile instances
// Static profile instances
const ChromeH2Profile kProfileChrome143 = CreateChrome143Profile();

}  // namespace

const ChromeH2Profile& GetChromeH2Profile(ChromeVersion version) {
  // We only support Chrome 143 now
  return kProfileChrome143;
}

}  // namespace http2
}  // namespace holytls
