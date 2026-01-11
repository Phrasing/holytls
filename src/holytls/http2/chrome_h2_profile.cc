// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/chrome_h2_profile.h"

namespace holytls {
namespace http2 {

namespace {

// Chrome 120 profile
ChromeH2Profile CreateChrome120Profile() {
  ChromeH2Profile profile;
  profile.version = ChromeVersion::kChrome120;
  profile.settings = kChrome120H2Settings;
  profile.connection_window_update = 15663105;
  profile.pseudo_header_order = ChromeH2Profile::PseudoHeaderOrder::kMASP;
  profile.send_priority_frames = false;
  profile.default_priority_weight = 256;
  return profile;
}

// Chrome 125 profile
ChromeH2Profile CreateChrome125Profile() {
  ChromeH2Profile profile;
  profile.version = ChromeVersion::kChrome125;
  profile.settings = kChrome120H2Settings;  // Same settings
  profile.connection_window_update = 15663105;
  profile.pseudo_header_order = ChromeH2Profile::PseudoHeaderOrder::kMASP;
  profile.send_priority_frames = false;
  profile.default_priority_weight = 256;
  return profile;
}

// Chrome 130 profile
ChromeH2Profile CreateChrome130Profile() {
  ChromeH2Profile profile;
  profile.version = ChromeVersion::kChrome130;
  profile.settings = kChrome120H2Settings;  // Same settings
  profile.connection_window_update = 15663105;
  profile.pseudo_header_order = ChromeH2Profile::PseudoHeaderOrder::kMASP;
  profile.send_priority_frames = false;
  profile.default_priority_weight = 256;
  return profile;
}

// Chrome 131 profile
ChromeH2Profile CreateChrome131Profile() {
  ChromeH2Profile profile;
  profile.version = ChromeVersion::kChrome131;
  profile.settings = kChrome120H2Settings;  // Same settings as 120
  profile.connection_window_update = 15663105;
  profile.pseudo_header_order = ChromeH2Profile::PseudoHeaderOrder::kMASP;
  profile.send_priority_frames = false;
  profile.default_priority_weight = 256;
  return profile;
}

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
const ChromeH2Profile kProfileChrome120 = CreateChrome120Profile();
const ChromeH2Profile kProfileChrome125 = CreateChrome125Profile();
const ChromeH2Profile kProfileChrome130 = CreateChrome130Profile();
const ChromeH2Profile kProfileChrome131 = CreateChrome131Profile();
const ChromeH2Profile kProfileChrome143 = CreateChrome143Profile();

}  // namespace

const ChromeH2Profile& GetChromeH2Profile(ChromeVersion version) {
  // Note: kLatest == kChrome143, handled by default case
  switch (version) {
    case ChromeVersion::kChrome120:
      return kProfileChrome120;
    case ChromeVersion::kChrome125:
      return kProfileChrome125;
    case ChromeVersion::kChrome130:
      return kProfileChrome130;
    case ChromeVersion::kChrome131:
      return kProfileChrome131;
    default:
      return kProfileChrome143;
  }
}

}  // namespace http2
}  // namespace holytls
