// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_HTTP2_CHROME_H2_PROFILE_H_
#define CHAD_HTTP2_CHROME_H2_PROFILE_H_

#include <cstdint>

#include "chad/config.h"

namespace chad {
namespace http2 {

// HTTP/2 SETTINGS parameters matching Chrome's fingerprint.
// These values are sent in the initial SETTINGS frame and are
// a key part of HTTP/2 fingerprinting.
struct ChromeH2Settings {
  uint32_t header_table_size = 65536;  // SETTINGS_HEADER_TABLE_SIZE
  uint32_t enable_push = 0;            // SETTINGS_ENABLE_PUSH (Chrome disables)
  uint32_t max_concurrent_streams = 1000;  // SETTINGS_MAX_CONCURRENT_STREAMS
  uint32_t initial_window_size = 6291456;  // SETTINGS_INITIAL_WINDOW_SIZE (6MB)
  uint32_t max_frame_size = 16384;         // SETTINGS_MAX_FRAME_SIZE
  uint32_t max_header_list_size =
      262144;  // SETTINGS_MAX_HEADER_LIST_SIZE (256KB)

  // Flags for which settings to send (Chrome 143+ doesn't send all)
  bool send_max_concurrent_streams = true;
  bool send_max_frame_size = true;
};

// Chrome HTTP/2 fingerprint profile
struct ChromeH2Profile {
  ChromeVersion version;

  // SETTINGS frame values
  ChromeH2Settings settings;

  // Connection-level WINDOW_UPDATE sent after connection preface
  // Chrome increases to ~15MB: 15663105 + 65535 = 15728640
  uint32_t connection_window_update = 15663105;

  // Pseudo-header ordering
  // Chrome uses: :method, :authority, :scheme, :path (MASP)
  enum class PseudoHeaderOrder {
    kMASP,  // Chrome: method, authority, scheme, path
    kMPAS,  // Firefox: method, path, authority, scheme
    kMSPA,  // Safari: method, scheme, path, authority
  };
  PseudoHeaderOrder pseudo_header_order = PseudoHeaderOrder::kMASP;

  // Whether to send PRIORITY frames (Chrome doesn't in recent versions)
  bool send_priority_frames = false;

  // Priority for the main stream (used if send_priority_frames is true)
  int32_t default_priority_weight = 256;
};

// Get HTTP/2 profile for Chrome version
const ChromeH2Profile& GetChromeH2Profile(ChromeVersion version);

// Chrome 120-131 SETTINGS (sends all 6 settings)
inline constexpr ChromeH2Settings kChrome120H2Settings = {
    .header_table_size = 65536,
    .enable_push = 0,
    .max_concurrent_streams = 1000,
    .initial_window_size = 6291456,
    .max_frame_size = 16384,
    .max_header_list_size = 262144,
    .send_max_concurrent_streams = true,
    .send_max_frame_size = true,
};

// Chrome 143+ SETTINGS (sends only 4 settings, omits MAX_CONCURRENT_STREAMS and
// MAX_FRAME_SIZE)
inline constexpr ChromeH2Settings kChrome143H2Settings = {
    .header_table_size = 65536,
    .enable_push = 0,
    .max_concurrent_streams = 1000,  // Not sent, but kept for internal use
    .initial_window_size = 6291456,
    .max_frame_size = 16384,  // Not sent, but kept for internal use
    .max_header_list_size = 262144,
    .send_max_concurrent_streams = false,
    .send_max_frame_size = false,
};

}  // namespace http2
}  // namespace chad

#endif  // CHAD_HTTP2_CHROME_H2_PROFILE_H_
