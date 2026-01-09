// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_HTTP2_SEC_CH_UA_H_
#define CHAD_HTTP2_SEC_CH_UA_H_

#include <array>
#include <random>
#include <string>
#include <string_view>

namespace chad {
namespace http2 {

// Generates Sec-CH-UA header values following Chrome 143's GREASE algorithm.
//
// Chrome uses "GREASE-like" brands to prevent ecosystem ossification.
// The GREASE brand is generated once at construction and remains stable
// for the lifetime of the generator (simulating a browser session).
//
// Example output:
//   "Not(A:Brand";v="24", "Chromium";v="143", "Google Chrome";v="143"
//
// The GREASE pattern follows Chromium's user_agent_utils.cc:
// - Base template: "Not?A_Brand"
// - Substitute ? and _ with chars from: ( ) : ; = ? _
// - Version: "24" (primary) or "99"
class SecChUaGenerator {
 public:
  // Create generator for specific Chrome major version.
  // GREASE brand and order are generated once and cached.
  explicit SecChUaGenerator(int major_version);

  // Get sec-ch-ua header value (stable per instance)
  const std::string& Get() const { return sec_ch_ua_; }

  // Get sec-ch-ua-mobile header value
  static std::string_view GetMobile(bool is_mobile);

  // Get sec-ch-ua-full-version-list with full version string
  std::string GetFullVersionList(const std::string& full_version) const;

  // Get the generated GREASE brand (for debugging/testing)
  const std::string& grease_brand() const { return grease_brand_; }

  // Get the GREASE version used (24 or 99)
  int grease_version() const { return grease_version_; }

 private:
  // Initialize cached values
  void Initialize();

  // Generate GREASE brand using Chrome's algorithm
  std::string GenerateGreaseBrand();

  // Build the full sec-ch-ua string from brands in cached order
  std::string BuildSecChUa(const std::string& version) const;

  int major_version_;
  std::mt19937 rng_;

  // Cached values (stable per session)
  std::string sec_ch_ua_;           // Pre-generated header value
  std::string grease_brand_;        // e.g., "Not(A:Brand"
  int grease_version_;              // 24 or 99
  std::array<int, 3> brand_order_;  // Permutation indices [0,1,2]
};

// Convenience function to generate sec-ch-ua for Chrome version
// Note: Creates new generator each call, so GREASE varies
std::string GenerateSecChUa(int major_version);

}  // namespace http2
}  // namespace chad

#endif  // CHAD_HTTP2_SEC_CH_UA_H_
