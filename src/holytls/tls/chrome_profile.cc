// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/tls/chrome_profile.h"

namespace holytls {
namespace tls {

namespace {

// Chrome 143 profile (latest, default)
ChromeTlsProfile CreateChrome143Profile() {
  ChromeTlsProfile profile;
  profile.version = ChromeVersion::kChrome143;
  profile.version_string = "143.0.0.0";

  profile.cipher_suites = kChrome143CipherSuites;
  profile.supported_groups = kChrome143SupportedGroups;  // X25519MLKEM768
  profile.signature_algorithms = kChrome143SignatureAlgorithms;

  profile.alpn_protocols = {"h2", "http/1.1"};

  profile.grease_enabled = true;
  profile.permute_extensions = true;
  profile.compress_certificates = true;
  profile.encrypted_client_hello = true;

  // Set extension order from real Chrome 143 capture
  profile.extension_order = kChrome143ExtensionOrder;

  profile.record_size_limit = 16385;
  profile.key_shares_limit = 2;

  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

  return profile;
}

// Static profile instances

const ChromeTlsProfile kProfileChrome143 = CreateChrome143Profile();

}  // namespace

const ChromeTlsProfile& GetChromeTlsProfile(ChromeVersion version) {
  // We only support Chrome 143 now
  return kProfileChrome143;
}

// Static cipher suite string (same for all Chrome versions)
// TLS 1.3 ciphers first, then TLS 1.2 ECDHE, then legacy fallbacks
constexpr const char* kChromeCipherString =
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:"
    "ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:"
    "AES128-SHA:"
    "AES256-SHA";

std::string GetCipherSuiteString(ChromeVersion /*version*/) {
  return kChromeCipherString;
}

std::string GetSupportedGroupsString(ChromeVersion version) {
  const auto& profile = GetChromeTlsProfile(version);

  std::string result;
  result.reserve(64);  // Plenty for group names

  for (uint16_t group : profile.supported_groups) {
    if (!result.empty()) result += ':';

    // Map group IDs to OpenSSL/BoringSSL names
    switch (group) {
      case 0x11ec:
        result += "X25519MLKEM768";
        break;
      case 0x6399:
        result += "X25519Kyber768Draft00";
        break;
      case 0x001d:
        result += "X25519";
        break;
      case 0x0017:
        result += "P-256";
        break;
      case 0x0018:
        result += "P-384";
        break;
      default:
        break;
    }
  }

  return result;
}

}  // namespace tls
}  // namespace holytls
