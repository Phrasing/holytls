// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/tls/chrome_profile.h"

#include <sstream>

namespace holytls {
namespace tls {

namespace {

// Chrome 120 profile
ChromeTlsProfile CreateChrome120Profile() {
  ChromeTlsProfile profile;
  profile.version = ChromeVersion::kChrome120;
  profile.version_string = "120.0.0.0";

  profile.cipher_suites = kChrome131CipherSuites;  // Same cipher order
  profile.supported_groups = kChrome120SupportedGroups;
  profile.signature_algorithms = kChrome131SignatureAlgorithms;

  profile.alpn_protocols = {"h2", "http/1.1"};

  profile.grease_enabled = true;
  profile.permute_extensions = true;  // Chrome 110+ has this
  profile.compress_certificates = true;
  profile.encrypted_client_hello = false;

  profile.record_size_limit = 16385;
  profile.key_shares_limit = 2;

  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

  return profile;
}

// Chrome 125 profile
ChromeTlsProfile CreateChrome125Profile() {
  ChromeTlsProfile profile;
  profile.version = ChromeVersion::kChrome125;
  profile.version_string = "125.0.0.0";

  profile.cipher_suites = kChrome131CipherSuites;
  profile.supported_groups = kChrome131SupportedGroups;  // Includes Kyber
  profile.signature_algorithms = kChrome131SignatureAlgorithms;

  profile.alpn_protocols = {"h2", "http/1.1"};

  profile.grease_enabled = true;
  profile.permute_extensions = true;
  profile.compress_certificates = true;
  profile.encrypted_client_hello = false;

  profile.record_size_limit = 16385;
  profile.key_shares_limit = 2;

  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

  return profile;
}

// Chrome 130 profile
ChromeTlsProfile CreateChrome130Profile() {
  ChromeTlsProfile profile;
  profile.version = ChromeVersion::kChrome130;
  profile.version_string = "130.0.0.0";

  profile.cipher_suites = kChrome131CipherSuites;
  profile.supported_groups = kChrome131SupportedGroups;
  profile.signature_algorithms = kChrome131SignatureAlgorithms;

  profile.alpn_protocols = {"h2", "http/1.1"};

  profile.grease_enabled = true;
  profile.permute_extensions = true;
  profile.compress_certificates = true;
  profile.encrypted_client_hello = true;  // ECH enabled

  profile.record_size_limit = 16385;
  profile.key_shares_limit = 2;

  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

  return profile;
}

// Chrome 131 profile
ChromeTlsProfile CreateChrome131Profile() {
  ChromeTlsProfile profile;
  profile.version = ChromeVersion::kChrome131;
  profile.version_string = "131.0.0.0";

  profile.cipher_suites = kChrome131CipherSuites;
  profile.supported_groups = kChrome131SupportedGroups;
  profile.signature_algorithms = kChrome131SignatureAlgorithms;

  profile.alpn_protocols = {"h2", "http/1.1"};

  profile.grease_enabled = true;
  profile.permute_extensions = true;
  profile.compress_certificates = true;
  profile.encrypted_client_hello = true;

  profile.record_size_limit = 16385;
  profile.key_shares_limit = 2;

  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

  return profile;
}

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
const ChromeTlsProfile kProfileChrome120 = CreateChrome120Profile();
const ChromeTlsProfile kProfileChrome125 = CreateChrome125Profile();
const ChromeTlsProfile kProfileChrome130 = CreateChrome130Profile();
const ChromeTlsProfile kProfileChrome131 = CreateChrome131Profile();
const ChromeTlsProfile kProfileChrome143 = CreateChrome143Profile();

}  // namespace

const ChromeTlsProfile& GetChromeTlsProfile(ChromeVersion version) {
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

std::string GetCipherSuiteString(ChromeVersion version) {
  // Get profile to validate version is known (ignoring result for now
  // since all versions use the same cipher string)
  (void)GetChromeTlsProfile(version);

  // Build OpenSSL-style cipher string
  // Note: This maps hex codes to OpenSSL names
  // BoringSSL uses similar naming conventions

  std::ostringstream ss;

  // TLS 1.3 ciphers (use colon separator)
  ss << "TLS_AES_128_GCM_SHA256:";
  ss << "TLS_AES_256_GCM_SHA384:";
  ss << "TLS_CHACHA20_POLY1305_SHA256:";

  // TLS 1.2 ECDHE ciphers
  ss << "ECDHE-ECDSA-AES128-GCM-SHA256:";
  ss << "ECDHE-RSA-AES128-GCM-SHA256:";
  ss << "ECDHE-ECDSA-AES256-GCM-SHA384:";
  ss << "ECDHE-RSA-AES256-GCM-SHA384:";
  ss << "ECDHE-ECDSA-CHACHA20-POLY1305:";
  ss << "ECDHE-RSA-CHACHA20-POLY1305:";

  // Legacy fallbacks
  ss << "ECDHE-RSA-AES128-SHA:";
  ss << "ECDHE-RSA-AES256-SHA:";
  ss << "AES128-GCM-SHA256:";
  ss << "AES256-GCM-SHA384:";
  ss << "AES128-SHA:";
  ss << "AES256-SHA";

  return ss.str();
}

std::string GetSupportedGroupsString(ChromeVersion version) {
  const auto& profile = GetChromeTlsProfile(version);

  std::ostringstream ss;
  bool first = true;

  for (uint16_t group : profile.supported_groups) {
    if (!first) {
      ss << ":";
    }
    first = false;

    // Map group IDs to names
    switch (group) {
      case 0x11ec:
        ss << "X25519MLKEM768";
        break;
      case 0x6399:
        ss << "X25519Kyber768Draft00";
        break;
      case 0x001d:
        ss << "X25519";
        break;
      case 0x0017:
        ss << "P-256";
        break;
      case 0x0018:
        ss << "P-384";
        break;
      default:
        // Unknown group, skip
        first = true;  // Don't add separator for next
        break;
    }
  }

  return ss.str();
}

}  // namespace tls
}  // namespace holytls
