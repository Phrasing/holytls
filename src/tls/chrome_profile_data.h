// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Optimized Chrome TLS profile data using constexpr fixed arrays.
// Zero heap allocation - all data is compile-time constants.

#ifndef CHAD_TLS_CHROME_PROFILE_DATA_H_
#define CHAD_TLS_CHROME_PROFILE_DATA_H_

#include <cstdint>

#include "chad/config.h"

namespace chad {
namespace tls {

// Maximum sizes for fixed arrays
inline constexpr size_t kMaxCipherSuites = 20;
inline constexpr size_t kMaxSupportedGroups = 8;
inline constexpr size_t kMaxSignatureAlgorithms = 16;
inline constexpr size_t kMaxAlpnProtocols = 4;
inline constexpr size_t kMaxUserAgent = 256;
inline constexpr size_t kMaxVersionString = 16;

// TLS fingerprint profile - fully constexpr, zero heap allocation
struct TlsProfileData {
  ChromeVersion version;

  // Fixed arrays with explicit counts
  uint16_t cipher_suites[kMaxCipherSuites];
  uint8_t cipher_count;

  uint16_t supported_groups[kMaxSupportedGroups];
  uint8_t group_count;

  uint16_t signature_algorithms[kMaxSignatureAlgorithms];
  uint8_t sig_alg_count;

  // Feature flags (packed)
  bool grease_enabled : 1;
  bool permute_extensions : 1;
  bool compress_certificates : 1;
  bool encrypted_client_hello : 1;

  uint16_t record_size_limit;
  uint8_t key_shares_limit;

  // Fixed strings
  char user_agent[kMaxUserAgent];
  char version_string[kMaxVersionString];
};

// Chrome 120 profile data
inline constexpr TlsProfileData kChrome120Data = {
    .version = ChromeVersion::kChrome120,
    .cipher_suites =
        {
            0x1301, 0x1302, 0x1303,                          // TLS 1.3
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,  // ECDHE
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035   // Legacy
        },
    .cipher_count = 15,
    .supported_groups = {0x001d, 0x0017, 0x0018},  // X25519, P-256, P-384
    .group_count = 3,
    .signature_algorithms = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                             0x0806, 0x0601},
    .sig_alg_count = 8,
    .grease_enabled = true,
    .permute_extensions = true,
    .compress_certificates = true,
    .encrypted_client_hello = false,
    .record_size_limit = 16385,
    .key_shares_limit = 2,
    .user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    .version_string = "120.0.0.0",
};

// Chrome 125 profile data
inline constexpr TlsProfileData kChrome125Data = {
    .version = ChromeVersion::kChrome125,
    .cipher_suites = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                      0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
                      0x0035},
    .cipher_count = 15,
    .supported_groups = {0x6399, 0x001d, 0x0017, 0x0018},  // X25519Kyber768
    .group_count = 4,
    .signature_algorithms = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                             0x0806, 0x0601},
    .sig_alg_count = 8,
    .grease_enabled = true,
    .permute_extensions = true,
    .compress_certificates = true,
    .encrypted_client_hello = false,
    .record_size_limit = 16385,
    .key_shares_limit = 2,
    .user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    .version_string = "125.0.0.0",
};

// Chrome 130 profile data
inline constexpr TlsProfileData kChrome130Data = {
    .version = ChromeVersion::kChrome130,
    .cipher_suites = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                      0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
                      0x0035},
    .cipher_count = 15,
    .supported_groups = {0x6399, 0x001d, 0x0017, 0x0018},
    .group_count = 4,
    .signature_algorithms = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                             0x0806, 0x0601},
    .sig_alg_count = 8,
    .grease_enabled = true,
    .permute_extensions = true,
    .compress_certificates = true,
    .encrypted_client_hello = true,
    .record_size_limit = 16385,
    .key_shares_limit = 2,
    .user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    .version_string = "130.0.0.0",
};

// Chrome 131 profile data
inline constexpr TlsProfileData kChrome131Data = {
    .version = ChromeVersion::kChrome131,
    .cipher_suites = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                      0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
                      0x0035},
    .cipher_count = 15,
    .supported_groups = {0x6399, 0x001d, 0x0017, 0x0018},
    .group_count = 4,
    .signature_algorithms = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                             0x0806, 0x0601},
    .sig_alg_count = 8,
    .grease_enabled = true,
    .permute_extensions = true,
    .compress_certificates = true,
    .encrypted_client_hello = true,
    .record_size_limit = 16385,
    .key_shares_limit = 2,
    .user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    .version_string = "131.0.0.0",
};

// Chrome 143 profile data (latest, default)
inline constexpr TlsProfileData kChrome143Data = {
    .version = ChromeVersion::kChrome143,
    .cipher_suites = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                      0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
                      0x0035},
    .cipher_count = 15,
    .supported_groups = {0x11ec, 0x001d, 0x0017, 0x0018},  // X25519MLKEM768
    .group_count = 4,
    .signature_algorithms = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                             0x0806, 0x0601},
    .sig_alg_count = 8,
    .grease_enabled = true,
    .permute_extensions = true,
    .compress_certificates = true,
    .encrypted_client_hello = true,
    .record_size_limit = 16385,
    .key_shares_limit = 2,
    .user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    .version_string = "143.0.0.0",
};

// Fast lookup by version (constexpr)
inline constexpr const TlsProfileData* GetTlsProfileData(
    ChromeVersion version) {
  switch (version) {
    case ChromeVersion::kChrome120:
      return &kChrome120Data;
    case ChromeVersion::kChrome125:
      return &kChrome125Data;
    case ChromeVersion::kChrome130:
      return &kChrome130Data;
    case ChromeVersion::kChrome131:
      return &kChrome131Data;
    default:
      return &kChrome143Data;
  }
}

// Pre-computed cipher string for OpenSSL/BoringSSL
inline constexpr char kCipherString[] =
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

}  // namespace tls
}  // namespace chad

#endif  // CHAD_TLS_CHROME_PROFILE_DATA_H_
