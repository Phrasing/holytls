// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_ERROR_H_
#define HOLYTLS_ERROR_H_

#include <cstdint>
#include <string>

namespace holytls {

enum class ErrorCode : uint8_t {
  kOk = 0,
  kDns,
  kConnection,
  kTls,
  kHttp2,
  kTimeout,
  kCancelled,
  kInvalidUrl,
  kInternal,
};

struct Error {
  ErrorCode code = ErrorCode::kOk;
  std::string message;

  explicit operator bool() const { return code != ErrorCode::kOk; }
};

}  // namespace holytls

#endif  // HOLYTLS_ERROR_H_
