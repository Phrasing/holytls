// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/sec_ch_ua.h"

#include <algorithm>

namespace holytls {
namespace http2 {

namespace {

// Chrome's GREASE characters for brand name substitution.
// These are the "messy" chars that break naive parsers.
// From Chromium's user_agent_utils.cc
constexpr std::array<char, 7> kGreaseChars = {'(', ')', ':', ';',
                                              '=', '?', '_'};

// Chrome 143 primarily uses version "24" for GREASE, with "99" as alternate
constexpr int kPrimaryGreaseVersion = 24;
constexpr int kAlternateGreaseVersion = 99;

// Probability of using primary version (80%)
constexpr int kPrimaryVersionWeight = 80;

}  // namespace

SecChUaGenerator::SecChUaGenerator(int major_version)
    : major_version_(major_version),
      rng_(std::random_device{}()),
      grease_version_(0) {
  Initialize();
}

void SecChUaGenerator::Initialize() {
  // Generate GREASE brand (stable for this instance)
  grease_brand_ = GenerateGreaseBrand();

  // Select GREASE version: 80% chance of "24", 20% chance of "99"
  std::uniform_int_distribution<int> version_dist(1, 100);
  grease_version_ = (version_dist(rng_) <= kPrimaryVersionWeight)
                        ? kPrimaryGreaseVersion
                        : kAlternateGreaseVersion;

  // Initialize brand order as [0, 1, 2] and shuffle once
  // 0 = GREASE, 1 = Chromium, 2 = Google Chrome
  brand_order_ = {0, 1, 2};
  std::shuffle(brand_order_.begin(), brand_order_.end(), rng_);

  // Build and cache the sec-ch-ua string
  sec_ch_ua_ = BuildSecChUa(std::to_string(major_version_));
}

std::string SecChUaGenerator::GenerateGreaseBrand() {
  // Chrome's GREASE pattern: "Not?A_Brand" with ? and _ substituted
  // We pick two random chars from kGreaseChars for the substitutions

  std::uniform_int_distribution<size_t> char_dist(0, kGreaseChars.size() - 1);

  char first_char = kGreaseChars[char_dist(rng_)];
  char second_char = kGreaseChars[char_dist(rng_)];

  // Build: "Not<c1>A<c2>Brand"
  std::string brand;
  brand.reserve(12);
  brand += "Not";
  brand += first_char;
  brand += 'A';
  brand += second_char;
  brand += "Brand";

  return brand;
}

std::string SecChUaGenerator::BuildSecChUa(const std::string& version) const {
  // Build the three brand entries
  std::string grease_entry =
      "\"" + grease_brand_ + "\";v=\"" + std::to_string(grease_version_) + "\"";
  std::string chromium_entry = "\"Chromium\";v=\"" + version + "\"";
  std::string chrome_entry = "\"Google Chrome\";v=\"" + version + "\"";

  // Arrange in cached order
  std::array<std::string, 3> brands;
  for (int i = 0; i < 3; ++i) {
    switch (brand_order_[static_cast<size_t>(i)]) {
      case 0:
        brands[static_cast<size_t>(i)] = grease_entry;
        break;
      case 1:
        brands[static_cast<size_t>(i)] = chromium_entry;
        break;
      case 2:
        brands[static_cast<size_t>(i)] = chrome_entry;
        break;
    }
  }

  // Join with ", "
  return brands[0] + ", " + brands[1] + ", " + brands[2];
}

std::string_view SecChUaGenerator::GetMobile(bool is_mobile) {
  return is_mobile ? "?1" : "?0";
}

std::string SecChUaGenerator::GetFullVersionList(
    const std::string& full_version) const {
  // Same structure as sec-ch-ua but with full version string
  return BuildSecChUa(full_version);
}

std::string GenerateSecChUa(int major_version) {
  SecChUaGenerator generator(major_version);
  return generator.Get();
}

}  // namespace http2
}  // namespace holytls
