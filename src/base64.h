#pragma once

#include <string>
#include <cstdint>
#include <string>
#include <vector>

std::string base64_encode(const uint8_t *data, size_t size);
std::vector<uint8_t> base64_decode(const std::string &str);