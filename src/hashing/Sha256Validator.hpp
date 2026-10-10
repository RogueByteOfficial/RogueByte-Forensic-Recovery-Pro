/**
 * RogueByte Forensic Recovery Pro (RFRP)
 * SHA-256 Cryptographic Validator using OpenSSL EVP
 * Developer: SidoDev-Dz | Brand: RogueByte
 */

#pragma once
#include <string>
#include <filesystem>
#include <vector>
#include <cstdint>

namespace rfrp::hashing {

class Sha256Validator {
public:
    static std::string calculateFileHash(const std::filesystem::path& path);
    static std::string calculateBufferHash(const uint8_t* data, size_t length);
    static bool verifyIntegrity(const std::filesystem::path& path, const std::string& expectedHex);
};

} // namespace rfrp::hashing
