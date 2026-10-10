/**
 * RogueByte Forensic Recovery Pro (RFRP)
 * Cryptographic SHA-256 Validator
 * Developer: SidoDev-Dz | Organization: RogueByte
 *
 * Supports OpenSSL when available, and includes a zero-dependency
 * standard FIPS 180-4 C++20 implementation for seamless compilation on
 * Windows (MinGW/MSVC), Linux, and macOS without requiring external OpenSSL.
 */

#include "hashing/Sha256Validator.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <cstring>
#include <cstdint>

#if defined(RFRP_USE_OPENSSL)
#include <openssl/evp.h>

namespace rfrp::hashing {

std::string Sha256Validator::calculateBufferHash(const uint8_t* data, size_t length) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;

    EVP_DigestInit_ex(ctx, md, nullptr);
    if (data && length > 0) {
        EVP_DigestUpdate(ctx, data, length);
    }
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string Sha256Validator::calculateFileHash(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    while (file.read(buffer.data(), BUFFER_SIZE)) {
        EVP_DigestUpdate(ctx, buffer.data(), file.gcount());
    }
    if (file.gcount() > 0) {
        EVP_DigestUpdate(ctx, buffer.data(), file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

bool Sha256Validator::verifyFileHash(const std::filesystem::path& path, const std::string& expectedHex) {
    std::string actual = calculateFileHash(path);
    std::string expClean = expectedHex;
    std::transform(actual.begin(), actual.end(), actual.begin(), ::tolower);
    std::transform(expClean.begin(), expClean.end(), expClean.begin(), ::tolower);
    return !actual.empty() && actual == expClean;
}

bool Sha256Validator::verifyBufferHash(const uint8_t* data, size_t length, const std::string& expectedHex) {
    std::string actual = calculateBufferHash(data, length);
    std::string expClean = expectedHex;
    std::transform(actual.begin(), actual.end(), actual.begin(), ::tolower);
    std::transform(expClean.begin(), expClean.end(), expClean.begin(), ::tolower);
    return actual == expClean;
}

} // namespace rfrp::hashing

#else
// Universal Standard FIPS 180-4 Compliant Pure C++20 SHA-256 Engine
// Requires ZERO external dependencies (no OpenSSL, works out-of-the-box on MinGW, MSVC, Clang, GCC)
namespace {
    inline uint32_t ror(uint32_t val, uint32_t bits) { return (val >> bits) | (val << (32 - bits)); }
    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32_t ep0(uint32_t x) { return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22); }
    inline uint32_t ep1(uint32_t x) { return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25); }
    inline uint32_t sig0(uint32_t x) { return ror(x, 7) ^ ror(x, 18) ^ (x >> 3); }
    inline uint32_t sig1(uint32_t x) { return ror(x, 17) ^ ror(x, 19) ^ (x >> 10); }

    const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    struct Sha256Engine {
        uint64_t bitlen = 0;
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        uint8_t buffer[64];
        size_t datalen = 0;

        void transform(const uint8_t data[]) {
            uint32_t m[64];
            for (int i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = (static_cast<uint32_t>(data[j]) << 24) |
                       (static_cast<uint32_t>(data[j + 1]) << 16) |
                       (static_cast<uint32_t>(data[j + 2]) << 8) |
                       (static_cast<uint32_t>(data[j + 3]));
            for (int i = 16; i < 64; ++i)
                m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];

            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h + ep1(e) + ch(e, f, g) + K[i] + m[i];
                uint32_t t2 = ep0(a) + maj(a, b, c);
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }

            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }

        void update(const uint8_t* data, size_t len) {
            for (size_t i = 0; i < len; ++i) {
                buffer[datalen] = data[i];
                datalen++;
                if (datalen == 64) {
                    transform(buffer);
                    bitlen += 512;
                    datalen = 0;
                }
            }
        }

        std::string finalize() {
            size_t i = datalen;
            if (datalen < 56) {
                buffer[i++] = 0x80;
                while (i < 56) buffer[i++] = 0x00;
            } else {
                buffer[i++] = 0x80;
                while (i < 64) buffer[i++] = 0x00;
                transform(buffer);
                std::memset(buffer, 0, 56);
            }
            bitlen += datalen * 8;
            for (int j = 7; j >= 0; --j) {
                buffer[63 - j] = static_cast<uint8_t>((bitlen >> (j * 8)) & 0xFF);
            }
            transform(buffer);

            std::ostringstream oss;
            for (int j = 0; j < 8; ++j) {
                oss << std::hex << std::setw(8) << std::setfill('0') << state[j];
            }
            return oss.str();
        }
    };
}

namespace rfrp::hashing {

std::string Sha256Validator::calculateBufferHash(const uint8_t* data, size_t length) {
    Sha256Engine engine;
    if (data && length > 0) {
        engine.update(data, length);
    }
    return engine.finalize();
}

std::string Sha256Validator::calculateFileHash(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";

    Sha256Engine engine;
    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<char> buffer(BUFFER_SIZE);

    while (file.read(buffer.data(), BUFFER_SIZE)) {
        engine.update(reinterpret_cast<const uint8_t*>(buffer.data()), file.gcount());
    }
    if (file.gcount() > 0) {
        engine.update(reinterpret_cast<const uint8_t*>(buffer.data()), file.gcount());
    }
    return engine.finalize();
}

bool Sha256Validator::verifyFileHash(const std::filesystem::path& path, const std::string& expectedHex) {
    std::string actual = calculateFileHash(path);
    std::string expClean = expectedHex;
    std::transform(actual.begin(), actual.end(), actual.begin(), ::tolower);
    std::transform(expClean.begin(), expClean.end(), expClean.begin(), ::tolower);
    return !actual.empty() && actual == expClean;
}

bool Sha256Validator::verifyBufferHash(const uint8_t* data, size_t length, const std::string& expectedHex) {
    std::string actual = calculateBufferHash(data, length);
    std::string expClean = expectedHex;
    std::transform(actual.begin(), actual.end(), actual.begin(), ::tolower);
    std::transform(expClean.begin(), expClean.end(), expClean.begin(), ::tolower);
    return actual == expClean;
}

} // namespace rfrp::hashing

#endif
