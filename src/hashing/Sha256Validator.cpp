#include "hashing/Sha256Validator.hpp"
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

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
