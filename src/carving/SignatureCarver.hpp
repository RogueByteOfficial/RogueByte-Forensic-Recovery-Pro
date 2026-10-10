/**
 * RogueByte Forensic Recovery Pro (RFRP)
 * Signature-Based File Carver Engine
 * Developer: SidoDev-Dz | Brand: RogueByte
 */

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <filesystem>

namespace rfrp::carving {

struct CarvedCandidate {
    std::string id;
    std::string extension;
    uint64_t startOffset;
    uint64_t endOffset;
    uint64_t sizeBytes;
    std::string sha256;
    bool headerValid;
    bool trailerValid;
    std::string validationStatus;
};

class SignatureCarver {
public:
    SignatureCarver() = default;

    std::vector<CarvedCandidate> carveFile(
        const std::filesystem::path& sourcePath,
        const std::filesystem::path& outputDirectory,
        bool sectorAlignedOnly = true,
        uint32_t sectorSize = 512,
        std::function<void(int progressPercent)> progressCallback = nullptr
    );
};

} // namespace rfrp::carving
