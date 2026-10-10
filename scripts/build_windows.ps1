# RogueByte Forensic Recovery Pro - Windows Build Script
# Developer: SidoDev-Dz | Brand: RogueByte
$ErrorActionPreference = "Stop"

Write-Host "=== Building RogueByte Forensic Recovery Pro (Windows x64) ===" -ForegroundColor Cyan
cmake --preset windows-x64-release
cmake --build --preset windows-build
ctest --preset windows-x64-release --output-on-failure

Write-Host "[+] Windows build and CTest validation completed successfully!" -ForegroundColor Green
