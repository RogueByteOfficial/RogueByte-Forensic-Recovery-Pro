# Packaging RogueByte Forensic Recovery Pro for Windows x64
$ErrorActionPreference = "Stop"
Write-Host "=== Packaging for Windows x64 ==="
New-Item -ItemType Directory -Force -Path "dist/bin"
Copy-Item "build/rfrp_cli.exe" -Destination "dist/bin/"
Compress-Archive -Path "dist/*" -DestinationPath "rfrp_windows_x64.zip" -Force
Write-Host "[+] Package created: rfrp_windows_x64.zip"
