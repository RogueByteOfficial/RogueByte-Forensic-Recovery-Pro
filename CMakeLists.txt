cmake_minimum_required(VERSION 3.22)

project(RogueByteForensicRecoveryPro
    VERSION 2.4.0
    DESCRIPTION "RogueByte Forensic Recovery Pro (RFRP) - Native DFIR Suite"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings and security flags
if(MSVC)
    add_compile_options(/W4 /WX- /permissive- /utf-8 /guard:cf)
    add_link_options(/GUARD:CF /DYNAMICBASE /NXCOMPAT)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2)
    add_link_options(-Wl,-z,relro,-z,now)
endif()

# Find Qt 6 Packages
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Widgets Sql)
qt_standard_project_setup()

# SQLite3 & OpenSSL Cryptography for SHA-256
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Core Library
add_library(rfrp_core
    src/core/CaseManager.cpp
    src/carving/SignatureCarver.cpp
    src/carving/SignatureRegistry.cpp
    src/hashing/Sha256Validator.cpp
    src/acquisition/IMemoryAcquisitionProvider.cpp
    src/acquisition/windows/WinPmemProvider.cpp
    src/acquisition/linux/LimeProvider.cpp
    src/memory/VolatilityAdapter.cpp
    src/reporting/ForensicReportGenerator.cpp
)

target_include_directories(rfrp_core PUBLIC
    include/
    src/
)

target_link_libraries(rfrp_core PUBLIC
    Qt6::Core
    Qt6::Sql
    OpenSSL::Crypto
    SQLite::SQLite3
)

# Desktop GUI Executable
add_executable(rfrp_gui
    app/main.cpp
    ui/MainWindow.cpp
    ui/HexViewWidget.cpp
    ui/CarverWidget.cpp
    ui/MemoryWidget.cpp
)

target_link_libraries(rfrp_gui PRIVATE
    rfrp_core
    Qt6::Widgets
    Qt6::Gui
)

# CLI Scriptable Executable
add_executable(rfrp_cli
    app/cli/main_cli.cpp
)

target_link_libraries(rfrp_cli PRIVATE
    rfrp_core
)

# Testing
enable_testing()
add_subdirectory(tests)
