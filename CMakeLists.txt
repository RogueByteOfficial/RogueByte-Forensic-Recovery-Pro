cmake_minimum_required(VERSION 3.22)

project(RogueByteForensicRecoveryPro
    VERSION 2.4.0
    DESCRIPTION "RogueByte Forensic Recovery Pro (RFRP) - Native Digital Forensics Suite"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Core Library
add_library(rfrp_core
    src/hashing/Sha256Validator.cpp
    src/carving/SignatureRegistry.cpp
    src/carving/SignatureCarver.cpp
    src/core/CaseManager.cpp
    src/acquisition/windows/WinPmemProvider.cpp
    src/acquisition/linux/LimeProvider.cpp
    src/memory/VolatilityAdapter.cpp
    src/reporting/ForensicReportGenerator.cpp
    src/database/CaseDatabase.cpp
    src/platform/PlatformUtils.cpp
    src/evidence/EvidenceItem.cpp
)

target_include_directories(rfrp_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(rfrp_core PUBLIC
    OpenSSL::Crypto
    SQLite::SQLite3
)

# CLI Application
add_executable(rfrp_cli
    app/cli/main_cli.cpp
)

target_link_libraries(rfrp_cli PRIVATE
    rfrp_core
)

# Desktop GUI with Qt 6 (when Qt 6 is installed)
find_package(Qt6 COMPONENTS Core Gui Widgets Sql QUIET)
if(Qt6_FOUND)
    qt_standard_project_setup()
    add_executable(rfrp_gui
        app/main.cpp
    )
    target_link_libraries(rfrp_gui PRIVATE
        rfrp_core
        Qt6::Widgets
        Qt6::Gui
    )
    message(STATUS "[+] Qt 6 found - building desktop GUI (rfrp_gui)")
else()
    message(STATUS "[*] Qt 6 not present in environment - CLI and core engine enabled")
endif()

enable_testing()
add_subdirectory(tests)
