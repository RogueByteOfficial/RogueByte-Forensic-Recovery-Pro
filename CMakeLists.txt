cmake_minimum_required(VERSION 3.22)

project(RogueByteForensicRecoveryPro
    VERSION 2.4.0
    DESCRIPTION "RogueByte Forensic Recovery Pro (RFRP) - Native Digital Forensics Suite"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()

# 1. Cryptography (OpenSSL or Universal Standard C++20 FIPS 180-4 fallback)
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    message(STATUS "[+] Found OpenSSL: using OpenSSL for cryptographic operations")
    add_compile_definitions(RFRP_USE_OPENSSL=1)
    set(CRYPTO_LIBS OpenSSL::Crypto)
else()
    message(STATUS "[+] OpenSSL not found; using embedded zero-dependency FIPS 180-4 standard SHA-256 engine")
    set(CRYPTO_LIBS "")
endif()

# 2. Database (SQLite3 - system, embedded amalgamation, or append-only audit fallback)
find_package(SQLite3 QUIET)
set(SQLITE_SOURCES "")
set(SQLITE_LIBS "")

if(SQLite3_FOUND)
    message(STATUS "[+] Found system SQLite3 library")
    add_compile_definitions(RFRP_HAVE_SQLITE=1)
    set(SQLITE_LIBS SQLite::SQLite3)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite/sqlite3.c")
    message(STATUS "[+] Using embedded SQLite3 amalgamation")
    add_compile_definitions(RFRP_HAVE_SQLITE=1)
    set(SQLITE_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite/sqlite3.c")
else()
    message(STATUS "[*] SQLite3 not found; enabling robust file-based append-only audit logging")
endif()

# Core Library - Absolute source paths ensure resolution across presets and out-of-tree builds
add_library(rfrp_core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hashing/Sha256Validator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/carving/SignatureRegistry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/carving/SignatureCarver.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/CaseManager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/acquisition/windows/WinPmemProvider.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/acquisition/linux/LimeProvider.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/memory/VolatilityAdapter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/reporting/ForensicReportGenerator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/database/CaseDatabase.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/platform/PlatformUtils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/evidence/EvidenceItem.cpp
    ${SQLITE_SOURCES}
)

target_include_directories(rfrp_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite
)

if(CRYPTO_LIBS)
    target_link_libraries(rfrp_core PUBLIC ${CRYPTO_LIBS})
endif()
if(SQLITE_LIBS)
    target_link_libraries(rfrp_core PUBLIC ${SQLITE_LIBS})
endif()

# CLI Application
add_executable(rfrp_cli
    ${CMAKE_CURRENT_SOURCE_DIR}/app/cli/main_cli.cpp
)

target_link_libraries(rfrp_cli PRIVATE
    rfrp_core
)

# Desktop GUI with Qt 6 (when Qt 6 is installed)
find_package(Qt6 COMPONENTS Core Gui Widgets Sql QUIET)
if(Qt6_FOUND)
    qt_standard_project_setup()
    add_executable(rfrp_gui
        ${CMAKE_CURRENT_SOURCE_DIR}/app/main.cpp
    )
    target_link_libraries(rfrp_gui PRIVATE
        rfrp_core
        Qt6::Widgets
        Qt6::Gui
    )
    message(STATUS "[+] Qt 6 found - building desktop GUI (rfrp_gui)")
else()
    message(STATUS "[*] Qt 6 not found in environment - CLI and core engine enabled")
endif()

enable_testing()
add_subdirectory(tests)
