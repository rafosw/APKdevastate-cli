cmake_minimum_required(VERSION 3.16)
project(apkdevastate VERSION 1.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Output directory ──────────────────────────────────────────────────────────
# Binary goes directly into the project root folder.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

# ── Find required packages ────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBZIP REQUIRED libzip)

# nlohmann/json – header-only, shipped in include/
# If the system provides it:  find_package(nlohmann_json QUIET)
# Otherwise we fall back to the vendored header.
find_package(nlohmann_json QUIET)

# ── Source files ──────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/analyzer.cpp
    src/hasher.cpp
    src/permissions.cpp
    src/rat_scanner.cpp
    src/cert_checker.cpp
    src/native_libs.cpp
    src/dynamic_loaders.cpp
    src/process_runner.cpp
    src/apk_extractor.cpp
    src/trusted_orgs.cpp
    src/terminal.cpp
)

add_executable(apkdevastate ${SOURCES})

# ── Include dirs ──────────────────────────────────────────────────────────────
target_include_directories(apkdevastate PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${LIBZIP_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# ── Link libraries ────────────────────────────────────────────────────────────
target_link_libraries(apkdevastate PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LIBZIP_LIBRARIES}
)

if(nlohmann_json_FOUND)
    target_link_libraries(apkdevastate PRIVATE nlohmann_json::nlohmann_json)
endif()

# ── Compile flags ─────────────────────────────────────────────────────────────
target_compile_options(apkdevastate PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-O2>
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS apkdevastate DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/resources/
        DESTINATION share/apkdevastate
        FILES_MATCHING PATTERN "*.json")

# ── Print summary ─────────────────────────────────────────────────────────────
message(STATUS "APKdevastate ${PROJECT_VERSION} – C++17 CLI")
message(STATUS "  OpenSSL:  ${OPENSSL_VERSION}")
message(STATUS "  libzip:   ${LIBZIP_VERSION}")
