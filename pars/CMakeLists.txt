cmake_minimum_required(VERSION 3.20)
project(pars VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# luxcrypto library path
set(LUXCRYPTO_ROOT "/Users/z/work/luxcpp/crypto")
set(LUXCRYPTO_BUILD "${LUXCRYPTO_ROOT}/build-local")
set(LUXCRYPTO_INCLUDE "${LUXCRYPTO_ROOT}/include")

# Find luxcrypto library
find_library(LUXCRYPTO_LIB
    NAMES luxcrypto
    PATHS "${LUXCRYPTO_BUILD}"
    NO_DEFAULT_PATH
    REQUIRED
)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(OXENMQ REQUIRED liboxenmq)
find_package(nlohmann_json REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Source files
set(PARS_SOURCES
    daemon/parsd.cpp
    rpc/lux_rpc.cpp
    crypto/lux_crypto_adapter.cpp
)

# parsd executable
add_executable(parsd ${PARS_SOURCES})

target_include_directories(parsd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LUXCRYPTO_INCLUDE}
    ${OXENMQ_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(parsd PRIVATE
    ${LUXCRYPTO_LIB}
    ${OXENMQ_LIBRARIES}
    nlohmann_json::nlohmann_json
    ${SODIUM_LIBRARIES}
)

target_link_directories(parsd PRIVATE
    ${OXENMQ_LIBRARY_DIRS}
    ${SODIUM_LIBRARY_DIRS}
)

# macOS Metal frameworks
if(APPLE)
    target_link_libraries(parsd PRIVATE
        "-framework Metal"
        "-framework Foundation"
    )
endif()

# Compiler warnings
target_compile_options(parsd PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# Install rules
include(GNUInstallDirs)

install(TARGETS parsd
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
