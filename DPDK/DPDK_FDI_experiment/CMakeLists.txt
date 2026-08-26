cmake_minimum_required(VERSION 3.10)
project(Timings C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# =========================================================
# Performance flags
# =========================================================
add_compile_options(-march=native -O3)

# =========================================================
# Directories
# =========================================================
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(EXTERNAL_DIR "${CMAKE_SOURCE_DIR}/external")
set(ENCRYPTION_TIMINGS_DIR "${SRC_DIR}/encryption_timings")

# =========================================================
# Includes
# =========================================================
set(COMMON_INCLUDES
    ${EXTERNAL_DIR}/CycloneCRYPTO
    ${EXTERNAL_DIR}/CycloneCRYPTO/core
    ${EXTERNAL_DIR}/Common
)

# =========================================================
# DPDK
# =========================================================
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

message(STATUS "DPDK include dirs: ${DPDK_INCLUDE_DIRS}")
message(STATUS "DPDK libraries: ${DPDK_LIBRARIES}")

# =========================================================
# Crypto sources (shared everywhere)
# =========================================================
set(CRYPTO_SOURCES
    ${EXTERNAL_DIR}/CycloneCRYPTO/cipher/zuc.c
    ${EXTERNAL_DIR}/CycloneCRYPTO/cipher/sm4.c
    ${EXTERNAL_DIR}/CycloneCRYPTO/cipher_modes/ctr.c
)

# =========================================================
# Encryption + timing sources (shared core)
# =========================================================
file(GLOB ENCRYPTION_TIMINGS_SRCS
    "${ENCRYPTION_TIMINGS_DIR}/*.c"
)

set(CORE_SRCS
    ${ENCRYPTION_TIMINGS_SRCS}
    ${CRYPTO_SOURCES}
)

# =========================================================
# SWITCH SOURCES
# =========================================================
set(SWITCH1_SRCS
    ${SRC_DIR}/mininet_setup/c_switch_handle_S1.c
    ${CORE_SRCS}
)

set(SWITCH2_SRCS
    ${SRC_DIR}/mininet_setup/c_switch_handle_S2.c
    ${CORE_SRCS}
)

# =========================================================
# RPSWITCH SOURCES  (FIXED - THIS WAS YOUR ERROR)
# =========================================================
set(RPSWITCH_SRCS
    ${SRC_DIR}/rpi/rp.c
    ${CORE_SRCS}
)

# =========================================================
# EXECUTABLES
# =========================================================
add_executable(switch1 ${SWITCH1_SRCS})
add_executable(switch2 ${SWITCH2_SRCS})
add_executable(rpswitch ${RPSWITCH_SRCS})
add_executable(goose_latency ${SRC_DIR}/rpi/rp_latency.c ${CORE_SRCS})

# =========================================================
# INCLUDE DIRECTORIES (CRITICAL FIX)
# =========================================================
foreach(target IN ITEMS switch1 switch2 rpswitch goose_latency)
    target_include_directories(${target} PRIVATE
        ${SRC_DIR}
        ${COMMON_INCLUDES}
        ${ENCRYPTION_TIMINGS_DIR}
        ${DPDK_INCLUDE_DIRS}
    )
endforeach()

# =========================================================
# LINK LIBRARIES
# =========================================================
foreach(target IN ITEMS switch1 switch2 rpswitch goose_latency)
    target_link_libraries(${target} PRIVATE
        ${DPDK_LIBRARIES}
        pcap
        sodium
        crypto
    )
endforeach()

# =========================================================
# OPTIONAL CLEAN TARGET
# =========================================================
add_custom_target(clean_mac_files
    COMMAND find ${CMAKE_SOURCE_DIR} -name "._*" -delete
)

add_custom_target(prebuild ALL DEPENDS clean_mac_files)
