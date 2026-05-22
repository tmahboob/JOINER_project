cmake_minimum_required(VERSION 3.10)
project(Timings C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Directories
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(EXTERNAL_DIR "${CMAKE_SOURCE_DIR}/external")
set(ENCRYPTION_TIMINGS_DIR "${SRC_DIR}/encryption_timings")

# Common include directories
set(COMMON_INCLUDES
    ${EXTERNAL_DIR}/CycloneCRYPTO
    ${EXTERNAL_DIR}/CycloneCRYPTO/core
    ${EXTERNAL_DIR}/Common
)

# Gather all sources recursively in src/
file(GLOB_RECURSE ALL_SRCS "${SRC_DIR}/*.c")

# Remove target-specific files that will be added separately
list(REMOVE_ITEM ALL_SRCS
    "${SRC_DIR}/mininet_setup/c_switch_handle_S1.c"
    "${SRC_DIR}/mininet_setup/c_switch_handle_S2.c"
    "${SRC_DIR}/rpi/rp.c"       # added manually for rpswitch
    "${SRC_DIR}/rpi/rp_latency.c"  # added manually for goose_latenc.
)

set(ENCRYPTION_SRCS ${ALL_SRCS})

# Define target-specific sources
set(SWITCH_1_SRCS "${SRC_DIR}/mininet_setup/c_switch_handle_S1.c" ${ENCRYPTION_SRCS})
set(SWITCH_2_SRCS "${SRC_DIR}/mininet_setup/c_switch_handle_S2.c" ${ENCRYPTION_SRCS})

# Define CycloneCRYPTO sources
set(CRYPTO_SOURCES
    ${EXTERNAL_DIR}/CycloneCRYPTO/cipher/zuc.c
    ${EXTERNAL_DIR}/CycloneCRYPTO/cipher/sm4.c
    ${EXTERNAL_DIR}/CycloneCRYPTO/cipher_modes/ctr.c
)

#  executables
add_executable(switch1 ${SWITCH_1_SRCS})
add_executable(switch2 ${SWITCH_2_SRCS})
add_executable(rpswitch "${SRC_DIR}/rpi/rp.c")
add_executable(goose_latency "${SRC_DIR}/rpi/rp_latency.c")

# Add encryption timings sources to rpswitch and goose_latency
file(GLOB ENCRYPTION_TIMINGS_SRCS "${ENCRYPTION_TIMINGS_DIR}/*.c")
target_sources(rpswitch PRIVATE ${ENCRYPTION_TIMINGS_SRCS})
target_sources(goose_latency PRIVATE ${ENCRYPTION_TIMINGS_SRCS})

# Link libraries (all targets share the same ones)
foreach(target IN ITEMS switch1 switch2 rpswitch goose_latency)
    target_link_libraries(${target} PRIVATE pcap sodium crypto)
endforeach()

# Add include directories
target_include_directories(switch1 PRIVATE ${COMMON_INCLUDES} ${ENCRYPTION_TIMINGS_DIR})
target_include_directories(switch2 PRIVATE ${COMMON_INCLUDES})
target_include_directories(rpswitch PRIVATE ${COMMON_INCLUDES} ${ENCRYPTION_TIMINGS_DIR})
target_include_directories(goose_latency PRIVATE ${COMMON_INCLUDES} ${ENCRYPTION_TIMINGS_DIR})

# Add common crypto sources to all targets
foreach(target IN ITEMS switch1 switch2 rpswitch goose_latency)
    target_sources(${target} PRIVATE ${CRYPTO_SOURCES})
endforeach()

# Custom target to clean up mac files
add_custom_target(clean_mac_files
    COMMAND find ${CMAKE_SOURCE_DIR} -name "._*" -delete
)
add_custom_target(prebuild ALL DEPENDS clean_mac_files)
