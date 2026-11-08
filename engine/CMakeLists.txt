cmake_minimum_required(VERSION 3.10)
project(AegisDPI VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Required for the multi-threaded dpi_engine
find_package(Threads REQUIRED)

# Find libpcap
find_library(PCAP_LIBRARY pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)
include_directories(${PCAP_INCLUDE_DIR})

# Find libnftables
find_library(NFTABLES_LIBRARY nftables REQUIRED)
find_path(NFTABLES_INCLUDE_DIR nftables/libnftables.h REQUIRED)
include_directories(${NFTABLES_INCLUDE_DIR})

include_directories(include)

set(ENGINE_SOURCES
    src/types.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
)

# Fetch redis-plus-plus
include(FetchContent)

FetchContent_Declare(
  redis-plus-plus
  URL https://github.com/sewenew/redis-plus-plus/archive/refs/tags/1.3.12.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(REDIS_PLUS_PLUS_BUILD_TEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(redis-plus-plus)

# Target 1: dpi_simple (Single-threaded)
add_executable(dpi_simple src/dpi_simple.cpp ${ENGINE_SOURCES})
target_link_libraries(dpi_simple ${PCAP_LIBRARY} ${NFTABLES_LIBRARY})

# Target 2: dpi_engine (Multi-threaded)
add_executable(dpi_engine src/dpi_engine.cpp src/reporter.cpp src/rule_subscriber.cpp ${ENGINE_SOURCES})
target_link_libraries(dpi_engine ${PCAP_LIBRARY} Threads::Threads redis++_static hiredis ${NFTABLES_LIBRARY})
set_target_properties(dpi_engine PROPERTIES SKIP_BUILD_RPATH TRUE)

# Target 3: GoogleTest setup via FetchContent
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(dpi_tests tests/dpi_tests.cpp tests/flow_hash_test.cpp tests/queue_test.cpp ${ENGINE_SOURCES})
target_link_libraries(dpi_tests GTest::gtest_main GTest::gtest ${PCAP_LIBRARY} Threads::Threads redis++_static hiredis ${NFTABLES_LIBRARY})

include(GoogleTest)
gtest_discover_tests(dpi_tests)
