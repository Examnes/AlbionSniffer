cmake_minimum_required (VERSION 3)
project (AlbionSniffer)

add_subdirectory(libpcap)
include_directories(libpcap/pcap)

set(SOURCE_FILES src/main.cpp)
add_executable(sniffer ${SOURCE_FILES})

target_link_libraries(sniffer libpcap)