cmake_minimum_required(VERSION 3.12)
project (AlbionSniffer)

add_subdirectory(libpcap)
include_directories(libpcap)
include_directories(include)

set(SOURCE_FILES src/main.cpp
                    src/sniffer.cpp)
add_executable(sniffer ${SOURCE_FILES})

target_link_libraries(sniffer pcap)