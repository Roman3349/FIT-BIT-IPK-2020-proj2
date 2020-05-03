cmake_minimum_required(VERSION 3.0)
project(FIT_BIT_IPK_2020_proj2)

set(WARNING_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WARNING_FLAGS} -fPIC -pthread")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(PCAP REQUIRED)

add_executable(ipk-sniffer src/main.cpp)
target_link_libraries(ipk-sniffer ${PCAP_LIBRARIES})