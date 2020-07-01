cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(ALLOW_DOWNLOADING_GOOGLETEST ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories("third_party/SEAL/native/src")

project(SealPIR VERSION 2.1 LANGUAGES CXX)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
add_subdirectory(third_party/SEAL/native/src)


add_executable(main
	main.cpp
)

add_library(sealpir STATIC
  pir.cpp
  pir_client.cpp
  pir_server.cpp
)

target_link_libraries(main sealpir seal)
