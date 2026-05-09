cmake_minimum_required(VERSION 3.22)

project (
  E2EEGroupChat
  VERSION 1.0
  DESCRIPTION "Making groupchat"
  LANGUAGES C
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(include)

file(GLOB SERVER_SOURCES "src/server/*.c")
file(GLOB CLIENT_SOURCES "src/client/*.c")

add_executable(server ${SERVER_SOURCES})
add_executable(client ${CLIENT_SOURCES})

find_package(OpenSSL REQUIRED)
target_link_libraries(client OpenSSL::Crypto)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g")