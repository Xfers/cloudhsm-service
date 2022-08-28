cmake_minimum_required(VERSION 3.4)

project(hsm-service C CXX)

find_package(OpenSSL REQUIRED)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++17)
file(GLOB SOURCE src/*.cpp src/*.c)

add_executable(hsm-service ${SOURCE} ext/mongoose-7.7/mongoose.c)
target_include_directories(hsm-service PRIVATE ext/mongoose-7.7)
target_link_libraries(hsm-service ${OPENSSL_LIBRARIES})
target_link_options(hsm-service PRIVATE -static-libgcc -static-libstdc++)