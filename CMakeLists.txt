cmake_minimum_required(VERSION 3.4)

project(hsm-service-lib C CXX)
file(GLOB SOURCE src/*.cpp src/*.c src/*.h)
list(FILTER SOURCE EXCLUDE REGEX .*/src/main.cpp)
message(${SOURCE})
add_library(hsm-service-lib STATIC ${SOURCE})
target_include_directories(hsm-service-lib PUBLIC ${OPENSSL_INCLUDE_DIR})

project(hsm-service C CXX)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++17)
file(GLOB SOURCE src/*.cpp src/*.c)

add_executable(hsm-service ${SOURCE} src/main.cpp ext/mongoose/mongoose.c)
target_include_directories(hsm-service PRIVATE ext/mongoose)
target_link_libraries(hsm-service ${OPENSSL_LIBRARIES})
target_link_libraries(hsm-service hsm-service-lib)
target_link_options(hsm-service PRIVATE -static-libgcc -static-libstdc++)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
  unit-test
  test/unit_test.cc
)
target_link_libraries(
  unit-test
  GTest::gtest_main
  hsm-service-lib
  ${OPENSSL_LIBRARIES}
)

include(GoogleTest)
gtest_discover_tests(unit-test)

find_program (BASH_PROGRAM bash)
if (BASH_PROGRAM)
  add_test (blackbox-test ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/test/blackbox_test.sh)
  add_test (server-test ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/test/server_test.sh)
endif (BASH_PROGRAM)