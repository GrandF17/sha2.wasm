include(FetchContent)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# 
# 
# 

add_executable(sha2
    sha2_224.test.cpp
    sha2_256.test.cpp
    sha2_384.test.cpp
    sha2_512.test.cpp
    hmac_sha2_224.test.cpp
    hmac_sha2_256.test.cpp
    hmac_sha2_384.test.cpp
    hmac_sha2_512.test.cpp
)

target_link_libraries(sha2
    sha2_core
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME sha2 COMMAND sha2)