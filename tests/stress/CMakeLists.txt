# Stress test CMakeLists.txt

add_executable(stress_test
  stress_test.cc
)

target_include_directories(stress_test PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(stress_test PRIVATE chad-tls)

# Stress tests are not part of the regular test suite (require network, long-running)
# Run manually with: ./stress_test --url https://example.com --connections 1000
