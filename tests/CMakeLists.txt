# Tests CMakeLists.txt

# Unit tests
add_executable(test_reactor
  unit/test_reactor.cc
)
target_include_directories(test_reactor PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_reactor PRIVATE holytls)

add_executable(test_buffer_pool
  unit/test_buffer_pool.cc
)
target_include_directories(test_buffer_pool PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_buffer_pool PRIVATE holytls)

# Integration tests (require network)
add_executable(test_fingerprint
  integration/test_fingerprint.cc
)
target_include_directories(test_fingerprint PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_fingerprint PRIVATE holytls)

add_executable(test_top_websites
  integration/test_top_websites.cc
)
target_include_directories(test_top_websites PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_top_websites PRIVATE holytls)

add_executable(test_arena
  unit/test_arena.cc
)
target_include_directories(test_arena PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_arena PRIVATE holytls)

add_executable(test_packed_headers
  unit/test_packed_headers.cc
)
target_include_directories(test_packed_headers PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_packed_headers PRIVATE holytls)

add_executable(test_chrome_header_builder
  unit/test_chrome_header_builder.cc
)
target_include_directories(test_chrome_header_builder PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_chrome_header_builder PRIVATE holytls)

add_executable(test_socks_proxy
  unit/test_socks_proxy.cc
)
target_include_directories(test_socks_proxy PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_socks_proxy PRIVATE holytls)

add_executable(test_ordered_headers
  unit/test_ordered_headers.cc
)
target_include_directories(test_ordered_headers PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_ordered_headers PRIVATE holytls)

# Register tests
add_test(NAME reactor COMMAND test_reactor)
add_test(NAME buffer_pool COMMAND test_buffer_pool)
add_test(NAME arena COMMAND test_arena)
add_test(NAME packed_headers COMMAND test_packed_headers)
add_test(NAME chrome_header_builder COMMAND test_chrome_header_builder)
add_test(NAME socks_proxy COMMAND test_socks_proxy)
add_test(NAME ordered_headers COMMAND test_ordered_headers)
add_test(NAME top_websites COMMAND test_top_websites)

# Protocol tests (HTTP/1, HTTP/2, HTTP/3)
add_subdirectory(protocol)

# Stress tests (not part of regular test suite)
add_subdirectory(stress)
