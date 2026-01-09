# Tests CMakeLists.txt

# Unit tests
add_executable(test_reactor
  unit/test_reactor.cc
)
target_include_directories(test_reactor PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_reactor PRIVATE chad-tls)

add_executable(test_buffer_pool
  unit/test_buffer_pool.cc
)
target_include_directories(test_buffer_pool PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_buffer_pool PRIVATE chad-tls)

# Integration tests (require network)
add_executable(test_fingerprint
  integration/test_fingerprint.cc
)
target_include_directories(test_fingerprint PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_fingerprint PRIVATE chad-tls)

add_executable(test_top_websites
  integration/test_top_websites.cc
)
target_include_directories(test_top_websites PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_top_websites PRIVATE chad-tls)

add_executable(test_arena
  unit/test_arena.cc
)
target_include_directories(test_arena PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_arena PRIVATE chad-tls)

add_executable(test_packed_headers
  unit/test_packed_headers.cc
)
target_include_directories(test_packed_headers PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_packed_headers PRIVATE chad-tls)

add_executable(test_chrome_header_builder
  unit/test_chrome_header_builder.cc
)
target_include_directories(test_chrome_header_builder PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_chrome_header_builder PRIVATE chad-tls)

# Register tests
add_test(NAME reactor COMMAND test_reactor)
add_test(NAME buffer_pool COMMAND test_buffer_pool)
add_test(NAME arena COMMAND test_arena)
add_test(NAME packed_headers COMMAND test_packed_headers)
add_test(NAME chrome_header_builder COMMAND test_chrome_header_builder)
add_test(NAME top_websites COMMAND test_top_websites)
