# Protocol tests CMakeLists.txt

# Mock server library
add_library(mock_server STATIC
  mock_server.cc
)
target_include_directories(mock_server PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(mock_server PRIVATE holytls)

# HTTP/1 protocol tests
add_executable(test_http1
  test_http1.cc
)
target_include_directories(test_http1 PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_http1 PRIVATE holytls mock_server)
add_test(NAME http1_protocol COMMAND test_http1)

# HTTP/2 protocol tests
add_executable(test_http2
  test_http2.cc
)
target_include_directories(test_http2 PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_http2 PRIVATE holytls mock_server)
add_test(NAME http2_protocol COMMAND test_http2)

# HTTP/3 protocol tests (only if QUIC is enabled)
if(HOLYTLS_BUILD_QUIC)
  add_executable(test_http3
    test_http3.cc
  )
  target_include_directories(test_http3 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${ngtcp2_SOURCE_DIR}/lib/includes
    ${ngtcp2_SOURCE_DIR}/crypto/includes
    ${ngtcp2_BINARY_DIR}/lib/includes
    ${nghttp3_SOURCE_DIR}/lib/includes
    ${nghttp3_BINARY_DIR}/lib/includes
  )
  target_link_libraries(test_http3 PRIVATE holytls mock_server)
  add_test(NAME http3_protocol COMMAND test_http3)
endif()
