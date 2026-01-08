# Compiler flags following Google C++ Style Guide recommendations

# Common flags for OUR code only (applied via target_compile_options)
set(CHAD_COMMON_FLAGS
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Wformat=2
  -Wshadow
  -Wunused
  -Wimplicit-fallthrough
  -fno-common
)

# GCC-specific flags
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  list(APPEND CHAD_COMMON_FLAGS
    -Wmisleading-indentation
    -Wduplicated-cond
    -Wlogical-op
  )
endif()

# Release flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -mtune=native")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

# Debug flags
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

# RelWithDebInfo
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

# NOTE: We do NOT use add_compile_options() globally because that applies
# to ALL targets including dependencies like nghttp2 and boringssl.
# Instead, flags are applied only to chad-tls targets in CMakeLists.txt.

# Sanitizer support (these are OK to apply globally)
if(CHAD_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

if(CHAD_TSAN)
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
endif()
