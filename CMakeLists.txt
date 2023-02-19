cmake_minimum_required(VERSION 3.17 FATAL_ERROR)

project(ep VERSION 0.1 LANGUAGES C)

enable_testing()

add_library(ip4ethparser
  include/ip4ethparser.h
  src/ip4ethparser.c
)

# Define headers for this library. PUBLIC headers are used for
# compiling the library, and will be added to consumers' build
# paths.
target_include_directories(ip4ethparser
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(ip4ethparser
    PUBLIC 
    PRIVATE 
)

target_compile_options(ip4ethparser
    PUBLIC 
      
    PRIVATE
      $<$<CXX_COMPILER_ID:MSVC>:/W4>
      $<$<CXX_COMPILER_ID:MSVC>:/MP>
      $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wno-unknown-pragmas -pedantic -pedantic-errors>
)
target_compile_definitions(ip4ethparser
    PRIVATE
        #$<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
        #$<$<CXX_COMPILER_ID:MSVC>:$<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=2>>
        
)

add_executable(ep
    src/main.c
)

target_include_directories(ep
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(ep
    PUBLIC 
    PRIVATE 
        ip4ethparser
)

target_compile_options(ep
    PUBLIC 
      
    PRIVATE
      $<$<CXX_COMPILER_ID:MSVC>:/W4>
      $<$<CXX_COMPILER_ID:MSVC>:/MP>
      $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wno-unknown-pragmas -pedantic -pedantic-errors>
)
target_compile_definitions(ep
    PRIVATE
        #$<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
        #$<$<CXX_COMPILER_ID:MSVC>:$<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=2>>
        
)

add_subdirectory(tests)