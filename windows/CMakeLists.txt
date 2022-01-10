cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "u2f")
project(${PROJECT_NAME} LANGUAGES C CXX)

add_library(u2f SHARED "authenticate.c" "register.c" "u2f.h")
target_link_libraries(u2f PRIVATE WebAuthn)

set_target_properties(u2f PROPERTIES
  PUBLIC_HEADER u2f.h
  OUTPUT_NAME "u2f"
)

target_compile_definitions(u2f PUBLIC DART_SHARED_LIB)

set(u2f_bundled_libraries $<TARGET_FILE:u2f> PARENT_SCOPE)
