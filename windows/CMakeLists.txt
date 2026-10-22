cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "u2f")
project(${PROJECT_NAME} LANGUAGES C CXX)

set(HIDAPI_VERSION "0.15.0" CACHE STRING "Version of hidapi used")
set(HIDAPI_ARCH "x64" CACHE STRING "Architecture of hidapi used")

# Download hidapi
include(../windows/DownloadProject.cmake)
download_project(
  PROJ
  hidapi
  URL
  "https://github.com/libusb/hidapi/archive/refs/tags/hidapi-${HIDAPI_VERSION}.zip"
  )
add_subdirectory(${hidapi_SOURCE_DIR} ${hidapi_BINARY_DIR})

add_library(${PROJECT_NAME} SHARED "authenticate.c" "register.c" "u2f.h")
apply_standard_settings(${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME} PRIVATE WebAuthn)
target_link_libraries(${PROJECT_NAME}
                      PRIVATE flutter flutter_wrapper_plugin hidapi::hidapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
  PUBLIC_HEADER u2f.h
  OUTPUT_NAME "u2f"
  CXX_VISIBILITY_PRESET hidden
  )

target_compile_definitions(${PROJECT_NAME} PUBLIC DART_SHARED_LIB FLUTTER_PLUGIN_IMPL)

set(${PROJECT_NAME}_bundled_libraries $<TARGET_FILE:${PROJECT_NAME}> PARENT_SCOPE)
