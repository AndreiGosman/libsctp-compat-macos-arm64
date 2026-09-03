# libsctp-compat-macos-arm64
# SPDX-License-Identifier: LGPL-2.1-or-later

cmake_minimum_required(VERSION 3.16)
project(libsctp-compat VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT APPLE)
  message(FATAL_ERROR "libsctp-compat targets macOS. Other systems have SCTP.")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(USRSCTP REQUIRED usrsctp)

add_library(sctp SHARED
  src/registry.c
  src/syscalls.c
  src/sctp_api.c
)

target_include_directories(sctp
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
          $<INSTALL_INTERFACE:include>
  PRIVATE ${USRSCTP_INCLUDE_DIRS}
)

target_link_directories(sctp PRIVATE ${USRSCTP_LIBRARY_DIRS})
target_link_libraries(sctp PRIVATE ${USRSCTP_LIBRARIES})

target_compile_options(sctp PRIVATE -Wall -Wextra -Wno-unused-parameter)

set_target_properties(sctp PROPERTIES
  VERSION       ${PROJECT_VERSION}
  SOVERSION     0
  OUTPUT_NAME   sctp
  MACOSX_RPATH  ON
  INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
  INSTALL_RPATH    "${CMAKE_INSTALL_PREFIX}/lib"
)

configure_file(libsctp.pc.in libsctp.pc @ONLY)
# lksctp-tools ships no pkg-config file, so consumers disagree on the module
# name. srsRAN asks pkg-config for "sctp"; Osmocom asks for "libsctp". Install
# both names so neither needs a patch.
configure_file(libsctp.pc.in sctp.pc @ONLY)

install(TARGETS sctp LIBRARY DESTINATION lib)
install(FILES include/netinet/sctp.h DESTINATION include/netinet)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsctp.pc
              ${CMAKE_CURRENT_BINARY_DIR}/sctp.pc
        DESTINATION lib/pkgconfig)

option(sctp_build_tests "Build the link and loopback tests" ON)
if(sctp_build_tests)
  enable_testing()
  add_executable(sctp_link_test test/sctp_link_test.c)
  target_link_libraries(sctp_link_test PRIVATE sctp)
  add_test(NAME sctp_link_test COMMAND sctp_link_test)

  add_executable(sctp_loopback_test test/sctp_loopback_test.c)
  target_link_libraries(sctp_loopback_test PRIVATE sctp)
  add_test(NAME sctp_loopback_test COMMAND sctp_loopback_test)

  # The header is consumed from C++ by both srsRAN and Osmocom.
  add_executable(sctp_cxx_usage_test test/sctp_cxx_usage_test.cc)
  set_target_properties(sctp_cxx_usage_test PROPERTIES CXX_STANDARD 14)
  target_link_libraries(sctp_cxx_usage_test PRIVATE sctp)
  add_test(NAME sctp_cxx_usage_test COMMAND sctp_cxx_usage_test)
endif()
