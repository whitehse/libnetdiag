cmake_minimum_required(VERSION 3.20)
project(libnetdiag LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(netdiag STATIC
    src/netdiag.c
    src/ping.c
    src/arping.c
    src/traceroute.c
    src/dnsdiag.c
    src/arprecon.c
    src/nfct.c
    src/nl80211_parse.c
)

target_include_directories(netdiag PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

include(GNUInstallDirs)
install(TARGETS netdiag EXPORT netdiag-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT netdiag-targets FILE netdiag-config.cmake NAMESPACE netdiag:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/netdiag)

enable_testing()

add_executable(netdiag_smoke_test tests/test_smoke.c)
target_link_libraries(netdiag_smoke_test PRIVATE netdiag)
add_test(NAME netdiag_smoke COMMAND netdiag_smoke_test)

add_executable(netdiag_dialectic_ping_test tests/test_dialectic_ping.c)
target_link_libraries(netdiag_dialectic_ping_test PRIVATE netdiag)
add_test(NAME netdiag_dialectic_ping COMMAND netdiag_dialectic_ping_test)

add_executable(netdiag_dialectic_arping_test tests/test_dialectic_arping.c)
target_link_libraries(netdiag_dialectic_arping_test PRIVATE netdiag)
add_test(NAME netdiag_dialectic_arping COMMAND netdiag_dialectic_arping_test)

add_executable(netdiag_dialectic_traceroute_test tests/test_dialectic_traceroute.c)
target_link_libraries(netdiag_dialectic_traceroute_test PRIVATE netdiag)
add_test(NAME netdiag_dialectic_traceroute COMMAND netdiag_dialectic_traceroute_test)

add_executable(netdiag_dialectic_dnsdiag_test tests/test_dialectic_dnsdiag.c)
target_link_libraries(netdiag_dialectic_dnsdiag_test PRIVATE netdiag)
add_test(NAME netdiag_dialectic_dnsdiag COMMAND netdiag_dialectic_dnsdiag_test)

add_executable(netdiag_nfct_cta_test tests/test_nfct_cta.c)
target_link_libraries(netdiag_nfct_cta_test PRIVATE netdiag)
add_test(NAME netdiag_nfct_cta COMMAND netdiag_nfct_cta_test)

# Examples (optional, for future liburing/epoll harnesses)
option(BUILD_EXAMPLES "Build example programs" OFF)
if(BUILD_EXAMPLES)
  # Placeholder for future examples; currently none to keep bootstrap minimal
endif()