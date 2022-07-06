cmake_minimum_required(VERSION 3.20)
project(update-digitalocean-firewall LANGUAGES CXX)

set(Boost_NO_BOOST_CMAKE ON)

# set required C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# for Vim + YouCompleteMe;
# after building, create a link to build/compile_commands.json in project dir
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Tell CMake where to find Boost
# set(BOOST_ROOT "/usr/local/boost_1_78_0")

include_directories(${Boost_INCLUDE_DIRS})

find_package(Boost COMPONENTS program_options REQUIRED)

add_library(session SHARED session.h utils.h)
add_executable(update-digitalocean-firewall update-firewall.cpp utils.h)

set_target_properties(session PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(session pthread ssl crypto)

# boost::beast needs ssl and crypto
target_link_libraries(update-digitalocean-firewall Boost::program_options pthread ssl crypto)
