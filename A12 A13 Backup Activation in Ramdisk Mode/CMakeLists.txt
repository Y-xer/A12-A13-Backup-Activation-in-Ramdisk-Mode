cmake_minimum_required(VERSION 3.10)
project(Arm64eVaultEngine VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SSH REQUIRED libssh)
pkg_check_modules(OPENSSL REQUIRED openssl)

add_executable(Arm64eVaultEngine main.cpp)
target_include_directories(Arm64eVaultEngine PRIVATE ${SSH_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(Arm64eVaultEngine PRIVATE ${SSH_LIBRARIES} ${OPENSSL_LIBRARIES})