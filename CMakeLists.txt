#CMakeLists.txt for build loki 

SET(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_C_CONPILER "gcc")
#set(CMAKE_STRIP "strip")
#for arm-androidlinux-eabi 
set(NDK_PATH /opt/android-ndk-r9d-arm-linux-androideabi-4.8)

SET(NDK_PATH_SYSROOT ${NDK_PATH}/sysroot/usr)
SET(NDK_PATH_BIN ${NDK_PATH}/bin)

SET(CMAKE_FIND_ROOT_PATH ${NDK_PATH_SYSROOT}/lib/)
include_directories( ${NDK_PATH_SYSROOT}/include/)
set(CMAKE_C_FLAGS "-I${NDK_PATH_SYSROOT}/include/")
set(CMAKE_C_FLAGS "-L${NDK_PATH_SYSROOT}/lib/")

SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET(CMAKE_C_COMPILER ${NDK_PATH_BIN}/arm-linux-androideabi-gcc)
set(CMAKE_CXX_COMPILER ${NDK_PATH_BIN}/arm-linux-androideabi-g++)
SET(CMAKE_STIRP ${NDK_PATH_BIN}/arm-linux-androideabi-strip)

project(loki_tool)
cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "-g -static -Wall")

set(LOKI_SRC loki_find.c 
			loki_flash.c
			loki_patch.c 
			loki_unlok.c
			main.c)

add_executable(loki_tool ${LOKI_SRC})

