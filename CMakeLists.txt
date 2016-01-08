#CMakeLists.txt for build loki 

SET(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_C_CONPILER "gcc")
#set(CMAKE_STRIP "strip")
#for arm-androidlinux-eabi 
SET(CMAKE_FIND_ROOT_PATH "/opt/android-ndk-r9d-arm-linux-androideabi-4.8/sysroot/usr/lib/")
include_directories( "/opt/android-ndk-r9d-arm-linux-androideabi-4.8/sysroot/usr/include/" )
set(CMAKE_C_FLAGS "-I/opt/android-ndk-r9d-arm-linux-androideabi-4.8/sysroot/usr/include/")
set(CMAKE_C_FLAGS "-L/opt/android-ndk-r9d-arm-linux-androideabi-4.8/sysroot/usr/lib/")

SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
SET(CMAKE_C_COMPILER "/opt/android-ndk-r9d-arm-linux-androideabi-4.8/bin/arm-linux-androideabi-gcc")
set(CMAKE_CXX_COMPILER "/opt/android-ndk-r9d-arm-linux-androideabi-4.8/bin/arm-linux-androideabi-g++")
SET(CMAKE_STIRP "/opt/android-ndk-r9d-arm-linux-androideabi-4.8/bin/arm-linux-androideabi-strip")

project(loki_tool)
cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "-g -static -Wall")

set(LOKI_SRC loki_find.c 
			loki_flash.c
			loki_patch.c 
			loki_unlok.c
			main.c)

add_executable(loki_tool ${LOKI_SRC})


