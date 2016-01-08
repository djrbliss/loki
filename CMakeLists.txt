#CMakeLists.txt for build loki 

SET(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_C_CONPILER "gcc")
#set(CMAKE_STRIP "strip")
#for arm-androidlinux-eabi 
SET(CMAKE_C_COMPILER "arm-linux-androideabi-gcc")
SET(CMAKE_STIRP "arm-linux-androideabi-strip")

project(loki_tool)
cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "-g -static -Wall")
set(LOKI_SRC loki_find.c 
			loki_flash.c
			loki_patch.c 
			loki_unlok.c
			main.c)

add_executable(loki_tool ${LOKI_SRC})


