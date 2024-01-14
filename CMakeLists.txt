cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(PythonWhiteFin)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(PythonWhiteFin
  packetlog.c
)

target_link_libraries(PythonWhiteFin
  taihenForKernel_stub
  SceIofilemgrForDriver_stub
  SceSdifForDriver_stub
  SceNpDrmForDriver_stub
  SceRtcForDriver_stub
  SceRegMgrForDriver_stub
  SceSblSsMgrForDriver_stub
  SceSysclibForDriver_stub
  SceDebugForDriver_stub
  SceThreadmgrForDriver_stub
)

vita_create_self(PythonWhiteFin.skprx PythonWhiteFin CONFIG exports.yml UNSAFE)