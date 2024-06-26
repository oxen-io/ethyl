# Copyright (c) 2018, The Loki Project
# Copyright (c) 2014-2019, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

add_library(cncrypto
  aesb.c
  blake256.c
  crypto-ops-data.c
  crypto-ops.c
  groestl.c
  hash-extra-blake.c
  hash-extra-groestl.c
  hash-extra-jh.c
  hash-extra-skein.c
  hash.c
  hmac-keccak.c
  jh.c
  keccak.c
  oaes_lib_expand.c
  random.c
  skein.c
  cn_heavy_hash_hard_arm.cpp
  cn_heavy_hash_hard_intel.cpp
  cn_heavy_hash_soft.cpp
  cn_turtle_hash.c
  tree-hash.c)

if (WIN32 OR CYGWIN)
    target_link_libraries(cncrypto PUBLIC bcrypt)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

if (CMAKE_CXX_COMPILER_ID MATCHES Clang OR CMAKE_CXX_COMPILER_ID STREQUAL GNU)
  # If we're compiling for x86/amd64 then we need to force on -maes -msse2 for the hard intel code:
  # it has a run-time check to not actually call it if not supported by the running CPU.
  # Unfortunately CMake sucks for actually reliably giving us the target architecture, so we'll just
  # try to compile with these flags if the compiler accepts them.
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag(-msse2 COMPILER_SUPPORTS_SSE2)
  if(COMPILER_SUPPORTS_SSE2)
    check_cxx_compiler_flag(-maes COMPILER_SUPPORTS_AES)
    if(COMPILER_SUPPORTS_AES)
      set_source_files_properties(cn_heavy_hash_hard_intel.cpp PROPERTIES COMPILE_FLAGS "-maes -msse2")
      set_source_files_properties(cn_monero_slow_hash.c PROPERTIES COMPILE_FLAGS "-maes -msse2")
      set_source_files_properties(cn_turtle_hash.c PROPERTIES COMPILE_FLAGS "-maes -msse2")
    endif()
  endif()
endif()

# GCC 11 LTO and cn_turtle_hash have some serious disagreements; disable LTO for it.
if(IPO_ENABLED AND (CMAKE_BUILD_TYPE STREQUAL Release OR CMAKE_BUILD_TYPE STREQUAL RelWithDebInfo)
    AND CMAKE_C_COMPILER_ID STREQUAL GNU
    AND CMAKE_C_COMPILER_VERSION VERSION_GREATER 11 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 12)
  message(STATUS "GCC-11 detected; disabling LTO for cncrypto")
  set_target_properties(cncrypto PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
endif()


if (ARCH STREQUAL "armv8-a" AND (CMAKE_CXX_COMPILER_ID MATCHES Clang OR CMAKE_CXX_COMPILER_ID STREQUAL GNU))
  # Similarly use +crypto extensions for the arm hash code (it also has a run-time check before
  # enabling).
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag(-march=armv8-a+crypto COMPILER_SUPPORTS_PLUS_CRYPTO)
  if (COMPILER_SUPPORTS_PLUS_CRYPTO)
    set_source_files_properties(cn_heavy_hash_hard_arm.cpp PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
  endif()
endif()


# Because of the way Qt works on android with JNI, the code does not live in the main android thread
# So this code runs with a 1 MB default stack size. 
# This will force the use of the heap for the allocation of the scratchpad
if (ANDROID OR IOS)
  target_compile_definitions(cncrypto PUBLIC FORCE_USE_HEAP=1)
endif()

