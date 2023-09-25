if(${PROJECT_NAME}_ENABLE_CLANG_TIDY)
  find_program(CLANGTIDY clang-tidy)
  if(CLANGTIDY)
    set(CMAKE_CXX_CLANG_TIDY ${CLANGTIDY} -extra-arg=-Wno-unknown-warning-option)
    message("Clang-Tidy finished setting up.")
  else()
    message(SEND_ERROR "Clang-Tidy requested but executable not found.")
  endif()
endif()

if(${PROJECT_NAME}_ENABLE_CPPCHECK)
  find_program(CPPCHECK cppcheck)
  if(CPPCHECK)
    set(cppcheck_opts --enable=all --inconclusive --inline-suppr --suppressions-list=${PROJECT_SOURCE_DIR}/cmake/CppCheckSuppressions.txt)

    set(cppcheck_dirs_and_files
        ${PROJECT_SOURCE_DIR}/src/
        ${PROJECT_SOURCE_DIR}/include/ethyl/
    )
    set(cppcheck_ignore_dirs
        ${PROJECT_SOURCE_DIR}/src/crypto/
        ${PROJECT_SOURCE_DIR}/external/
    )
    foreach(ignore_dir ${cppcheck_ignore_dirs})
        list(APPEND cppcheck_opts "-i" ${ignore_dir})
    endforeach()
    set(CMAKE_CXX_CPPCHECK ${CPPCHECK} --std=c++17 ${cppcheck_opts} ${cppcheck_dirs_and_files})
    message("Cppcheck finished setting up.")
  else()
    message(SEND_ERROR "Cppcheck requested but executable not found.")
  endif()
endif()
