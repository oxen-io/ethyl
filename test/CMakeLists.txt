cmake_minimum_required(VERSION 3.15)

#
# Project details
#

verbose_message("Adding tests under ${CMAKE_PROJECT_NAME}tests...")

foreach(file ${test_sources})
    string(REGEX REPLACE "(.*/)([a-zA-Z0-9_ ]+)(\.cpp)" "\\2" test_name ${file}) 
    add_executable(${test_name}_tests ${file})

    target_compile_features(${test_name}_tests PUBLIC cxx_std_17)


    set(${CMAKE_PROJECT_NAME}_TEST_LIB ${CMAKE_PROJECT_NAME})

    target_link_libraries(
      ${test_name}_tests
      PUBLIC
        Catch2::Catch2WithMain
        ${${CMAKE_PROJECT_NAME}_TEST_LIB}
        cncrypto
    )

    add_test(
    NAME
      ${test_name}
    COMMAND
      ${test_name}_tests
    )
endforeach()

verbose_message("Finished adding unit tests for ${CMAKE_PROJECT_NAME}.")
