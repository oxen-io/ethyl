cmake_minimum_required(VERSION 3.15)

#
# Project details
#

verbose_message("Adding tests under ${PROJECT_NAME}tests...")

foreach(file ${test_sources})
    get_filename_component(test_name ${file} NAME_WE)
    add_executable(${test_name}_tests ${file})

    set(${PROJECT_NAME}_TEST_LIB ${PROJECT_NAME})

    target_link_libraries(
      ${test_name}_tests
      PRIVATE
        Catch2::Catch2WithMain
        ethyl
        ${${PROJECT_NAME}_TEST_LIB}
        cncrypto
        cpr::cpr
    )
    target_include_directories(
        ${test_name}_tests
        PRIVATE
        ${PROJECT_SOURCE_DIR}/src
    )

    add_test(
    NAME
      ${test_name}
    COMMAND
      ${test_name}_tests
    )
endforeach()

verbose_message("Finished adding unit tests for ${PROJECT_NAME}.")
