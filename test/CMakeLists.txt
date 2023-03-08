message(STATUS "${PROJECT_NAME} TEST ON")

set(TEST_BUILD_NAME fpe_test)
add_executable(${TEST_BUILD_NAME} fpe_test.c test_utils.c)
if(IMPORT_OPENSSL)
    TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)
else()
    TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lm)
endif()