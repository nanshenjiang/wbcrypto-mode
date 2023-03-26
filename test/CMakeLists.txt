message(STATUS "${PROJECT_NAME} TEST ON")

set(TEST_BUILD_NAME aes_test)
add_executable(${TEST_BUILD_NAME} aes_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME wbaes_test)
add_executable(${TEST_BUILD_NAME} wbaes_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME wbaes_wbgcm_ee_test)
add_executable(${TEST_BUILD_NAME} wbaes_wbgcm_ee_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME wbaes_wbgcm_mask_test)
add_executable(${TEST_BUILD_NAME} wbaes_wbgcm_mask_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME sm3_test)
add_executable(${TEST_BUILD_NAME} sm3_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME sm4_test)
add_executable(${TEST_BUILD_NAME} sm4_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME wbsm4_test)
add_executable(${TEST_BUILD_NAME} wbsm4_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME fpe_test)
add_executable(${TEST_BUILD_NAME} fpe_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME fpe_app_test)
add_executable(${TEST_BUILD_NAME} fpe_app_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME perform_wbaes_test)
add_executable(${TEST_BUILD_NAME} perform_wbaes_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm -fopenmp)

set(TEST_BUILD_NAME file_encrypt_test)
add_executable(${TEST_BUILD_NAME} file_encrypt_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME perform_file_enc_test)
add_executable(${TEST_BUILD_NAME} perform_file_enc_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)