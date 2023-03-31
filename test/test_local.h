#ifndef WBCRYPTO_TEST_LOCAL_H
#define WBCRYPTO_TEST_LOCAL_H

#include <wbcrypto/conf.h>

//number of test cycle
#define TEST_CYCLE_NUM 10

//Indicates the path to the file to encrypt and decrypt
#define WBCRYPTO_TEST_FIN_PATH "../../testData/test-enc-file.txt"
#define WBCRYPTO_TEST_FENC_PATH "../../testData/test-enc-file.enc.txt"
#define WBCRYPTO_TEST_FDEC_PATH "../../testData/test-enc-file.dec.txt"

//test util
//print string in hexadecimal
void TEST_print_state(unsigned char * in, size_t len);
//compare two values, and return 1 if correct and 0 if error
int TEST_cmp_values(const unsigned char *value1,const unsigned char *value2, int len);

//compare two files, and return 1 if correct and 0 if error
int TEST_cmp_files(char *fpath1,char *fpath2);

int TEST_cmp_handle_files();

#endif //WBCRYPTO_TEST_LOCAL_H
