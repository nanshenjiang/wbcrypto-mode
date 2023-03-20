#include "test_local.h"

void TEST_print_state(unsigned char * in, size_t len){
    int i;
    for(i = 0; i < len; i++) {
        printf("%.2X ", in[i]);
        if((i+1)%16==0) {
            printf("\n");
        }
    }
    printf("\n");
}

int TEST_cmp_values(const unsigned char *value1,const unsigned char *value2, int len){
    return strncmp(value1, value2, len)==0?1:0;
}

int TEST_cmp_files(char *fpath1,char *fpath2){
    FILE *f1,*f2;
    char ch1,ch2;

    if(((f1=fopen(fpath1,"r"))==0) || ((f2=fopen(fpath2,"r"))==0))
    {
        return 0;
    }
    do
    {
        ch1=fgetc(f1);
        ch2=fgetc(f2);
        if(ch1!=ch2)
        {
            return 0;
        }
    }while(ch1!=EOF || ch2!=EOF);
    fclose(f1);
    fclose(f2);
    return 1;
}

int TEST_cmp_handle_files(){
    int ret = TEST_cmp_files(WBCRYPTO_TEST_FIN_PATH, WBCRYPTO_TEST_FDEC_PATH);
    remove(WBCRYPTO_TEST_FENC_PATH);
    remove(WBCRYPTO_TEST_FDEC_PATH);
    return ret;
}