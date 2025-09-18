#include <stdlib.h>
#include "openssl/ssl.h"

/* mimic the library and openssl definition of success and failure */
#define FAILURE 0
#define SUCCESS 1

int hexString2byteArray(const char *hexStr,
                     unsigned char **output,
                     size_t *outputLen);

char* byteArray2hexString(const unsigned char* data, size_t datalen);

int generate_key_from_name(const char *alg_name, EVP_PKEY **pkey);



