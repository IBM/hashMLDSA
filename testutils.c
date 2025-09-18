#include <stdlib.h>
#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "testutils.h"

/* Helpers for hexString <-> byteArray conversions */
/* ----------------------------------------------- */
int hexString2byteArray(const char *hexStr,
                     unsigned char **output,
                     size_t *outputLen)
{
    size_t len = strlen(hexStr);
    size_t finalLen;

    if (len % 2 != 0)
        return -1;

    finalLen = len / 2;
    *outputLen = finalLen;
    *output = (unsigned char*)malloc((finalLen + 1) * sizeof(unsigned char));

    for (size_t inIdx = 0, outIdx = 0; outIdx < finalLen; inIdx += 2, outIdx++) {
        if ((hexStr[inIdx] - 48) <= 9 && (hexStr[inIdx + 1] - 48) <= 9) {
            goto convert;
        } else {
            if (((hexStr[inIdx] - 65) <= 5 && (hexStr[inIdx + 1] - 65) <= 5) || ((hexStr[inIdx] - 97) <= 5 && (hexStr[inIdx + 1] - 97) <= 5)) {
                goto convert;
            } else {
                *outputLen = 0;
                return -1;
            }
        }
    convert:
        (*output)[outIdx] =
            (hexStr[inIdx] % 32 + 9) % 25 * 16 + (hexStr[inIdx + 1] % 32 + 9) % 25;
    }

    (*output)[finalLen] = '\0';
    return 0;
}

char* byteArray2hexString(const unsigned char* data, size_t datalen) {
  size_t final_len = datalen * 2;
  unsigned int j = 0;

  char* chrs = (unsigned char *) malloc((final_len + 1) * sizeof(*chrs));
  for(j = 0; j < datalen; j++) {
    chrs[2*j] = (data[j]>>4)+48;
    chrs[2*j+1] = (data[j]&15)+48;
    if (chrs[2*j]>57) chrs[2*j]+=7;
    if (chrs[2*j+1]>57) chrs[2*j+1]+=7;
  }
  chrs[2*j]='\0';
  return chrs;
}

int generate_key_from_name(const char *alg_name, EVP_PKEY **pkey) {
    EVP_PKEY_CTX *pctx = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (!pctx) {
        fprintf(stderr, "Error creating context for algorithm: %s\n", alg_name);
        goto error;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error initializing keygen for: %s\n", alg_name);
        goto error;
    }

    if (EVP_PKEY_keygen(pctx, pkey) <= 0) {
        fprintf(stderr, "Error generating key for: %s\n", alg_name);
        goto error;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;

error:
    ERR_print_errors_fp(stderr);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    return -1;
}
