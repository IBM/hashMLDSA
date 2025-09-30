/*
Copyright 2025 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <openssl/evp.h>

typedef struct hashMLDSA_ctx HASHMLDSA_CTX;
typedef struct hashMLDSA HASHMLDSA;

HASHMLDSA_CTX *HASHMLDSA_CTX_new(OSSL_LIB_CTX *lib_ctx, const char* sig_alg);
HASHMLDSA_CTX *HASHMLDSA_CTX_new_for_test(OSSL_LIB_CTX *lib_ctx, const char* sig_alg);
int HASHMLDSA_CTX_set_message_digest(HASHMLDSA_CTX *ctx, const char* digest_name, size_t hash_len);
void HASHMLDSA_CTX_free(HASHMLDSA_CTX *ctx);

HASHMLDSA *HASHMLDSA_new(const HASHMLDSA_CTX *ctx);
int HASHMLDSA_set_context_string(HASHMLDSA *input_data, const unsigned char* context_string, size_t context_string_len);
int HASHMLDSA_set_message(HASHMLDSA *input_data, const unsigned char* message, size_t message_len);
int HASHMLDSA_set_hashed_message(HASHMLDSA *input_data, const unsigned char* hashed_message, size_t hashed_message_len);
int HASHMLDSA_override_message_digest(HASHMLDSA *input_data, const char* digest_name, size_t hash_len);
void HASHMLDSA_free(HASHMLDSA *data);

int HASHMLDSA_print_last_error(FILE *fp);
void HASHMLDSA_clear_last_error();

int HASHMLDSA_generate_hashed_message(const HASHMLDSA_CTX *ctx,
                      const HASHMLDSA *input_data,
                      unsigned char *hashed_message,
                      size_t *hashed_message_len);

int HASHMLDSA_sign(const HASHMLDSA_CTX *ctx,
                   EVP_PKEY *priv_key,
                   const HASHMLDSA *input_data,
                   unsigned char *signature,
                   size_t *signature_len);

int HASHMLDSA_verify(const HASHMLDSA_CTX *ctx,
                     EVP_PKEY *public_key,
                     const HASHMLDSA *input_data,
                     const unsigned char *signature,
                     const size_t signature_len);

