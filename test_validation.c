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

#include <stdio.h>
#include <stdlib.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "hashMLDSA.h"
#include "testutils.h"

typedef int (*perform_function)(unsigned char* x, size_t y);

static const unsigned char *encoded_valid_hashed_msg = "0167EE0B3F679FB50F59AD31328AAF4E702CCF6092DA4794DCF07C8EA278B34228A41561C369271AFDD26159DCF071223BB5D7B789270150C5B17467829C8871B28A21A3ADEA0347E35987932A0C465157FF2B2AE966CD4A48C24CC7B10B7484658C652241C82266DF060960864801650304020180F2BFF501F94ABB1B8530F1EA78EE7D595F762E2C026847833EA1D067EBB65F";
static const size_t encoded_valid_hashed_msg_len = 148;
static const char* valid_hash_msg_digest = "SHA2-256";
static const char* notapplicable_hash_msg_digest = "SHA3-512";
static const char* valid_sig_alg = "ML-DSA-44";
static const char* notapplicable_sig_alg = "ML-DSA-65";
static const char* notvalid_sig_alg = "ED25519";

/*
 * Perform a verify given a hashed message, setting the digest on the context
 */
static int perform_verify(unsigned char* hashed_msg, size_t hashed_msg_len)
{
    int rc = SUCCESS;
    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *input_data = NULL;
    EVP_PKEY *valid_pkey = NULL; /* Will hold the key used to verify */

    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_hashed_message(input_data, hashed_msg, hashed_msg_len);
    if (generate_key_from_name(valid_sig_alg, &valid_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", valid_sig_alg);
        rc = FAILURE;
        goto exit;
    }

    rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, input_data, "Signature", 9);

exit:
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_free(input_data);
    EVP_PKEY_free(valid_pkey);

    return rc;
}

/*
 * sign a pre-hashed message, setting the digest on the context
 */
static int perform_sign(unsigned char* hashed_msg, size_t hashed_msg_len)
{
    int rc = SUCCESS;
    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *input_data = NULL;
    EVP_PKEY *valid_pkey = NULL; /* Will hold the private key used to sign */
    unsigned char blank_buffer[10000];
    size_t signature_len =  10000;

    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_hashed_message(input_data, hashed_msg, hashed_msg_len);
    if (generate_key_from_name(valid_sig_alg, &valid_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", valid_sig_alg);
        rc = FAILURE;
        goto exit;
    }

    rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, input_data, blank_buffer, &signature_len);

exit:
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_free(input_data);
    EVP_PKEY_free(valid_pkey);

    return rc;
}

/* check the return code to ensure that an error was received */
static void check_rc(int rc, const unsigned char* action, unsigned int *testcount, const unsigned char* description, unsigned int *passes, unsigned int *failures) {
    printf("%s Test %d: \"%s\"\n", action, *testcount, description);
    if (rc == FAILURE) {
        HASHMLDSA_print_last_error(stdout);
        HASHMLDSA_clear_last_error();
        printf("%s Test %d: [SUCCESS] resulted in an expected error\n", action, *testcount);
        (*passes)++;
    } else if (rc == SUCCESS) {
        printf("%s Test %d: [FAILURE] did not result in a failure\n", action, *testcount);
        (*failures)++;
    } else {
        printf("%s Test %d: [SUCCESS] did NOT result in a failure\n", action, *testcount);
        (*passes)++;
    }
    (*testcount)++;
    printf("\n");
}

/*
 * Here we test the validity of the hashed message using Sign or Verify API
 */
int test_hash_msg_validity_sign_or_verify(perform_function sign_or_verify, unsigned char* action, int *passes, unsigned int *failures, unsigned int* testcount)
{

    unsigned char* test_hashed_msg = NULL;
    size_t len = 0;

    /* assertion check to make sure we are working with a valid hashed_msg */
    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    if (perform_sign(test_hashed_msg, len) == FAILURE) {
        printf("[FAILED] starting hashed_msg is NOT valid\n");
        free(test_hashed_msg);
        return FAILURE;
    }
    free(test_hashed_msg);

    /*
     * tests
     */
    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    size_t oidstart = 1 + 1 + test_hashed_msg[1];
    test_hashed_msg[0] = 0x02;
    check_rc(sign_or_verify(test_hashed_msg, len), action, testcount, "Check expected incorrect domain identifier", passes, failures);
    free(test_hashed_msg);

    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    test_hashed_msg[1] = 0x60;
    check_rc(sign_or_verify(test_hashed_msg, len), action, testcount, "Check incorrect context length, oid identifier not found", passes, failures);
    free(test_hashed_msg);

    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    test_hashed_msg[oidstart + 1] = 0x0A;  /* alter the length of the OID */
    check_rc(sign_or_verify(test_hashed_msg, len), action, testcount, "Check oid length too long, it won't match the oid used", passes, failures);
    free(test_hashed_msg);

    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    test_hashed_msg[oidstart + 1] = 0x03;  /* alter the length of the OID */
    check_rc(sign_or_verify(test_hashed_msg, len), action, testcount, "Check oid length too short, it won't match the oid used", passes, failures);
    free(test_hashed_msg);

    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    test_hashed_msg[oidstart + 3] = 0x0A;  /* alter the OID itself to something else */
    check_rc(sign_or_verify(test_hashed_msg, len), action, testcount, "Check oid different, it won't match the oid used", passes, failures);
    free(test_hashed_msg);

    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    check_rc(sign_or_verify(test_hashed_msg, len - 2), action, testcount, "Check hash is too short (but still has part of the hash)", passes, failures);
    free(test_hashed_msg);

    /* hash length = 256/8 = 32 */
    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    check_rc(sign_or_verify(test_hashed_msg, len - 32), action, testcount, "Check whole message is too short (no hash at all)", passes, failures);
    free(test_hashed_msg);

    hexString2byteArray(encoded_valid_hashed_msg, &test_hashed_msg, &len);
    check_rc(sign_or_verify(test_hashed_msg, len - 100), action, testcount, "Check whole message is too short (not even got complete oid)", passes, failures);
    free(test_hashed_msg);

    return SUCCESS;
}

static int test_validation_on_context_creation(unsigned int *passes, unsigned int *failures, unsigned int *testcount) {
    HASHMLDSA_CTX *hashmldsa_ctx = NULL;

    /* invalid signature algorithms*/
    hashmldsa_ctx = HASHMLDSA_CTX_new(NULL);
    check_rc(hashmldsa_ctx == NULL ? FAILURE:SUCCESS, "Context creation", testcount, "Check NULL signature algorithm", passes, failures);

    hashmldsa_ctx = HASHMLDSA_CTX_new("");
    check_rc(hashmldsa_ctx == NULL ? FAILURE:SUCCESS, "Context creation", testcount, "Check blank signature algorithm", passes, failures);

    hashmldsa_ctx = HASHMLDSA_CTX_new("Unknown");
    check_rc(hashmldsa_ctx == NULL ? FAILURE:SUCCESS, "Context creation", testcount, "Check unknown signature algorithm", passes, failures);

    hashmldsa_ctx = HASHMLDSA_CTX_new("ED25519");
    check_rc(hashmldsa_ctx == NULL ? FAILURE:SUCCESS, "Context creation", testcount, "Check non MLDSA signature algorithm", passes, failures);

    /* invalid digests */
    hashmldsa_ctx = HASHMLDSA_CTX_new("ML-DSA-87");
    check_rc(HASHMLDSA_CTX_set_message_digest(NULL, "SHA2-512", 0), "Set Digest on Context", testcount, "Check Context is NULL", passes, failures);
    check_rc(HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, NULL, 0), "Set Digest on Context", testcount, "Check NULL digest algorithm", passes, failures);
    check_rc(HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, "", 0), "Set Digest on Context", testcount, "Check Empty digest algorithm", passes, failures);
    check_rc(HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, "unknown", 0), "Set Digest on Context", testcount, "Check Unknown digest algorithm", passes, failures);
    check_rc(HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, "SHA2-256", 0), "Set Digest on Context", testcount, "Check Digest not strong enough", passes, failures);

    HASHMLDSA_CTX_free(hashmldsa_ctx);
    return SUCCESS;
}

static int test_validation_on_data_creation(unsigned int *passes, unsigned int *failures, unsigned int *testcount) {
    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *data = NULL;

    data = HASHMLDSA_new(NULL);
    check_rc(data == NULL ? FAILURE:SUCCESS, "Data creation", testcount, "Null Context", passes, failures);


    hashmldsa_ctx = HASHMLDSA_CTX_new("ML-DSA-87");
    data = HASHMLDSA_new(hashmldsa_ctx);

    /* invalid digests */
    check_rc(HASHMLDSA_override_message_digest(NULL, "SHA2-512", 0), "Set Digest on Data", testcount, "Check Data is NULL", passes, failures);
    check_rc(HASHMLDSA_override_message_digest(data, NULL, 0), "Set Digest on Data", testcount, "Check NULL digest algorithm", passes, failures);
    check_rc(HASHMLDSA_override_message_digest(data, "", 0), "Set Digest on Data", testcount, "Check Empty digest algorithm", passes, failures);
    check_rc(HASHMLDSA_override_message_digest(data, "unknown", 0), "Set Digest on Data", testcount, "Check Unknown digest algorithm", passes, failures);
    check_rc(HASHMLDSA_override_message_digest(data, "SHA2-256", 0), "Set Digest on Data", testcount, "Check Digest not strong enough", passes, failures);

    /* set context string */
    check_rc(HASHMLDSA_set_context_string(NULL, "context1", 8), "Set context string on Data", testcount, "Check Input Data is NULL", passes, failures);
    check_rc(HASHMLDSA_set_context_string(data, "Context", 256), "Set context string on Data", testcount, "Check Context string is too long", passes, failures);

    /* set message */
    check_rc(HASHMLDSA_set_message(NULL, "message", 7), "Set message string on Data", testcount, "Check Input Data is NULL", passes, failures);

    /* set hashed message */
    check_rc(HASHMLDSA_set_hashed_message(NULL, "message", 7), "Set hashed message string on Data", testcount, "Check Input Data is NULL", passes, failures);

    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_free(data);
    return SUCCESS;
}


/*
 * tests validation for signing activities
 */
static int test_validation_on_sign(unsigned int *sign_passes, unsigned int *sign_failures, unsigned int *testcount)
{
    unsigned char* valid_hashed_msg = NULL;
    size_t len = 0;

    int rc = SUCCESS;
    int sign_rc = SUCCESS;

    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *msg_input_data = NULL;
    HASHMLDSA *hashed_msg_input_data = NULL;
    HASHMLDSA *blank_input_data = NULL;

    unsigned char blank_buffer[10000];
    size_t signature_len = 0;

    EVP_PKEY *valid_pkey = NULL;
    EVP_PKEY *notapplicable_pkey = NULL;
    EVP_PKEY *notvalid_pkey = NULL;

    /* generate a valid key */
    if (generate_key_from_name(valid_sig_alg, &valid_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", valid_sig_alg);
        rc = FAILURE;
        goto exit;
    }

    /* create a valid context and input data with a message (not hashed message) */
    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_message(msg_input_data, "Here is a Message of a specific length", 38);
    blank_input_data = HASHMLDSA_new(hashmldsa_ctx);

    /* start of tests */
    sign_rc = HASHMLDSA_sign(NULL, valid_pkey, msg_input_data, NULL, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check for context being NULL", sign_passes, sign_failures);

    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, NULL, msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check for private key being NULL", sign_passes, sign_failures);

    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, NULL, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check for input data being NULL", sign_passes, sign_failures);

    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, msg_input_data, blank_buffer, NULL);
    check_rc(sign_rc, "Sign", testcount, "Check for signature len being NULL", sign_passes, sign_failures);

    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, NULL, NULL, NULL, &signature_len);
    check_rc(sign_rc == SUCCESS ? -100:SUCCESS, "Sign", testcount, "Check get signature length with only context and signature_len is possible", sign_passes, sign_failures);

    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, blank_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check input data has no message or hashed message set", sign_passes, sign_failures);

    /* test the use of a key that isn't compatible with the context */
    if (generate_key_from_name(notapplicable_sig_alg, &notapplicable_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", notapplicable_sig_alg);
        rc = FAILURE;
        goto exit;
    }
    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, notapplicable_pkey, msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check the key cannot be used even though it's MLDSA type", sign_passes, sign_failures);

    if (generate_key_from_name(notvalid_sig_alg, &notvalid_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", notvalid_sig_alg);
        rc = FAILURE;
        goto exit;
    }
    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, notvalid_pkey, msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check the key cannot be used", sign_passes, sign_failures);

    /* tests to check hashed message digest mismatch */
    hashed_msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    hexString2byteArray(encoded_valid_hashed_msg, &valid_hashed_msg, &len);
    HASHMLDSA_set_hashed_message(hashed_msg_input_data, valid_hashed_msg, encoded_valid_hashed_msg_len);
    HASHMLDSA_override_message_digest(hashed_msg_input_data, notapplicable_hash_msg_digest, 0);

    /* the check for hash message isn't reached when getting signature length, so we can't test using NULL here */
    signature_len = 10000;
    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, hashed_msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check Hashed message mismatches with data overridden hash", sign_passes, sign_failures);

    HASHMLDSA_free(hashed_msg_input_data);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, notapplicable_hash_msg_digest, 0);
    hashed_msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_hashed_message(hashed_msg_input_data, valid_hashed_msg, encoded_valid_hashed_msg_len);
    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, hashed_msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check Hashed message mismatches with context defined hash", sign_passes, sign_failures);

    /* test to check that data came from a matching context */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = HASHMLDSA_CTX_new(notapplicable_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc, "Sign", testcount, "Check Context and Data Mismatch", sign_passes, sign_failures);

    /*
     * test that data can be used with a matching context, and as the previous one has been freed
     * It also demonstrates there a not links between the data object and the context that was used to
     * create it
     */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    signature_len = 10000;
    sign_rc = HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, msg_input_data, blank_buffer, &signature_len);
    check_rc(sign_rc == SUCCESS ? -100:SUCCESS , "Sign", testcount, "Check new context and old data match, plus no link to old context", sign_passes, sign_failures);

exit:
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_free(msg_input_data);
    HASHMLDSA_free(hashed_msg_input_data);
    HASHMLDSA_free(blank_input_data);

    if (valid_pkey)
        EVP_PKEY_free(valid_pkey);

    if (notvalid_pkey)
        EVP_PKEY_free(notvalid_pkey);

    if (notapplicable_pkey)
        EVP_PKEY_free(notapplicable_pkey);

    if (valid_hashed_msg)
        free(valid_hashed_msg);

    return rc;
}

/*
 * Here we test for failures within just the Verify API
 * the internal prehash call is already tested as is a successful verify
 */
static int test_validation_on_verify(unsigned int *passes, unsigned int *failures, unsigned int *testcount)
{
    unsigned char* valid_hashed_msg = NULL;
    size_t len = 0;

    unsigned char blank_buffer[10000];
    size_t signature_len = 0;

    int rc = SUCCESS;
    int verify_rc = SUCCESS;
    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *msg_input_data = NULL;
    HASHMLDSA *hashed_msg_input_data = NULL;
    HASHMLDSA *blank_input_data = NULL;

    EVP_PKEY *valid_pkey = NULL;
    EVP_PKEY *notapplicable_pkey = NULL;
    EVP_PKEY *notvalid_pkey = NULL;


    /* generate a valid key */
    if (generate_key_from_name(valid_sig_alg, &valid_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", valid_sig_alg);
        rc = FAILURE;
        goto exit;
    }

    /* create valid context and input data */
    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_message(msg_input_data, "Here is a Message of a specific length", 38);

    /* start of the tests */
    verify_rc = HASHMLDSA_verify(NULL, valid_pkey, msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check for context being NULL", passes, failures);

    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, NULL, msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check for public key being NULL", passes, failures);

    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, NULL, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check for input data being NULL", passes, failures);

    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, blank_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check for no message or hashed message (blank input)", passes, failures);

    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, msg_input_data, "Signature", 0);
    check_rc(verify_rc, "Verify", testcount, "Check for signature length being zero", passes, failures);

    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, msg_input_data, NULL, 0);
    check_rc(verify_rc, "Verify", testcount, "Check for signature being NULL", passes, failures);

    /* test the use of a key that isn't compatible with the context */
    if (generate_key_from_name(notapplicable_sig_alg, &notapplicable_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", notapplicable_sig_alg);
        rc = FAILURE;
        goto exit;
    }
    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, notapplicable_pkey, msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check the key cannot be used even though it's MLDSA type", passes, failures);

    if (generate_key_from_name(notvalid_sig_alg, &notvalid_pkey) != 0) {
        fprintf(stderr, "[ERROR] Failed to create new %s key\n", notvalid_sig_alg);
        rc = FAILURE;
        goto exit;
    }
    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, notvalid_pkey, msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check the key cannot be used", passes, failures);

    /* tests to check hashed message digest mismatch */
    hashed_msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    hexString2byteArray(encoded_valid_hashed_msg, &valid_hashed_msg, &len);
    HASHMLDSA_set_hashed_message(hashed_msg_input_data, valid_hashed_msg, encoded_valid_hashed_msg_len);
    HASHMLDSA_override_message_digest(hashed_msg_input_data, notapplicable_hash_msg_digest, 0);
    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, hashed_msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check Hashed message mismatches with data overridden hash", passes, failures);

    HASHMLDSA_free(hashed_msg_input_data);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, notapplicable_hash_msg_digest, 0);
    hashed_msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_hashed_message(hashed_msg_input_data, valid_hashed_msg, encoded_valid_hashed_msg_len);
    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, hashed_msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check Hashed message mismatches with context defined hash", passes, failures);

    /* test to show that data came from a matching context */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = HASHMLDSA_CTX_new(notapplicable_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, msg_input_data, "Signature", 9);
    check_rc(verify_rc, "Verify", testcount, "Check Context and Data Mismatch", passes, failures);

    /*
     * test that data can be used with a matching context, and as the previous one has been freed
     * It also demonstrates there a not links between the data object and the context that was used to
     * create it.
     */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    signature_len = 10000;
    if (!HASHMLDSA_sign(hashmldsa_ctx, valid_pkey, msg_input_data, blank_buffer, &signature_len)) {
        fprintf(stdout, "Failed to sign successfully as needed by the test");
        HASHMLDSA_print_last_error(stdout);
        HASHMLDSA_clear_last_error();
        rc = FAILURE;
        goto exit;
    }
    verify_rc = HASHMLDSA_verify(hashmldsa_ctx, valid_pkey, msg_input_data, blank_buffer, signature_len);
    HASHMLDSA_print_last_error(stdout);
    check_rc(verify_rc == SUCCESS ? -100:SUCCESS , "Verify", testcount, "Check new context and old data match, plus no link to old context", passes, failures);


exit:
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_free(msg_input_data);
    HASHMLDSA_free(hashed_msg_input_data);
    HASHMLDSA_free(blank_input_data);

    if (valid_pkey)
        EVP_PKEY_free(valid_pkey);

    if (notvalid_pkey)
        EVP_PKEY_free(notvalid_pkey);

    if (notapplicable_pkey)
        EVP_PKEY_free(notapplicable_pkey);

    if (valid_hashed_msg)
        free(valid_hashed_msg);

    return rc;
}

/*
 * Here we test for failures within just the prehash API
 */
static int test_validation_on_prehash(unsigned int *passes, unsigned int *failures, unsigned int *testcount)
{
    unsigned char *hashed_message = NULL;
    unsigned char blank_buffer[10000];
    size_t hashed_message_len = 10000;
    int create_hash_rc = SUCCESS;  // TODO: Can remove and merge calls into check lines
    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *msg_input_data = NULL;
    HASHMLDSA *general_input_data = NULL;
    HASHMLDSA *blank_input_data = NULL;

    /* create a valid context and input data */
    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    msg_input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_message(msg_input_data, "Here is a Message of a specific length", 38);
    blank_input_data = HASHMLDSA_new(hashmldsa_ctx);

    create_hash_rc = HASHMLDSA_generate_hashed_message(NULL, msg_input_data, NULL, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for context being NULL", passes, failures);

    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, NULL, NULL, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for input data being NULL", passes, failures);

    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, msg_input_data, NULL, NULL);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for hashed_message_len being NULL", passes, failures);

    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, blank_input_data, blank_buffer, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for input data being blank", passes, failures);


    general_input_data = HASHMLDSA_new(hashmldsa_ctx);
    HASHMLDSA_set_hashed_message(general_input_data, "Here is a Message of a specific length", 38);
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, general_input_data, blank_buffer, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for hashed message being set", passes, failures);

    /* test to see if we have now set a message previously set with hashed message and it now works */
    HASHMLDSA_set_message(general_input_data, "Here is a Message of a specific length", 38);
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, general_input_data, blank_buffer, &hashed_message_len);
    check_rc(create_hash_rc == SUCCESS ? -100 : SUCCESS, "PreHash", testcount, "Check for message being set where hashed message was set", passes, failures);

    /* test to see if we now set hashed message that previous message is not there anymore */
    HASHMLDSA_set_hashed_message(general_input_data, "Here is a Message of a specific length", 38);
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, general_input_data, blank_buffer, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for hashed message being set where message was set", passes, failures);

    /* test to see if mismatch of hashed message length is detected */
    HASHMLDSA_set_context_string(general_input_data, "Here is a context of a specific length", 38);
    HASHMLDSA_set_message(general_input_data, "Here is a Message of a specific length", 38);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, "SHA256", 0);
    hashed_message_len = 10000;
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, general_input_data, NULL, &hashed_message_len);
    if (create_hash_rc != SUCCESS) {
        printf("Expected successful prehash, but failed: ");
        return FAILURE;
    }
    hashed_message_len--;
    hashed_message = malloc(hashed_message_len);
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, general_input_data, hashed_message, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check for mismatch of hashed message length", passes, failures);
    free(hashed_message);

    /* test to show that data came from a matching context */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = HASHMLDSA_CTX_new(notapplicable_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, msg_input_data, blank_buffer, &hashed_message_len);
    check_rc(create_hash_rc, "PreHash", testcount, "Check Context and Data Mismatch", passes, failures);

    /*
     * test that data can be used with a matching context, and as the previous one has been freed
     * It also demonstrates there a not links between the data object and the context that was used to
     * create it
     */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = HASHMLDSA_CTX_new(valid_sig_alg);
    HASHMLDSA_CTX_set_message_digest(hashmldsa_ctx, valid_hash_msg_digest, 0);
    create_hash_rc = HASHMLDSA_generate_hashed_message(hashmldsa_ctx, msg_input_data, blank_buffer, &hashed_message_len);
    check_rc(create_hash_rc == SUCCESS ? -100:SUCCESS , "PreHash", testcount, "Check new context and old data match, plus no link to old context", passes, failures);


    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_free(msg_input_data);
    HASHMLDSA_free(blank_input_data);
    HASHMLDSA_free(general_input_data);
    HASHMLDSA_clear_last_error();

    return 0;

}


int main(int argc, char const *argv[])
{
    unsigned int context_passes = 0;
    unsigned int context_failures = 0;

    unsigned int data_passes = 0;
    unsigned int data_failures = 0;

    unsigned int sign_passes = 0;
    unsigned int sign_failures = 0;

    unsigned int verify_passes = 0;
    unsigned int verify_failures = 0;

    unsigned int prehash_passes = 0;
    unsigned int prehash_failures = 0;

    unsigned int testcount = 0;
    unsigned int total_passed = 0;
    unsigned int total_failed = 0;

    int rc = 0;

    printf("Start testing parameter validation\n");

    /*
     * context creation tests
     */
    rc = test_validation_on_context_creation(&context_passes, &context_failures, &testcount);
    if (rc != SUCCESS) {
        printf("Critical test failure, test run not done\n");
        return rc;
    }
    printf("Context creation Results: Passed: %d, Failed: %d\n\n", context_passes, context_failures);
    total_passed += context_passes;
    total_failed += context_failures;

    /*
     * data creation tests
     */
    rc = test_validation_on_data_creation(&data_passes, &data_failures, &testcount);
    if (rc != SUCCESS) {
        printf("Critical test failure, test run not done\n");
        return rc;
    }
    printf("Data creation Results: Passed: %d, Failed: %d\n\n", data_passes, data_failures);
    total_passed += data_passes;
    total_failed += data_failures;

    /*
     * sign tests
     */
    rc = test_hash_msg_validity_sign_or_verify(perform_sign, "Sign", &sign_passes, &sign_failures, &testcount);
    if (rc != SUCCESS) {
        printf("Critical test failure, test run not done\n");
        return rc;
    }

    rc = test_validation_on_sign(&sign_passes, &sign_failures, &testcount);
    if (rc != SUCCESS) {
        printf("Critical test failure, test run not done\n");
        return rc;
    }

    printf("Sign Results: Passed: %d, Failed: %d\n\n", sign_passes, sign_failures);
    total_passed += sign_passes;
    total_failed += sign_failures;

    /*
     * verify tests
     */
    rc = test_hash_msg_validity_sign_or_verify(perform_verify, "Verify", &verify_passes, &verify_failures, &testcount);
    if (rc != SUCCESS) {
        printf("Critical test failure, test run not complete 1\n");
        return 1;
    }

    rc = test_validation_on_verify(&verify_passes, &verify_failures, &testcount);
    if (rc != SUCCESS) {
        printf("Critical test failure, test run not complete 2\n");
        return 1;
    }
    printf("Verify Results: Passed: %d, Failed: %d\n\n", verify_passes, verify_failures);
    total_passed += verify_passes;
    total_failed += verify_failures;

    /*
     * create hashed message tests
     */
    rc = test_validation_on_prehash(&prehash_passes, &prehash_failures, &testcount);
    if (rc != 0) {
        printf("Critical test failure, test run not complete 3\n");
        return 1;
    }
    printf("PreHash Results: Passed: %d, Failed: %d\n\n", prehash_passes, prehash_failures);
    total_passed += prehash_passes;
    total_failed += prehash_failures;

    printf("\nOverall Results: Total %d, Passed: %d, Failed: %d\n", testcount, total_passed, total_failed);
    if (total_failed > 0)
        return 1;

    return 0;
}
