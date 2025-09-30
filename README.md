# PreHash ML-DSA Library for OpenSSL

[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) chapter 5 defines an algorithm for pre hashing a message before signing using one of the ML-DSA signature algorithms (see section 5.4 in FIPS 204 PreHash ML-DSA). There are many reasons for wanting to do this, for example you may wish to use an external signing service but do not want to include the message content due to privacy concerns. However at this time, the capability has not been made available in OpenSSL.

The library, built on top of OpenSSL 3.5 provides the following capabilities confirming to the FIPS standard

- create a pre-hash prior to signing or verifying
- the ability to sign this pre-hash
- the ability to verify this pre-hash

In addition to use explicit pre-hashing as shown above, the library can also leverage implicit pre-hashing: In the functions for sign/verify, the pre-hashed message *or* the message can be used, whichever was set last in the input data before the sign/verify invocation. This can be helpful for the case where the signing is done (e.g. remotely) using an explicitly pre-hashed message, but the verification is done (e.g. locally) against a readily available message with implicit pre-hashing inside the verify function.

It's important to choose the right hash (or length of hash if you use a XOF hashing algorithm) to ensure resistance against collision. in FIPS 204 section 5.4 subnote 6 specifies that "Obtaining at least 𝜆 bits of classical security strength against collision attacks requires that the digest to be signed be at least 2𝜆 bits in length". The classical security strength is the strength of the signature algorithm specified. Section 3.6.1 in FIPS 204 defines the minimum security strength each signature shall achieve

| Signature Algorithm | Security Strength in bits | minimum hash bit length |
| ---- | ---- | ---- |
| ML-DSA-44 | 128 | 256 |
| ML-DSA-65 | 192 | 384 |
| ML-DSA-87 | 256 | 512 |

These are the strengths that OpenSSL creates for each of the signature algorithms. Given the above, you can see that a message digest of SHA3-256 is only suitable for use with ML-DSA-44. The library return an error if you try to set a digest that cannot be used with the specific algorithm. When you create a new HASHMLDSA_ctx context and specify a signature algorithm, the library will set up an initial digest for you that would satisfy the collision prevention requirements. The default and digests that can be used with a specific signature algorithm are

| Signature Algorithm | Default Digest | SHA2-256 | SHA2-384 | SHA2-512 | SHA2-512/256 | SHA3-256   | SHA3-384   | SHA3-512   | SHAKE128     | SHAKE256     |
|---------------------|----------------|----------|----------|----------|--------------|------------|------------|------------|--------------|--------------|
| ML-DSA-44           | SHA3-256       | &#9989;  | &#9989;  | &#9989;  | &#9989;      | &#9989;    | &#9989;    | &#9989;    | len ≥ 32B    | len ≥ 32B    |
| ML-DSA-65           | SHA3-384       | &#10060; | &#9989;  | &#9989;  | &#10060;     | &#10060;   | &#9989;    | &#9989;    | len ≥ 48B    | len ≥ 48B    |
| ML-DSA-87           | SHA3-512       | &#10060; | &#10060; | &#9989;  | &#10060;     | &#10060;   | &#10060;   | &#9989;    | len ≥ 64B    | len ≥ 64B    |

## API Reference

[API reference](./api_documentation.md)

## Code Examples

The following a small snippets showing the use of the library

### Signing a message which has not been pre-hashed

```c
#include "hashMLDSA.h"
...
HASHMLDSA_CTX *hashmldsa_ctx = NULL;
HASHMLDSA *hashmldsa_data = NULL;
char *signature = NULL;
size_t signature_len = 0;
EVP_PKEY *private_key = NULL; // to contain the private key
OSSL_LIB_CTX *lib_ctx;        // openssl library context (to be populated by app)
int rc = SUCCESS;             // developer defined return code
...
hashmldsa_ctx = HASHMLDSA_CTX_new(lib_ctx, "ML-DSA-44");
if (hashmldsa_ctx == NULL) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}
...
hashmldsa_data = HASHMLDSA_new(hashmldsa_ctx);
if (hashmldsa_data == NULL) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}

HASHMLDSA_set_message(hashmldsa_data, "This is an example message", 26);
// obtain the signature length
if (!HASHMLDSA_sign(hashmldsa_ctx, NULL, NULL, NULL, &signature_len)) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE; // developer defined return code
    goto exit;
}

signature = OPENSSL_zalloc(signature_len);
if (!HASHMLDSA_sign(hashmldsa_ctx, private_key, hashmldsa_data, signature, &signature_len)) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE; // developer defined return code
    goto exit;
}

// do something with signature

exit:
    HASHMLDSA_free(hashmldsa_data);
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_clear_last_error();
    return rc;
```

### Verifying a prehashed message

```c
#include "hashMLDSA.h"
...
HASHMLDSA_CTX *hashmldsa_ctx = NULL;
HASHMLDSA *hashmldsa_data = NULL;
unsigned char* hashed_message = NULL; // to contain the hashed message
size_t hashed_message_len = 0;        // to contain the length the the hashed message
unsigned char* signature = NULL;      // to contain the signature
size_t signature_len = 0;             // to contain the signature length
EVP_PKEY *public_key = NULL;          // to contain the public key
OSSL_LIB_CTX *lib_ctx;                // openssl library context (to be populated by app)
int rc = SUCCESS;                     // developer defined return code
...
hashmldsa_ctx = HASHMLDSA_CTX_new((lib_ctx, "MLDSA65"); // note the different format of the signature algorithm is also supported
if (hashmldsa_ctx == NULL) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}
...
hashmldsa_data = HASHMLDSA_new(hashmldsa_ctx);
if (hashmldsa_data == NULL) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}
HASHMLDSA_set_hashed_message(hashmldsa_data, hashed_message, hashed_message_len);

if (!HASHMLDSA_verify(hashmldsa_ctx, public_key, hashmldsa_data, signature, signature_len)) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE; // developer defined return code
    goto exit;
}

// verifcation successful

exit:
    HASHMLDSA_free(hashmldsa_data);
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_clear_last_error();
    return rc;
```

### Creating a prehashed message

```c
#include "hashMLDSA.h"
...
HASHMLDSA_CTX *hashmldsa_ctx = NULL;
HASHMLDSA *hashmldsa_data = NULL;
unsigned char* hashed_message = NULL;
size_t hashed_message_len = 0;
OSSL_LIB_CTX *lib_ctx; // openssl library context (to be populated by app)
int rc = SUCCESS;      // developer defined return code
...
hashmldsa_ctx = HASHMLDSA_CTX_new((lib_ctx, "ML-DSA-44");  // signature algorithm may seem unnecessary, but means we can use context for other operations
if (hashmldsa_ctx == NULL) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}
...
hashmldsa_data = HASHMLDSA_new(hashmldsa_ctx);
if (hashmldsa_data == NULL) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}

if (!HASHMLDSA_set_context_string(hashmldsa_data, "A Context", 9)) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}
HASHMLDSA_set_message(hashmldsa_data, "This is an example message", 26);
// get the length of the hashed message so it can be allocated
if (!HASHMLDSA_generate_hashed_message(hashmldsa_ctx, hashmldsa_data, NULL, &hashed_message_len)) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}
hashed_message = OPENSSL_zalloc(hashed_message_len);
if (!HASHMLDSA_generate_hashed_message(hashmldsa_ctx, hashmldsa_data, hashed_message, &hashed_message_len)) {
    HASHMLDSA_print_last_error(stderr);
    rc = FAILURE;
    goto exit;
}

// do something with the pre-hashed message

exit:
    HASHMLDSA_free(hashmldsa_data);
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    HASHMLDSA_clear_last_error();
    return rc;
```

## HASHMLDSA Contexts

Contexts are designed for reuse as they perform a few calculations when they are created for performance improvements. They have not been tested for thread safety therefore contexts should not be shared across threads at this time. When you create a context you specify the signature algorithm that the context is going to represent and a default digest is assigned as described in the introduction. This default may not be desired so it can be changed on the context using the `HASHMLDSA_ctx_set_message_digest` API. You may have a context for which the digest it contains is the required digest for most of the time but you may wish to use a different digest under certain conditions. In this case you don't want to create a new context or change the existing context, just to change it back again you can use the `HASHMLDSA_override_message_digest` API on the HASHMLDSA instance to alter the message digest used when using that data.
