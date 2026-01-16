# API Documentation

```c
HASHMLDSA_CTX *HASHMLDSA_CTX_new(OSSL_LIB_CTX *lib_ctx, const char *sig_alg_name)
```

**Description**:
Allocates memory for a new HASHMLDSA context structure and initializes its fields. The only supported algorithms are ML-DSA-44, ML-DSA-65 or ML-DSA-87. Alternative names such as MLDSA44 are also allowed. It returns a pointer to the newly created context or NULL if memory allocation fails. A default digest will be assigned to this context which will have the necessary number of bits to satisfy the FIPS 204 requirements. See the documentation on this library for more details which lists the default digest assigned based on the provided signature algorithm.

**Parameters**:

- *lib_ctx*: An openssl library context. NULL is not valid. The library context must have the default provider loaded otherwise it's not valid.
- *sig_alg_name*: The required signature algorithm.

**Returns**:
A pointer to the newly created HASHMLDSA context on success, NULL on failure.

---

```c
HASHMLDSA_CTX *HASHMLDSA_CTX_new_for_test(OSSL_LIB_CTX *lib_ctx, const char* sig_alg_name)
```

**Description**:
Allocates memory for a new HASHMLDSA context structure and initializes its fields. The only supported algorithms are ML-DSA-44, ML-DSA-65 or ML-DSA-87. Alternative names such as MLDSA44 are also allowed. It returns a pointer to the newly created context or NULL if memory allocation fails. This will force deterministic mode for signing and should only be used for testing purposes. A default digest will be assigned to this context which will have the necessary number of bits to satisfy the FIPS 204 requirements. See the documentation on this library for more details which lists the default digest assigned based on the provided signature algorithm.

**Parameters**:

- *lib_ctx*: An openssl library context. NULL is not valid. The library context must have the default provider loaded otherwise it's not valid.
- *sig_alg_name*: The required signature algorithm.

**Returns**:
A pointer to the newly created HASHMLDSA context on success, NULL on failure.

---

```c
int HASHMLDSA_CTX_set_message_digest(HASHMLDSA_CTX *ctx, const char* digest_name, size_t hash_len)
```

**Description**:
Explicitly set the message digest name if the default value is not suitable. You can specify a hash length if you specify a XOF digests such as SHAKE128 or SHAKE256. For non XOF digests the length is ignored. Note that any previously created HASHMLDSA strctures will not see this change, only when you create new HASHMLDSA structures using the updated context will the HASHMLDSA structure get the updated digest information. All the alternative names for digests supported by OpenSSL are supported here as well. You much chose a digest or in the case of an XOF digest, a length, that is note strong enough for the signature algorithm specified when the context is created, this call will fail. If you chose an XOF digest such as SHAKE128 or SHAKE256, specifying a hash_len of 0 will result in a default hash length being allocated. The default is defined by OpenSSL itself and not by this library.

**Parameters**:

- *ctx*: A pointer to HASHMLDSA_CTX structure.
- *digest_name*: The name of the digest (e.g., "SHA-256"). Supports same canonical names as OpenSSL.
- *hash_len*: The byte length of the hash when specifying a XOF digest. it's ignored otherwise.

**Returns**:
1 on success, 0 on failure if the digest (and optionally the length) is not strong enough for the signature algorithm selected.

---

```c
void HASHMLDSA_CTX_free(HASHMLDSA_CTX *ctx)
```

**Description**:
This function frees the memory allocated for the HASHMLDSA context either from a HASHMLDSA_CTX_new or HASHMLDSA_CTX_new_for_test. Passing in NULL results in a NO-OP.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context to be freed.

---

```c
HASHMLDSA *HASHMLDSA_new(const HASHMLDSA_CTX *ctx)
```

**Description**:
This function allocates memory for a new HASHMLDSA structure and initializes its fields to default values, the digest information is taken from the context and stored in this structure.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.

**Returns**:
A pointer to the newly allocated HASHMLDSA structure on success, NULL on failure.

---

```c
void HASHMLDSA_free(HASHMLDSA *data)
```

**Description**:
This function frees the memory allocated for the HASHMLDSA structure. Passing in NULL results in a NO-OP.

**Parameters**:

- *data*: Pointer to HASHMLDSA structure to be freed.

---

```c
int HASHMLDSA_set_context_string(HASHMLDSA *data, const unsigned char* context_string, size_t context_string_len)
```

**Description**:
set's the context string and the length of this context string in the HASHMLDSA structure for use when creating the hashed message during sign or the createPreHash operations.

**Parameters**:

- *data*: A pointer to HASHMLDSA structure.
- *context_string_string*: A pointer to the byte array containing the context string.
- *context_string_string_len*: The length of the context string. Maximum length is 255.

**Returns**:
1 on success, 0 on failure if context is too large or if data is NULL.

---

```c
int HASHMLDSA_set_message(HASHMLDSA *data, const unsigned char* message, size_t message_len)
```

**Description**:
set's the message and the length of this message in the HASHMLDSA structure for use when creating the hashed message during sign or the createPreHash operations. Message and Hashed Message are mutually exclusive. Whichever was set last is used, so for example if set_message was invoked after set_hashed_message then the values for set_message are used.

**Parameters**:

- *data*: A pointer to HASHMLDSA structure.
- *message*: A pointer to the message data.
- *message_len*: The length of the message.

**Returns**:
1 on success, 0 on failure if data is NULL.

---

```c
int HASHMLDSA_set_hashed_message(HASHMLDSA *data, const unsigned char* hashed_message, size_t hashed_message_len)
```

**Description**:
Set a previously hashed message and it's length. This provides the ability to separate the sign or verify into 2 distinct steps where the creation of the hash may have been done earlier or elsewhere (for example a different machine). Message and Hashed Message are mutually exclusive. Whichever was set last is used, so for example if set_hashed_message was invoked after set_message then the values for set_hashed_message are used.

**Parameters**:

- *data*: A pointer to HASHMLDSA structure.
- *hashed_message*: A pointer to the hashed message.
- *hashed_message_len*: The length of the hashed message.

**Returns**:
1 on success, 0 on failure if data is NULL.

---

```c
int HASHMLDSA_override_message_digest(HASHMLDSA *data, const char* digest_name, size_t hash_len)
```

**Description**:
Explicitly override the message digest if the value inherited from the context is not suitable. You can specify a hash length if you specify a XOF digests such as SHAKE128 or SHAKE256. For non XOF digests the length is ignored. All the alternative names for digests supported by OpenSSL are supported here as well. You much chose a digest or in the case of an XOF digest, a length, that is note strong enough for the signature algorithm specified when the context is created, this call will fail. If you chose an XOF digest such as SHAKE128 or SHAKE256, specifying a hash_len of 0 will result in a default hash length being allocated. The default is defined by OpenSSL itself and not by this library.

**Parameters**:

- *data*: A pointer to HASHMLDSA structure.
- *digest_name*: The name of the digest (e.g., "SHA2-256").
- *hash_len*: The byte length of the hash when specifying a XOF digest. it's ignored otherwise.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_print_last_error(FILE *fp)
```

**Description**:
Output the last error recorded. Note that it is never cleared and further errors will overwrite the previous one.

**Parameters**:

- *fp*: file pointer to write to, eg stderr.

---

```c
void HASHMLDSA_clear_last_error()
```

**Description**:
Clear last error recorded. If there was an error recorded then the memory is freed as well.

---

```c
int HASHMLDSA_generate_hashed_message(const HASHMLDSA_CTX *ctx, const HASHMLDSA *data, unsigned char *hashed_message, size_t *hashed_message_len)
```

**Description**:
Pre hash the message ready for signing or verifying. This is useful when needing to do the sign or verification separately. This performs a full init/update/final in one call.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters, message and context or pre-hashed message.
- *hashed_message*: Pointer to buffer where the pre-hashed message will be stored.
- *hashed_message_len*: Pointer to size_t variable that will hold the length of the pre-hashed message.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_generate_hashed_message_init(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, size_t *hashed_message_len)
```

**Description**:
initialise in preparation to generate a pre-hash of a message.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *hashed_message_len*: Pointer to size_t variable that will hold the length of the final pre-hashed message.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_generate_hashed_message_update(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, const unsigned char* message_fragment, size_t message_fragment_len)
```

**Description**:
Add a message fragment to the current set of message fragments. This can be called multiple times to build up the message to be pre-hashed.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *message_fragment*: The message fragment.
- *hashed_message_len*: The size of the message fragment.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_generate_hashed_message_final(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, unsigned char *hashed_message, size_t *hashed_message_len)
```

**Description**:
Perform the actual pre-hash on the collection of message fragments provided through the HASHMLDSA_generate_hashed_message_final API.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *hashed_message*: Pointer to buffer where the pre-hashed message will be stored.
- *hashed_message_len*: Pointer to size_t variable that will hold the length of the pre-hashed message.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_sign(const HASHMLDSA_CTX *ctx, EVP_PKEY *priv_key, const HASHMLDSA *data, unsigned char *signature, size_t *signature_len)
```

**Description**:
This will sign a message creating the hash first or using a previously hashed message using the provided private key. You can use this call to determine the size of the signature without performing a sign by passing NULL for all parameters except the context and a point to the signature length. This performs the action of an init/update/final in a single API call but also allows support for providing an already pre-hashed message.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *priv_key*: The private key for signing.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters, message and context or pre-hashed message.
- *signature*: The buffer to store the generated signature.
- *signature_len*: Pointer to the size of the signature buffer. If NULL is passed for the signature this will contain the length required for the signature.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_sign_init(const HASHMLDSA_CTX *ctx, EVP_PKEY *priv_key, HASHMLDSA *data, size_t *signature_len)
```

**Description**:
This will prepare to sign a message provided though one or more calls to HASHMLDSA_sign_init. This API will return the size of the signature that will be created as it is not dependent on the length of the message.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *priv_key*: The private key for signing.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *signature_len*: Pointer to the size of the signature buffer. If NULL is passed for the signature this will contain the length required for the signature.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_sign_update(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, const unsigned char* message_fragment, size_t message_fragment_len)
```

**Description**:
Add a message fragment to the current set of message fragments. This can be called multiple times to build up the message to be pre-hashed and signed.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *message_fragment*: The message fragment.
- *hashed_message_len*: The size of the message fragment.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_sign_final(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, unsigned char *signature, size_t *signature_len)
```

**Description**:
This will pre-hash and sign the complete message using the private key provided via HASHMLDSA_sign_init. Note The final message is not stored in the data object.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *signature*: The buffer to store the generated signature.
- *signature_len*: Pointer to the size of the signature buffer.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_verify(const HASHMLDSA_CTX *ctx, EVP_PKEY *public_key, const HASHMLDSA *data, const unsigned char *signature, size_t signature_len)
```

**Description**:
This will verify a message creating the hash first or using a previously hashed message using the provided public key. This performs the action of an init/update/final in a single API call but also allows support for providing an already pre-hashed message.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *public_key*: The public key for verifying.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters, message and context or pre-hashed message.
- *signature*: The signature to verify.
- *signature_len*: The size of the signature buffer.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_verify_init(const HASHMLDSA_CTX *ctx, EVP_PKEY *public_key, HASHMLDSA *data)
```

**Description**:
This will verify a message creating the hash first or using a previously hashed message using the provided public key.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *public_key*: The public key for verifying.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_verify_update(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, const unsigned char* message_fragment,
```

**Description**:
Add a message fragment to the current set of message fragments. This can be called multiple times to build up the message to be pre-hashed and verified.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA structure containing algorithm-specific parameters.
- *message_fragment*: The message fragment.
- *hashed_message_len*: The size of the message fragment.

**Returns**:
1 on success, 0 on failure.

---

```c
int HASHMLDSA_verify_final(const HASHMLDSA_CTX *ctx, HASHMLDSA *data, unsigned char *signature,
```

**Description**:
This will pre-hash and verify the complete message using the provided signature and public key provided via HASHMLDSA_sign_init. Note The final message is not stored in the data object.

**Parameters**:

- *ctx*: Pointer to HASHMLDSA context.
- *data*: Pointer to HASHMLDSA_Params structure containing the context and digest information.
- *signature*: The buffer to store the generated signature.
- *signature_len*: Pointer to the size of the signature buffer.

**Returns**:
1 on success, 0 on failure.
