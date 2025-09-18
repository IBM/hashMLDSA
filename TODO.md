# TODO

- runnable samples
- multiplatform/arch support: linux-ppc64le, windows-intel, windows-arm, darwin-intel/arm, zOS via USS (known to not work due to thread local storage)
- test this with OQS

- Improvements to documentation
  - how to build ie how to consume what is there
  - compatibility between data and context

- Future code changes
  - implement thread local support (rather than rely on inbuilt C capabilities) to support zOS via USS as well as other platforms that use older C standards
  - consider marking pointers read only eg HASHMLDSA * const input_data
  - contexts to be thread safe
  - cache partial calculation of hashed_message_len
  - EVP_PKEY_get_security_bits(...) to get security strength in the future, not hard coded
  - get the signature length for a sig from OpenSSL call, not hard coded
  - thread_local move to using apis to allow for other environments to be supported (eg z/OS)
