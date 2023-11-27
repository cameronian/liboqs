

#include <sig_kaz_sign.h>
#include <kaz_api.h>

#if defined(OQS_ENABLE_SIG_KAZ_SIGN)

OQS_SIG *OQS_SIG_KAZ_SIGN_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	sig->method_name = OQS_SIG_alg_KAZ_SIGN;
	sig->alg_version = "V1.4";

	sig->claimed_nist_level = 1;
	sig->euf_cma = true;

	sig->length_public_key = CRYPTO_PUBLICKEYBYTES;
	sig->length_secret_key = CRYPTO_SECRETKEYBYTES;
	sig->length_signature = KAZ_DS_S1BYTES+KAZ_DS_S2BYTES;

	sig->keypair = OQS_SIG_KAZ_SIGN_keypair;
	sig->sign = OQS_SIG_KAZ_SIGN_sign;
	sig->verify = OQS_SIG_KAZ_SIGN_verify;

	return sig;
}
extern void KAZ_DS_KeyGen(unsigned char *kaz_ds_verify_key,
                          unsigned char *kaz_ds_sign_key);

extern int KAZ_DS_SIGNATURE(unsigned char *signature,
                             size_t *signlen,
                             const unsigned char *m,
                             size_t mlen,
                             const unsigned char *kaz_ds_sign_key);
extern int KAZ_DS_VERIFICATION(unsigned char *signature,
                               size_t signature_len,
                               const unsigned char *m,
                               size_t mlen,
                               const unsigned char *pk);


OQS_API OQS_STATUS OQS_SIG_KAZ_SIGN_keypair(uint8_t *public_key, uint8_t *secret_key) {
  
  KAZ_DS_KeyGen(public_key, secret_key);
  
  if(sizeof(public_key)!=0 || sizeof(secret_key)!=0) return 0;
  else return -4;

}

OQS_API OQS_STATUS OQS_SIG_KAZ_SIGN_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {

  int status = KAZ_DS_SIGNATURE(signature, signature_len, message, message_len, secret_key);

  if(*signature_len > message_len && status == 0)
    return 0;
  else
    return status;

}


OQS_API OQS_STATUS OQS_SIG_KAZ_SIGN_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {

  int status = KAZ_DS_VERIFICATION(signature, signature_len, message, message_len, public_key);

  if (status == 0)
    return 0;
  else
    return status;

}

#endif
