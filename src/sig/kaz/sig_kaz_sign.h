// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_KAZ_SIGN_H
#define OQS_SIG_KAZ_SIGN_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_SIG_KAZ_SIGN

OQS_SIG *OQS_SIG_KAZ_SIGN_new(void);

OQS_API OQS_STATUS OQS_SIG_KAZ_SIGN_keypair(uint8_t *public_key, uint8_t *secret_key);

OQS_API OQS_STATUS OQS_SIG_KAZ_SIGN_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

OQS_API OQS_STATUS OQS_SIG_KAZ_SIGN_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif

#endif
