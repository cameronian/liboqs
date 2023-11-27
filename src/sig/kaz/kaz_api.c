#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/sha.h>

#include "rng.h"
#include "gmp.h"
#include "kaz_api.h"
#include "sha256.h"

void HashMsg(const unsigned char *msg, unsigned long long mlen, unsigned char buf[32])
{
//    SHA512(msg, mlen, &buf);
    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, msg, mlen);
    //sha256_update(&hash, msg, mlen);
    sha256_final(&hash, buf);
}

void KAZ_DS_KeyGen(unsigned char *kaz_ds_verify_key,
                   unsigned char *kaz_ds_sign_key)
{
    mpz_t GRg, q, Q;
    mpz_t ALPHA, GRgq, V1, q2, qsub1, q0, tmp, V2;
    mpz_inits(GRg, q, Q, ALPHA, GRgq, V1, q2, qsub1, q0, tmp, V2, NULL);

    //1) Get all system parameters
    mpz_set_str(GRg, KAZ_DS_SP_GRg, 10);
    mpz_set_str(q, KAZ_DS_SP_q, 10);
    mpz_set_str(Q, KAZ_DS_SP_Q, 10);

    int nphiGg=KAZ_DS_SP_nPHIGg;

    //2) Generate ALPHA & (V1, V2)
    KAZ_DS_RANDOM(nphiGg-2, nphiGg-1, ALPHA);

    mpz_mul(GRgq, GRg, q);
    mpz_mod(V1, ALPHA, GRgq);

    mpz_mul(q2, q, q);
    mpz_sub_ui(qsub1, q, 1);
    mpz_divexact(q0, qsub1, Q);
    mpz_powm(tmp, ALPHA, q0, q2);

    size_t TMPSIZE=mpz_sizeinbase(tmp, 16);

    unsigned char *TMPBYTE=(unsigned char*) malloc(TMPSIZE*sizeof(unsigned char));
    mpz_export(TMPBYTE, &TMPSIZE, 1, sizeof(char), 0, 0, tmp);

    unsigned char buf[32]={0};
    HashMsg(TMPBYTE, TMPSIZE, buf);

    mpz_import(V2, 32, 1, sizeof(char), 0, 0, buf);

    //3) Set kaz_ds_sign_key=(ALPHA, V2) & kaz_ds_verify_key=(V1, V2, V3)
    size_t ALPHASIZE=mpz_sizeinbase(ALPHA, 16);
    size_t V1SIZE=mpz_sizeinbase(V1, 16);
    size_t V2SIZE=mpz_sizeinbase(V2, 16);

    unsigned char *ALPHABYTE=(unsigned char*) malloc(ALPHASIZE*sizeof(unsigned char));
    mpz_export(ALPHABYTE, &ALPHASIZE, 1, sizeof(char), 0, 0, ALPHA);

    unsigned char *V1BYTE=(unsigned char*) malloc(V1SIZE*sizeof(unsigned char));
    mpz_export(V1BYTE, &V1SIZE, 1, sizeof(char), 0, 0, V1);

    unsigned char *V2BYTE=(unsigned char*) malloc(V2SIZE*sizeof(unsigned char));
    mpz_export(V2BYTE, &V2SIZE, 1, sizeof(char), 0, 0, V2);

    for(int i=0; i<KAZ_DS_ALPHABYTES; i++) {
        kaz_ds_sign_key[i] = (unsigned char) '0';
    }

    //__android_log_print(ANDROID_LOG_INFO, "BEFORE",
    //                    "%s (%lu) | (%lu)", kaz_ds_sign_key,
    //                    strlen(kaz_ds_sign_key), ALPHASIZE);

    int j=ALPHASIZE;
    for(int i=ALPHASIZE-1; i>=0; i--) {
        kaz_ds_sign_key[j--] = ALPHABYTE[i];
    }

    //__android_log_print(ANDROID_LOG_INFO, "AFTER",
    //                    "%s (%lu) | (%lu)", kaz_ds_sign_key,
    //                    strlen(kaz_ds_sign_key), ALPHASIZE);

    for(int i=0; i<KAZ_DS_V1BYTES+KAZ_DS_V2BYTES; i++) {
        kaz_ds_verify_key[i] = (unsigned char) '0';
    }

    //__android_log_print(ANDROID_LOG_INFO, "BEFORE",
    //                    "%s (%lu) | (%lu)", kaz_ds_verify_key,
    //                    strlen(kaz_ds_verify_key), (V1SIZE+V2SIZE));

    j=KAZ_DS_V1BYTES+KAZ_DS_V2BYTES-1;
    for(int i=V2SIZE-1; i>=0; i--) {
        kaz_ds_verify_key[j--] = V2BYTE[i];
    }

    j=KAZ_DS_V1BYTES-1;
    for(int i=V1SIZE-1; i>=0; i--) {
        kaz_ds_verify_key[j--] = V1BYTE[i];
    }

    //__android_log_print(ANDROID_LOG_INFO, "AFTER",
    //                    "%s (%lu) | (%lu)", kaz_ds_verify_key,
    //                    strlen(kaz_ds_verify_key), (V1SIZE+V2SIZE));

    unsigned char *ALPHAHEX=(unsigned char*) malloc(ALPHASIZE*sizeof(unsigned char));
    mpz_get_str(ALPHAHEX, 16, ALPHA);

    unsigned char *V1HEX=(unsigned char*) malloc(V1SIZE*sizeof(unsigned char));
    mpz_get_str(V1HEX, 16, V1);

    unsigned char *V2HEX=(unsigned char*) malloc(V2SIZE*sizeof(unsigned char));
    mpz_get_str(V2HEX, 16, V2);

    //__android_log_print(ANDROID_LOG_INFO, "ALPHAHEX", "%s", ALPHAHEX);
    //__android_log_print(ANDROID_LOG_INFO, "V1HEX", "%s", V1HEX);
    //__android_log_print(ANDROID_LOG_INFO, "V2HEX", "%s", V2HEX);

    free(ALPHABYTE);
    //free(ALPHAHEX);
    free(V1BYTE);
    //free(V1HEX);
    free(V2BYTE);
    //free(V2HEX);

    mpz_clears(GRg, q, Q, ALPHA, GRgq, V1, q2, qsub1, q0, tmp, V2, NULL);
}

int KAZ_DS_SIGNATURE(unsigned char *signature,
                     size_t *signature_len,
                     const unsigned char *m,
                     size_t mlen,
                     const unsigned char *sk)
{

  if(signature == NULL)
  {
    *signature_len = KAZ_DS_S1BYTES+KAZ_DS_S2BYTES;
    return 0;
  }
  else
  {


    mpz_t PHIQ2, GRg, q, ALPHA;
    mpz_t hashValue, q2, GRgq2, r0, r, S1, GS1, rGS1, Condition1, S1GS1, Condition2, Condition3;
    mpz_t PHIQ2BETA2,Condition4, tmp, rinverse, S2;
    mpz_inits(PHIQ2, GRg, q, ALPHA, hashValue, q2, GRgq2, r0, r, S1, GS1, rGS1, Condition1, S1GS1, NULL);
    mpz_inits(Condition2, Condition3, PHIQ2BETA2,Condition4, tmp, rinverse, S2, NULL);

    //1) Get all system parameters
    mpz_set_str(PHIQ2, KAZ_DS_SP_PHIQ2, 10);
    mpz_set_str(GRg, KAZ_DS_SP_GRg, 10);
    mpz_set_str(q, KAZ_DS_SP_q, 10);

    int BETA=KAZ_DS_SP_BETA;
    int nphiGg=KAZ_DS_SP_nPHIGg;

    //2) Get kaz_ds_sign_key=ALPHA
    //mpz_set_str(ALPHA, sk, 16);
    int ALPHASIZE=0;
    for(int i=0; i<KAZ_DS_ALPHABYTES; i++){
        if((int)sk[i]==48) ALPHASIZE++;
        else break;
    }

    unsigned char *ALPHABYTE=(unsigned char*) malloc((KAZ_DS_ALPHABYTES-ALPHASIZE)*sizeof(unsigned char));

    for(int i=0; i<KAZ_DS_ALPHABYTES-ALPHASIZE; i++) ALPHABYTE[i]=0;
    for(int i=0; i<KAZ_DS_ALPHABYTES-ALPHASIZE; i++){ALPHABYTE[i]=sk[i+ALPHASIZE];}

    mpz_import(ALPHA, KAZ_DS_ALPHABYTES-ALPHASIZE, 1, sizeof(char), 0, 0, ALPHABYTE);

    //3) Generate the hash value of the message
    unsigned char buf[CRYPTO_BYTES]={0};
    HashMsg(m, mlen, buf);

    mpz_t mValue; mpz_init(mValue);
    mpz_import(mValue, mlen, 1, sizeof(char), 0, 0, m);
    mpz_import(hashValue, CRYPTO_BYTES, 1, sizeof(char), 0, 0, buf);

    //4) Generate S1, S2
    mpz_mul(q2, q, q);
    mpz_mul(GRgq2, GRg, q2);

    do{
        KAZ_DS_RANDOM(nphiGg-2, nphiGg-1, r0);
        mpz_mul_ui(r, r0, BETA);
        mpz_mod(S1, r, GRgq2);
        mpz_gcd(GS1, r, GRg);
        // Condition 1
        mpz_divexact(rGS1, r, GS1);
        mpz_gcd(Condition1, rGS1, GRgq2);
        // Condition 2
        mpz_divexact(S1GS1, S1, GS1);
        mpz_gcd(Condition2, S1GS1, GRgq2);
        // Condition 3
        mpz_mod_ui(Condition3, S1, BETA);
        // Condition 4
        mpz_divexact_ui(PHIQ2BETA2, PHIQ2, BETA*BETA);
        mpz_gcd(Condition4, S1, PHIQ2BETA2);
    }while(mpz_cmp_ui(Condition1, 1)!=0 || mpz_cmp_ui(Condition2, 1)!=0 ||
           mpz_cmp_ui(Condition3, 0)!=0 || mpz_cmp_ui(Condition4, 1)!=0);

    //gmp_printf("Condition1=%Zd\nCondition2=%Zd\nCondition3=%Zd\nCondition4=%Zd\n", Condition1, Condition2, Condition3, Condition4);
    mpz_powm(tmp, ALPHA, S1, GRgq2);    // ALPHA^S1 mod GRgq^2
    mpz_add(tmp, tmp, hashValue);       // (ALPHA^S1)+h mod GRgq^2
    mpz_mod(tmp, tmp, GRgq2);
    //mpz_mul(tmp, tmp, GS1);             // GS1*((ALPHA^S1)+h) mod GRgq^2
    mpz_mod(tmp, tmp, GRgq2);
    mpz_divexact(rGS1, r, GS1);
    mpz_invert(rinverse, rGS1, GRgq2);  // 1/r mod GRgq^2
    mpz_mul(tmp, tmp, rinverse);        // GS1*((ALPHA^S1)+h)*r^-1 mod GRgq^2
    mpz_mod(S2, tmp, GRgq2);

    //5) Set signature=(S1, S2)
    size_t S1SIZE=mpz_sizeinbase(S1, 16);
    size_t S2SIZE=mpz_sizeinbase(S2, 16);

    unsigned char *S1BYTE=(unsigned char*) malloc(S1SIZE*sizeof(unsigned char));
    mpz_export(S1BYTE, &S1SIZE, 1, sizeof(char), 0, 0, S1);

    unsigned char *S2BYTE=(unsigned char*) malloc(S2SIZE*sizeof(unsigned char));
    mpz_export(S2BYTE, &S2SIZE, 1, sizeof(char), 0, 0, S2);

    for(int i=0; i<KAZ_DS_S1BYTES+KAZ_DS_S2BYTES; i++) {
        signature[i] = (unsigned char) '0';
    }

    //__android_log_print(ANDROID_LOG_INFO, "BEFORE",
    //                    "%s (%lu) | (%lu)", signature,
    //                    strlen(signature), (S1SIZE+S2SIZE));

    int j=KAZ_DS_S1BYTES+KAZ_DS_S2BYTES-1;
    for(int i=S2SIZE-1; i>=0; i--) {
        signature[j--] = S2BYTE[i];
    }

    j=KAZ_DS_S1BYTES-1;
    for(int i=S1SIZE-1; i>=0; i--) {
        signature[j--] = S1BYTE[i];
    }

    //__android_log_print(ANDROID_LOG_INFO, "AFTER",
    //                    "%s (%lu) | (%lu)", signature,
    //                    strlen(signature), (S1SIZE+S2SIZE));

    unsigned char *S1HEX=(unsigned char*) malloc(S1SIZE*sizeof(unsigned char));
    mpz_get_str(S1HEX, 16, S1);

    unsigned char *S2HEX=(unsigned char*) malloc(S2SIZE*sizeof(unsigned char));
    mpz_get_str(S2HEX, 16, S2);

    size_t HSIZE=mpz_sizeinbase(hashValue, 16);
    unsigned char *HASHHEX=(unsigned char*) malloc(HSIZE*sizeof(unsigned char));
    mpz_get_str(HASHHEX, 16, hashValue);

    //__android_log_print(ANDROID_LOG_INFO, "S1HEX", "%s", S1HEX);
    //__android_log_print(ANDROID_LOG_INFO, "S2HEX", "%s", S2HEX);
    //__android_log_print(ANDROID_LOG_INFO, "HASHHEX", "%s", HASHHEX);

    free(S1BYTE);
    free(S2BYTE);

    mpz_clears(PHIQ2, GRg, q, ALPHA, hashValue, q2, GRgq2, r0, r, S1, GS1, rGS1, Condition1, S1GS1, NULL);
    mpz_clears(Condition2, Condition3, PHIQ2BETA2,Condition4, tmp, rinverse, S2, NULL);

    return 0;
  }
}

int KAZ_DS_VERIFICATION(unsigned char *signature,
                        size_t signature_len,
                        const unsigned char *m,
                        size_t mlen,
                        const unsigned char *pk)
{
    mpz_t N, g, Gg, R, GRg, q, Q, hashValue, V1, V2, S1, S2;
    mpz_t GS1r, aF, q2, GRgq2, tmp, S1inverse, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, PHIQ2BETA2;
    mpz_t qsub1, q0, y1, y2, z0, z1, phiq2o2;
    mpz_inits(N, g, Gg, R, GRg, q, Q, hashValue, V1, V2, S1, S2, GS1r, aF, q2, GRgq2, tmp, S1inverse, NULL);
    mpz_inits(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, PHIQ2BETA2, qsub1, q0, y1, y2, z0, z1, phiq2o2, NULL);

    //1) Get all system parameters
    mpz_set_str(N, KAZ_DS_SP_N, 10);
    mpz_set_str(g, KAZ_DS_SP_G, 10);
    mpz_set_str(Gg, KAZ_DS_SP_Gg, 10);
    mpz_set_str(R, KAZ_DS_SP_R, 10);
    mpz_set_str(GRg, KAZ_DS_SP_GRg, 10);
    mpz_set_str(q, KAZ_DS_SP_q, 10);
    mpz_set_str(Q, KAZ_DS_SP_Q, 10);
    mpz_set_str(phiq2o2, KAZ_DS_SP_PHIQ2, 10);

    int BETA=KAZ_DS_SP_BETA;
    int nphiGg=KAZ_DS_SP_nPHIGg;

    //2) Get kaz_ds_verify_key=(V1, V2)
    //unsigned char *V1BYTE;
    //unsigned char *V2BYTE;

    //V1BYTE=(unsigned char *)calloc(KAZ_DS_V1BYTES, sizeof(unsigned char));
    //V2BYTE=(unsigned char *)calloc(KAZ_DS_V2BYTES, sizeof(unsigned char));

    //strncpy(V1BYTE, pk, KAZ_DS_V1BYTES);
    //strncpy(V2BYTE, &pk[KAZ_DS_V1BYTES], KAZ_DS_V2BYTES);

    //mpz_set_str(V1, V1BYTE, 16);
    //mpz_set_str(V2, V2BYTE, 16);

    //3) Get signature=(S1, S2, m)
    //unsigned char *S1BYTE;
    //unsigned char *S2BYTE;

    //S1BYTE=(unsigned char *)calloc(KAZ_DS_S1BYTES, sizeof(unsigned char));
    //S2BYTE=(unsigned char *)calloc(KAZ_DS_S2BYTES, sizeof(unsigned char));

    //strncpy(S1BYTE, signature, KAZ_DS_S1BYTES);
    //strncpy(S2BYTE, &signature[KAZ_DS_S1BYTES], KAZ_DS_S2BYTES);

    //mpz_set_str(S1, S1BYTE, 16);
    //mpz_set_str(S2, S2BYTE, 16);

    int V1SIZE=0;
    for(int i=0; i<KAZ_DS_V1BYTES; i++){
        if((int)pk[i]==48) V1SIZE++;
        else break;
    }

    int V2SIZE=0;
    for(int i=KAZ_DS_V1BYTES; i<CRYPTO_PUBLICKEYBYTES; i++){
        if((int)pk[i]==48) V2SIZE++;
        else break;
    }

    unsigned char *V1BYTE=(unsigned char*) malloc((KAZ_DS_V1BYTES-V1SIZE)*sizeof(unsigned char));
    unsigned char *V2BYTE=(unsigned char*) malloc((KAZ_DS_V2BYTES-V2SIZE)*sizeof(unsigned char));

    for(int i=0; i<KAZ_DS_V1BYTES-V1SIZE; i++) V1BYTE[i]=0;
    for(int i=0; i<KAZ_DS_V2BYTES-V2SIZE; i++) V2BYTE[i]=0;

    for(int i=0; i<KAZ_DS_V1BYTES-V1SIZE; i++){V1BYTE[i]=pk[i+V1SIZE];}
    for(int i=0; i<KAZ_DS_V2BYTES-V2SIZE; i++){V2BYTE[i]=pk[i+KAZ_DS_V1BYTES+V2SIZE];}

    mpz_import(V1, KAZ_DS_V1BYTES-V1SIZE, 1, sizeof(char), 0, 0, V1BYTE);
    mpz_import(V2, KAZ_DS_V2BYTES-V2SIZE, 1, sizeof(char), 0, 0, V2BYTE);

    //gmp_printf("V1=%Zd\nV2=%Zd\n", V1, V2);
    //3) Get signature=(S1, S2, m)
    int S1SIZE=0;
    for(int i=0; i<KAZ_DS_S1BYTES; i++){
        if((int)signature[i]==48) S1SIZE++;
        else break;
    }

    int S2SIZE=0;
    for(int i=KAZ_DS_S1BYTES; i<KAZ_DS_S1BYTES+KAZ_DS_S2BYTES; i++){
        if((int)signature[i]==48) S2SIZE++;
        else break;
    }

    unsigned char *S1BYTE=(unsigned char*) malloc((KAZ_DS_S1BYTES-S1SIZE)*sizeof(unsigned char));
    unsigned char *S2BYTE=(unsigned char*) malloc((KAZ_DS_S2BYTES-S2SIZE)*sizeof(unsigned char));

    for(int i=0; i<KAZ_DS_S1BYTES-S1SIZE; i++) S1BYTE[i]=0;
    for(int i=0; i<KAZ_DS_S2BYTES-S2SIZE; i++) S2BYTE[i]=0;

    for(int i=0; i<KAZ_DS_S1BYTES-S1SIZE; i++){S1BYTE[i]=signature[i+S1SIZE];}
    for(int i=0; i<KAZ_DS_S2BYTES-S2SIZE; i++){S2BYTE[i]=signature[i+(KAZ_DS_S1BYTES+S2SIZE)];}

    mpz_import(S1, KAZ_DS_S1BYTES-S1SIZE, 1, sizeof(char), 0, 0, S1BYTE);
    mpz_import(S2, KAZ_DS_S2BYTES-S2SIZE, 1, sizeof(char), 0, 0, S2BYTE);

    //4) Compute the hash value of the message
    unsigned char buf[CRYPTO_BYTES]={0};
    HashMsg(m, mlen, buf);

    mpz_t mValue; mpz_init(mValue);
    mpz_import(mValue, mlen, 1, sizeof(char), 0, 0, m);
    mpz_import(hashValue, CRYPTO_BYTES, 1, sizeof(char), 0, 0, buf);

    //5) Filter 1
    mpz_gcd(GS1r, S1, GRg);
    mpz_mod(aF, V1, GRg);

    mpz_mul(q2, q, q);
    mpz_mul(GRgq2, GRg, q2);

    mpz_invert(S1inverse, S1, GRgq2);
    mpz_powm(tmp, V1, S1, GRgq2);   // V1^S1 mod GRgq^2
    mpz_add(tmp, tmp, hashValue);   // (V1^S1)+h mod GRgq^2
    mpz_mod(tmp, tmp, GRgq2);
    mpz_mul(tmp, tmp, GS1r);        // GS1r*((V1^S1)+h) mod GRgq^2
    mpz_mod(tmp, tmp, GRgq2);
    mpz_mul(tmp, tmp, S1inverse);   // GS1r*((V1^S1)+h)*S1^-1 mod GRgq^2
    mpz_mod(w0, tmp, GRgq2);

    mpz_sub(w1, w0, S2);

    if(mpz_cmp_ui(w1, 0)==0){
        //__android_log_print(ANDROID_LOG_WARN, "FILTER 1", "%s", "SANGKUT");
        return -4; //REJECT SIGNATURE
    }

    //6) Filter 2
    mpz_powm(tmp, aF, S1, GRgq2);   // aF^S1 mod GRgq^2
    mpz_add(tmp, tmp, hashValue);   // (aF^S1)+h mod GRgq^2
    mpz_mod(tmp, tmp, GRgq2);
    mpz_mul(tmp, tmp, GS1r);        // GS1r*((aF^S1)+h) mod GRgq^2
    mpz_mod(tmp, tmp, GRgq2);
    mpz_mul(tmp, tmp, S1inverse);   // GS1r*((aF^S1)+h)*S1^-1 mod GRgq^2
    mpz_mod(w2, tmp, GRgq2);

    mpz_sub(w3, w2, S2);

    if(mpz_cmp_ui(w3, 0)==0){
        //__android_log_print(ANDROID_LOG_WARN, "FILTER 2", "%s", "SANGKUT");
        return -4; //REJECT SIGNATURE
    }

    //7) Filter 3
    mpz_mul(tmp, S1, S2);           // S1*S1 mod q
    mpz_mod(w4, tmp, q);
    mpz_mul(tmp, GS1r, hashValue);  // GS1r*h mod q
    mpz_mod(tmp, tmp, q);
    mpz_sub(w4, w4, tmp);           // S1*S1-GS1r*h mod q
    mpz_mod(w4, w4, q);

    mpz_powm(w5, V1, S1, q);        // V1^S1 mod q
    mpz_mul(w5, w5, GS1r);          // GS1r*(V1^S1) mod q
    mpz_mod(w5, w5, q);

    mpz_sub(w6, w4, w5);

    if(mpz_cmp_ui(w6, 0)!=0){
        //__android_log_print(ANDROID_LOG_WARN, "FILTER 3", "%s", "SANGKUT");
        return -4; //REJECT SIGNATURE
    }

    //8) Filter 4
    mpz_divexact_ui(PHIQ2BETA2, phiq2o2, BETA*BETA);
    mpz_invert(w7, S1, PHIQ2BETA2);

    mpz_mul(w8, S1, S2);
    mpz_mod(w8, w8, q2);
    mpz_mul(tmp, GS1r, hashValue);
    mpz_mod(tmp, tmp, q2);
    mpz_sub(w8, w8, tmp);
    mpz_mod(w8, w8, q2);
    mpz_invert(tmp, GS1r, q2);
    mpz_mul(w8, w8, tmp);
    mpz_mod(w8, w8, q2);
    mpz_sub_ui(qsub1, q, 1);
    mpz_divexact(q0, qsub1, Q);
    mpz_mul(tmp, w7, q0);
    mpz_powm(w8, w8, tmp, q2);

    size_t W8SIZE=mpz_sizeinbase(w8, 16);

    unsigned char *W8BYTE=(unsigned char*) malloc(W8SIZE*sizeof(unsigned char));
    mpz_export(W8BYTE, &W8SIZE, 1, sizeof(char), 0, 0, w8);

    unsigned char bufw8[32]={0};
    HashMsg(W8BYTE, W8SIZE, bufw8);

    mpz_import(w8, 32, 1, sizeof(char), 0, 0, bufw8);

    mpz_sub(w9, w8, V2);

    if(mpz_cmp_ui(w9, 0)!=0){
        //__android_log_print(ANDROID_LOG_WARN, "FILTER 4", "%s", "SANGKUT");
        return -4; //REJECT SIGNATURE
    }

    //9) Verify signature
    mpz_mul(tmp, S1, S2);
    mpz_powm(z0, R, tmp, Gg);
    mpz_powm(y1, g, z0, N);

    mpz_powm(tmp, V1, S1, GRg);
    mpz_add(tmp, tmp, hashValue);
    mpz_mul(tmp, tmp, GS1r);
    mpz_mod(tmp, tmp, GRg);
    mpz_powm(z1, R, tmp, Gg);
    mpz_powm(y2, g, z1, N);

    if(mpz_cmp(y1, y2)==0){
        mpz_clears(N, g, Gg, R, GRg, q, Q, hashValue, V1, V2, S1, S2, GS1r, aF, q2, GRgq2, tmp, S1inverse, NULL);
        mpz_clears(w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, PHIQ2BETA2, qsub1, q0, y1, y2, z0, z1, phiq2o2, NULL);

        free(V1BYTE);
        free(V2BYTE);
        //free(S1BYTE);
        //free(S2BYTE);
        free(W8BYTE);

        return 0;
    }

    return -4;
}

void KAZ_DS_RANDOM(int lb,
                   int ub,
                   mpz_t out){
    mpz_t lbound, ubound;

    gmp_randstate_t gmpRandState;
    gmp_randinit_mt(gmpRandState);
    mpz_inits(lbound, ubound, NULL);

    mpz_ui_pow_ui(lbound, 2, lb);
    mpz_ui_pow_ui(ubound, 2, ub);

    unsigned int sd=100000;

    do{
        // initialize state for a Mersenne Twister algorithm. This algorithm is fast and has good randomness properties.

        //gmp_randseed_ui(gmpRandState, sd);
        gmp_randseed_ui(gmpRandState, rand()+sd);
        mpz_urandomb(out, gmpRandState, ub);
        sd+=1;
    }while((mpz_cmp(out, lbound) == -1) || (mpz_cmp(out, ubound) == 1));

    // empty the memory location for the random generator state
    //gmp_randclear(gmpRandState);
}
