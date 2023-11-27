#ifndef FILE_H_INCLUDED
#define FILE_H_INCLUDED
#include "gmp.h"

#define KAZ_DS_SP_J             180
#define KAZ_DS_SP_K             128

#define KAZ_DS_SP_N             "16654099924025690560880991628826166333626342440673565018885011847989446\
                                 73390411604901732676624210376510769252181354174828223286340057028944019\
                                 91339669414651118456372695070769619863131971414241586048862803140660472\
                                 06653222207353469933659597534156792443205461406819169388949586947835045\
                                 09315984550444746877596669802184487731229941008215513808488975493742420\
                                 95332359872258964174269418980707061566230310986271334632962653419873630\
                                 52884725941333218996085207555"

#define KAZ_DS_SP_G             "6007"

#define KAZ_DS_SP_Gg            "66425249147392035103359575563682919206231140688573787652572381678879876\
                                 350990985890249087277450456295776000"

#define KAZ_DS_SP_nPHIGg        352

#define KAZ_DS_SP_R             "6151"

#define KAZ_DS_SP_GRg           "964284630129748924872876000"

#define KAZ_DS_SP_q             "484951683103685348549656983165341722603"

#define KAZ_DS_SP_Q             "26941760172426963808314276842518984589"

#define KAZ_DS_SP_PHIQ2         "23517813494509725757394617762133412675478302525134411018676400174816205\
                                 9373006"

#define KAZ_DS_SP_BETA          3

#define KAZ_DS_ALPHABYTES       45
#define KAZ_DS_V1BYTES          29
#define KAZ_DS_V2BYTES          33
#define KAZ_DS_S1BYTES          45
#define KAZ_DS_S2BYTES          45

#define CRYPTO_SECRETKEYBYTES 45
#define CRYPTO_PUBLICKEYBYTES 62
#define CRYPTO_BYTES 32

/*extern void KAZ_DS_OrderBase(mpz_t Modular,
                             mpz_t FiModular,
                             mpz_t Base,
                             mpz_t OrderBase);
extern int KAZ_DS_GET_PFactors(mpz_t input);
extern void KAZ_DS_PFactors(mpz_t ord,
                            mpz_t *pfacs,
                            int *qlist,
                            int *elist);
extern void KAZ_DS_CRT(mpz_t product_of_modulus,
                       mpz_t *moduluss,
                       mpz_t *candidate,
                       int no_of_elements,
                       mpz_t crt);
extern char* KAZ_DS_MLOG(mpz_t Modular,
                        mpz_t OrderBase,
                        mpz_t Base,
                        mpz_t Target,
                        mpz_t *pfactors,
                        int *qlist,
                        int *elist,
                        int saiz,
                        mpz_t kaz_crt); */
void KAZ_DS_KeyGen(unsigned char *kaz_ds_verify_key,
                          unsigned char *kaz_ds_sign_key);

int KAZ_DS_SIGNATURE(unsigned char *signature,
                             size_t *signlen,
                             const unsigned char *m,
                             size_t mlen,
                             const unsigned char *kaz_ds_sign_key);
int KAZ_DS_VERIFICATION(unsigned char *signature,
                               size_t signature_len,
                               const unsigned char *m,
                               size_t mlen,
                               const unsigned char *pk);
extern void KAZ_DS_RANDOM(int lb,
                          int ub,
                          mpz_t out);


#endif // FILE_H_INCLUDED
