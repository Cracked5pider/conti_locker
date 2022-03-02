#ifndef CHACHA_H
#define CHACHA_H

#ifdef __cplusplus

extern "C" {

#endif

#include <stdint.h>

#define CHACHA_BLOCKLENGTH 64

    typedef struct {
        uint32_t input[16];
    } chacha_ctx;

    void chacha_keysetup(chacha_ctx*, const uint8_t* k, uint32_t kbits);
    void chacha_ivsetup(chacha_ctx*, const uint8_t* iv);
    void chacha_encrypt(chacha_ctx*, const uint8_t* m, uint8_t* c, uint32_t bytes);

#ifdef __cplusplus 

}
#endif

#endif /* CHACHA_H */