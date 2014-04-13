#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

extern void curve25519_donna(unsigned char *output, const unsigned char *a,
                             const unsigned char *b);

unsigned char basepoint[32] = {9};


MODULE = Crypt::Curve25519		PACKAGE = Crypt::Curve25519		

void curve25519_secret_key(sk)
    SV *sk
    PROTOTYPE: $
    INIT:
        int i;
        unsigned char masked[32];
        STRLEN l;
        unsigned char *csk;
    PPCODE:
    {
        csk = SvPV(sk, l);

        if ( l != 32 ) croak("Secret key requires 32 bytes");

        for ( i = 0; i < 32; i++ ) masked[i] = csk[i];
        masked[0] &= 248;
        masked[31] &= 127;
        masked[31] |= 64;

        mXPUSHp(masked, 32);
    }

void curve25519_public_key(sk, ...)
    SV *sk
    ALIAS:
        curve25519_shared_secret = 1
    PROTOTYPE: $;$
    INIT:
        unsigned char OUT[32];
        unsigned char *bp;
        STRLEN l;
        unsigned char *msk;
    PPCODE:
    {
        msk = SvPV(sk, l);

        if ( l != 32 ) croak("Secret key requires 32 bytes");

        if ( ix == 1 && items != 2 ) croak("Calculating shared secret requires public key");

        /* ST(1) is a basepoint:
         * his public key
         * or
         * custom one used to generate public key
         */
        if ( ix == 1 || items == 2 ) {

            bp = SvPV(ST(1), l);

            if ( l != 32 ) {
                if ( ix == 1 ) croak("Public key requires 32 bytes");
                else croak("Basepoint requires 32 bytes");
            }
        } else {
            bp = basepoint;
        }

        curve25519_donna(OUT, msk, bp);

        mXPUSHp(OUT, 32);
    }

