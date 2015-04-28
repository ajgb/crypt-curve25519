#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#if USE_X64
#include "curve25519-donna-c64.c"
#else
#include "curve25519-donna.c"
#endif

unsigned char basepoint[32] = {9};

MODULE = Crypt::Curve25519		PACKAGE = Crypt::Curve25519		

void curve25519(sk, ...)
    SV *sk
    ALIAS:
        curve25519_public_key = 1
        curve25519_shared_secret = 2
    PROTOTYPE: $;$
    INIT:
        unsigned char OUT[32];
        unsigned char *bp;
        STRLEN l;
        unsigned char *csk;
    PPCODE:
    {
        csk = SvPV(sk, l);

        if ( l != 32 ) croak("Secret key requires 32 bytes");

        if ( ix == 0 && items != 2 ) croak("Using primitive function requires two arguments");

        if ( ix == 2 && items != 2 ) croak("Calculating shared secret requires public key");

        /* ST(1) is a basepoint:
         * his public key
         * or
         * custom one used to generate public key
         */
        if ( ix == 2 || items == 2 ) {

            bp = SvPV(ST(1), l);

            if ( l != 32 ) {
                if ( ix == 2 ) croak("Public key requires 32 bytes");
                else croak("Basepoint requires 32 bytes");
            }
        } else {
            bp = basepoint;
        }

        curve25519_donna(OUT, csk, bp);

        mXPUSHp(OUT, 32);
    }

