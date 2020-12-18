/**********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: hash to FourQ
***********************************************************************************/ 

#include "apsi/fourq/FourQ_internal.h"
#include "apsi/fourq/FourQ_params.h"
#include <string.h>


static digit_t fpeq1271(digit_t* a, digit_t* b)
{ // Constant-time comparison of two field elements, ai=bi? : (0) equal, (-1) unequal
    digit_t c = 0;

    for (unsigned int i = 0; i < NWORDS_FIELD; i++)
        c |= a[i] ^ b[i];
    
    return (digit_t)((-(sdigit_t)(c >> 1) | -(sdigit_t)(c & 1)) >> (8*sizeof(digit_t) - 1)); 
}   


static void fpselect(digit_t* a, digit_t* b, digit_t* c, digit_t selector)
{ // Constant-time selection of field elements
  // If selector = 0 do c <- a, else if selector =-1 do a <- a

    for (unsigned int i = 0; i < NWORDS_FIELD; i++)
        c[i] = (selector & (a[i] ^ b[i])) ^ a[i]; 
}           


static inline void fpsqrt1271(felm_t in, felm_t out)
{
    fpsqr1271(in, out);
    for (unsigned int i = 1; i < 125; i++)
        fpsqr1271(out, out);
}


ECCRYPTO_STATUS HashToCurve(f2elm_t r, point_t out)
{
    digit_t *r0 = (digit_t*)r[0], *r1 = (digit_t*)r[1];
    felm_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, tt0, tt1, tt2, tt3, tt4;
    felm_t one = {0};
    one[0] = 1;

    digit_t* x0 = (digit_t*)out->x[0];
    digit_t* x1 = (digit_t*)out->x[1];
    digit_t* y0 = (digit_t*)out->y[0];
    digit_t* y1 = (digit_t*)out->y[1];
    digit_t selector;

    fpsqr1271(r0, t1);
    fpsqr1271(r1, t2);
    fpsub1271(t1, t2, t0);
    fpadd1271(t1, t2, t1);
    fpmul1271(r0, r1, t2);

    fpadd1271(t2, t2, t3);
    fpadd1271(t3, t3, t3);
    fpadd1271(t0, t3, t3);

    fpsub1271(t0, t2, t2);
    fpadd1271(t2, t2, t2);
    fpsqr1271(t2, t0);

    fpsqr1271(t3, t4);
    fpadd1271(t4, t0, t4);
    fpadd1271(t4, t2, t4);
    fpadd1271(t4, t2, t4);
    fpadd1271(t4, one, t4);
    fpinv1271(t4);

    fpmul1271(A1, t3, t0);
    fpadd1271(t0, A0, t0);
    fpmul1271(A0, t2, t5);
    fpadd1271(t0, t5, t0);
    fpmul1271(t4, t0, t0);
    fpneg1271(t0);

    fpmul1271(A0, t3, t5);
    fpsub1271(t5, A1, t5);
    fpmul1271(A1, t2, t6);
    fpsub1271(t5, t6, t5);
    fpmul1271(t4, t5, t5);
    fpadd1271(t0, t5, t4);

    fpsub1271(t0, t5, t6);
    fpmul1271(t4, t6, t4);
    fpadd1271(t4, one, t4);
    fpmul1271(A1, t5, t6);
    fpsub1271(t4, t6, t4);
    fpmul1271(A0, t0, t6);
    fpadd1271(t6, t4, t4);
    fpmul1271(t0, t5, t6);
    fpadd1271(t6, t6, t6);
    fpmul1271(A1, t0, t7);
    fpadd1271(t6, t7, t6);
    fpmul1271(A0, t5, t7);
    fpadd1271(t7, t6, t6);
    fpmul1271(t4, t0, t7);
    fpmul1271(t6, t5, t8);
    fpsub1271(t7, t8, t7);
    fpmul1271(t6, t0, t6);
    fpmul1271(t4, t5, t8);
    fpadd1271(t8, t6, t8);
    fpsqr1271(t7, t4);
    fpsqr1271(t8, t6);
    fpadd1271(t4, t6, t4);
    fpsqrt1271(t4, t6);
    fpsqr1271(t6, t9);
    
    fpcopy1271(t0, tt0);
    fpcopy1271(t5, tt1);
    fpcopy1271(t6, tt2);
    fpcopy1271(t7, tt3);
    fpcopy1271(t8, tt4);

    selector = fpeq1271(t9, t4);

    fpadd1271(t0, A0, t0);
    fpneg1271(t0);
    fpadd1271(t5, A1, t5);
    fpneg1271(t5);
    fpcopy1271(t7, t9);
    fpmul1271(t2, t7, t7);
    fpmul1271(t8, t2, t2);
    fpmul1271(t8, t3, t8);
    fpsub1271(t7, t8, t7);
    fpmul1271(t3, t9, t8);
    fpadd1271(t8, t2, t8);
    fpmul1271(t1, t6, t6);
    fpmul1271(c0, t6, t6);
    
    fpselect(tt0, t0, t0, selector);
    fpselect(tt1, t5, t5, selector);
    fpselect(tt2, t6, t6, selector);
    fpselect(tt3, t7, t7, selector);
    fpselect(tt4, t8, t8, selector);

    fpadd1271(t7, t6, t7);
    fpdiv1271(t7);
    fpsqrt1271(t7, t6);
    fpmul1271(b0, t0, t2);
    fpmul1271(b1, t5, t4);
    fpsub1271(t2, t4, t2);
    fpmul1271(t2, t6, t2);
    fpadd1271(t2, t2, t2);
    fpmul1271(b0, t5, t3);
    fpmul1271(b1, t0, t4);
    fpadd1271(t3, t4, t3);
    fpmul1271(t3, t6, t3);
    fpadd1271(t3, t3, t3);
    fpsqr1271(t6, t1);
    fpadd1271(t1, t1, t6);
    fpmul1271(t2, t6, t4);
    fpmul1271(t3, t6, t9);
    fpmul1271(t3, t8, t3);
    fpmul1271(t2, t8, t2);
    
    selector = fpeq1271(t1, t7);
    fpselect(t4, t9, tt0, selector);
    fpselect(t3, t2, tt1, selector);
    fpselect(t9, t3, tt2, selector);
    fpselect(t2, t4, tt3, selector);

    fpadd1271(tt0, tt1, x0);
    fpsub1271(tt2, tt3, x1);

    fpsqr1271(t6, t6);
    fpsqr1271(t8, t8);
    fpadd1271(t6, t8, t6);
    fpadd1271(t5, t5, y1);
    fpsqr1271(t5, t5);
    fpsqr1271(t0, t8);
    fpadd1271(t8, t5, t8);
    fpsub1271(t8, one, y0);
    fpadd1271(t0, t0, t0);
    fpadd1271(t0, t8, t0);
    fpadd1271(t0, one, t0);
    fpmul1271(t0, t6, t1);
    fpinv1271(t1);
    fpmul1271(t0, t1, t7);
    fpmul1271(t6, t1, t0);
    fpmul1271(x0, t7, x0);
    fpmul1271(x1, t7, x1);
    fpmul1271(y0, t0, y0);
    fpmul1271(y1, t0, y1);

    // Clear cofactor
    point_extproj_t P;
    point_setup(out, P);
    cofactor_clearing(P);
    eccnorm(P, out);

    return ECCRYPTO_SUCCESS;
}
