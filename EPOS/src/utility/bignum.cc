// EPOS (Litte-endian) Big Numbers Utility Implementation

#include <utility/bignum.h>

__BEGIN_UTIL

// Class attributes
template<>
/*const*/ Bignum<16>::_Word Bignum<16>::_mod = {{ 0xff, 0xff, 0xff, 0xff,
                                              0xff, 0xff, 0xff, 0xff,
                                              0xff, 0xff, 0xff, 0xff,
                                              0xfd, 0xff, 0xff, 0xff }};

template<>
const Bignum<16>::_Barrett Bignum<16>::_barrett_u = {{ 17, 0, 0, 0,
                                                        8, 0, 0, 0,
                                                        4, 0, 0, 0,
                                                        2, 0, 0, 0,
                                                        1, 0, 0, 0}};

template<>
/*const*/ Bignum<16>::_Word Bignum<16>::_order = {{ 0x15, 0xa1, 0x38, 0x90,
                                                0x1b, 0x0d, 0xa3, 0x75,
                                                0x00, 0x00, 0x00, 0x00,
                                                0xfe, 0xff, 0xff, 0xff }};


// 2^(130) - 5: used by Poly1305
template<>
/*const*/ Bignum<17>::_Word Bignum<17>::_mod = {{ 0x15, 0xa1, 0x38, 0x90,
                                              0x1b, 0x0d, 0xa3, 0x75,
                                              0x00, 0x00, 0x00, 0x00,
                                              0xfe, 0xff, 0xff, 0xff,
                                              0x00, 0x00, 0x00, 0x00 }};

// 0x400000000000000000000000000000005000000000000000
template<>
const Bignum<17>::_Barrett Bignum<17>::_barrett_u = {{ 0x87, 0x2a, 0x3b, 0x99,
                                                       0xea, 0xf2, 0x5c, 0x8a,
                                                       0x03, 0x00, 0x00, 0x00,
                                                       0x02, 0x00, 0x00, 0x00,
                                                       0x01, 0x00, 0x00, 0x00 }};
__END_UTIL
