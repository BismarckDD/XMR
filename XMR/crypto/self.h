#pragma once

typedef union 
__declspec(align(16)) 
xmr128i {
    __int8              m128i_i8[16];
    __int16             m128i_i16[8];
    __int32             m128i_i32[4];
    __int64             m128i_i64[2];
    unsigned __int8     m128i_u8[16];
    unsigned __int16    m128i_u16[8];
    unsigned __int32    m128i_u32[4];
    unsigned __int64    m128i_u64[2];
} xmr128i;

#ifdef __cplusplus
extern "C"
{
#endif
    xmr128i add_epi64(xmr128i p_in1, xmr128i p_in2);    //
    __int64 cvtsi128_si64(xmr128i p_in);                //
    int     cvtsi128_si32(xmr128i p_in);                //
    xmr128i set_epi64(__int64 i1, __int64 i0);          //
    xmr128i set_epi32(int i3, int i2, int i1, int i0);  //
    xmr128i shuffle_epi32(xmr128i p_in, int imm);       //
    xmr128i xor_si128(xmr128i p_xor1, xmr128i p_xor2);  //
    xmr128i slli_si128(xmr128i p_in, int imm);          //

#ifdef __cplusplus
}
#endif