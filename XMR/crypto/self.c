#pragma once

#include "self.h"

xmr128i add_epi64(xmr128i p_in1, xmr128i p_in2)
{
    xmr128i temp;
    temp.m128i_i64[0] = p_in1.m128i_i64[0] + p_in2.m128i_i64[0];
    temp.m128i_i64[1] = p_in1.m128i_i64[1] + p_in2.m128i_i64[1];
    return temp;
}

__int64 cvtsi128_si64(xmr128i p_in)
{
    return p_in.m128i_i64[0];
}

int cvtsi128_si32(xmr128i p_in)
{
    return p_in.m128i_i32[0];
}

xmr128i set_epi64(__int64 i1, __int64 i0)
{
    xmr128i temp;
    temp.m128i_i64[1] = i1;
    temp.m128i_i64[0] = i0;
    return temp;
}

xmr128i set_epi32(int i3, int i2, int i1, int i0)
{
    xmr128i temp;
    temp.m128i_i32[3] = i3;
    temp.m128i_i32[2] = i2;
    temp.m128i_i32[1] = i1;
    temp.m128i_i32[0] = i0;
    return temp;
}

xmr128i shuffle_epi32(xmr128i p_in, int imm)
{
    xmr128i temp;
    temp.m128i_u32[3] = p_in.m128i_u32[(imm >> 6) & 0x3];
    temp.m128i_u32[2] = p_in.m128i_u32[(imm >> 4) & 0x3];
    temp.m128i_u32[1] = p_in.m128i_u32[(imm >> 2) & 0x3];
    temp.m128i_u32[0] = p_in.m128i_u32[(imm >> 0) & 0x3];
    return temp;
}

xmr128i xor_si128(xmr128i p_xor1, xmr128i p_xor2)
{
    xmr128i temp;
    temp.m128i_u64[0] = p_xor1.m128i_u64[0] ^ p_xor2.m128i_u64[0];
    temp.m128i_u64[1] = p_xor1.m128i_u64[1] ^ p_xor2.m128i_u64[1];
    return temp;
}

xmr128i slli_si128(xmr128i p_in, int imm)
{
    xmr128i temp;
    temp.m128i_u64[1] = p_in.m128i_u64[1] << (imm << 3);
    temp.m128i_u64[1] |= p_in.m128i_u64[0] >> (64 - (imm << 3));
    temp.m128i_u64[0] = p_in.m128i_u64[0] << (imm << 3);
    return temp;
}