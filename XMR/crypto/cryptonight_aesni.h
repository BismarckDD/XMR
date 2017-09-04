/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
#pragma once

#include "cryptonight.h"
#include <memory.h>
#include <stdio.h>
#include "self.h"

#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

extern "C"
{
    void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
    void keccakf(uint64_t st[25], int rounds);
    extern void(*const extra_hashes[4])(const void *, size_t, char *);

    xmr128i soft_aesenc(xmr128i in, xmr128i key);
    xmr128i soft_aeskeygenassist(xmr128i key, uint8_t rcon);
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline xmr128i sl_xor(xmr128i tmp1)
{
    xmr128i tmp4;
    tmp4 = slli_si128(tmp1, 0x04);
    tmp1 = xor_si128(tmp1, tmp4);
    tmp4 = slli_si128(tmp4, 0x04);
    tmp1 = xor_si128(tmp1, tmp4);
    tmp4 = slli_si128(tmp4, 0x04);
    tmp1 = xor_si128(tmp1, tmp4);
    return tmp1;
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline void soft_aes_genkey_sub(xmr128i* xout0, xmr128i* xout2, uint8_t rcon)
{
    xmr128i xout1 = soft_aeskeygenassist(*xout2, rcon);
    xout1 = shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = xor_si128(*xout0, xout1);
    xout1 = soft_aeskeygenassist(*xout0, 0x00);
    xout1 = shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = xor_si128(*xout2, xout1);
}

static inline void aes_genkey(const xmr128i* memory, xmr128i* k0, xmr128i* k1, xmr128i* k2, xmr128i* k3,
    xmr128i* k4, xmr128i* k5, xmr128i* k6, xmr128i* k7, xmr128i* k8, xmr128i* k9)
{
    xmr128i xout0, xout2;

    xout0 = *(memory);
    xout2 = *(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    soft_aes_genkey_sub(&xout0, &xout2, 0x01);
    *k2 = xout0;
    *k3 = xout2;

    soft_aes_genkey_sub(&xout0, &xout2, 0x02);
    *k4 = xout0;
    *k5 = xout2;

    soft_aes_genkey_sub(&xout0, &xout2, 0x04);
    *k6 = xout0;
    *k7 = xout2;

    soft_aes_genkey_sub(&xout0, &xout2, 0x08);
    *k8 = xout0;
    *k9 = xout2;
}

static inline void soft_aes_round(xmr128i key, xmr128i* x0, xmr128i* x1, xmr128i* x2, xmr128i* x3, xmr128i* x4, xmr128i* x5, xmr128i* x6, xmr128i* x7)
{
    *x0 = soft_aesenc(*x0, key);
    *x1 = soft_aesenc(*x1, key);
    *x2 = soft_aesenc(*x2, key);
    *x3 = soft_aesenc(*x3, key);
    *x4 = soft_aesenc(*x4, key);
    *x5 = soft_aesenc(*x5, key);
    *x6 = soft_aesenc(*x6, key);
    *x7 = soft_aesenc(*x7, key);
}

void cn_explode_scratchpad(const xmr128i* input, xmr128i* output);
void cn_implode_scratchpad(const xmr128i* input, xmr128i* output);
void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0);
void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx* __restrict ctx0, cryptonight_ctx* __restrict ctx1);
