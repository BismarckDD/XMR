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
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

extern "C"
{
    #include "c_groestl.h"
    #include "c_blake256.h"
    #include "c_jh.h"
    #include "c_skein.h"
}

#include "cryptonight.h"
#include "cryptonight_aesni.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef __GNUC__
#include <mm_malloc.h>
#else
#include <malloc.h>
#endif // __GNUC__

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#endif // _WIN32

void do_blake_hash(const void* input, size_t len, char* output)
{
    blake256_hash((uint8_t*)output, (const uint8_t*)input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output)
{
    groestl((const uint8_t*)input, len << 3, (uint8_t*)output);
}

void do_jh_hash(const void* input, size_t len, char* output)
{
    jh_hash(256 /*32 * 8*/, (const uint8_t*)input, len << 3, (uint8_t*)output);
}

void do_skein_hash(const void* input, size_t len, char* output)
{
    skein_hash(256 /*8 * 32*/, (const uint8_t*)input, len << 3, (uint8_t*)output);
}

void (* const extra_hashes[4])(const void *, size_t, char *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};

#ifdef _WIN32
BOOL AddPrivilege(TCHAR* pszPrivilege)
{
    HANDLE           hToken;
    TOKEN_PRIVILEGES tp;
    BOOL             status;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, pszPrivilege, &tp.Privileges[0].Luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    status = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    if (!status || (GetLastError() != ERROR_SUCCESS))
        return FALSE;

    CloseHandle(hToken);
    return TRUE;
}
#endif

size_t cryptonight_init(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg)
{
#ifdef _WIN32
    if (AddPrivilege(TEXT("SeLockMemoryPrivilege")) == 0)
    {
        msg->warning = "Obtaning SeLockMemoryPrivilege failed.";
        return 0;
    }
    return 1;
#else
    return 1;
#endif // _WIN32
}

cryptonight_ctx* cryptonight_alloc_ctx(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg)
{
    cryptonight_ctx* ptr = (cryptonight_ctx*)_mm_malloc(sizeof(cryptonight_ctx), 4096);

    if(use_fast_mem == 0)
    {
        // use 2MiB aligned memory
        ptr->long_state = (uint8_t*)_mm_malloc(MEMORY, 2*1024*1024);
        ptr->ctx_info[0] = 0;
        ptr->ctx_info[1] = 0;
        return ptr;
    }

#ifdef _WIN32
    SIZE_T iLargePageMin = GetLargePageMinimum();

    if(MEMORY > iLargePageMin)
        iLargePageMin <<= 1;

    ptr->long_state = (uint8_t*)VirtualAlloc(NULL, iLargePageMin,
        MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);

    if(ptr->long_state == NULL)
    {
        _mm_free(ptr);
        msg->warning = "VirtualAlloc failed.";
        return NULL;
    }
    else
    {
        ptr->ctx_info[0] = 1;
        return ptr;
    }
#else

#if defined(__APPLE__)
    ptr->long_state  = (uint8_t*)mmap(0, MEMORY, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, VM_FLAGS_SUPERPAGE_SIZE_2MB, 0);
#else
    ptr->long_state = (uint8_t*)mmap(0, MEMORY, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, 0, 0);
#endif

    if (ptr->long_state == MAP_FAILED)
    {
        _mm_free(ptr);
        msg->warning = "mmap failed";
        return NULL;
    }

    ptr->ctx_info[0] = 1;

    if(madvise(ptr->long_state, MEMORY, MADV_RANDOM|MADV_WILLNEED) != 0)
        msg->warning = "madvise failed";

    ptr->ctx_info[1] = 0;
    if(use_mlock != 0 && mlock(ptr->long_state, MEMORY) != 0)
        msg->warning = "mlock failed";
    else
        ptr->ctx_info[1] = 1;

    return ptr;
#endif // _WIN32
}

void cryptonight_free_ctx(cryptonight_ctx* ctx)
{
    if(ctx->ctx_info[0] != 0)
    {
#ifdef _WIN32
        VirtualFree(ctx->long_state, 0, MEM_RELEASE);
#else
        if(ctx->ctx_info[1] != 0)
            munlock(ctx->long_state, MEMORY);
        munmap(ctx->long_state, MEMORY);
#endif // _WIN32
    }
    else
        _mm_free(ctx->long_state);

    _mm_free(ctx);
}

void cn_explode_scratchpad(const xmr128i* input, xmr128i* output)
{
    // This is more than we have registers, compiler will assign 2 keys on the stack
    xmr128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    xmr128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = *(input + 4);
    xin1 = *(input + 5);
    xin2 = *(input + 6);
    xin3 = *(input + 7);
    xin4 = *(input + 8);
    xin5 = *(input + 9);
    xin6 = *(input + 10);
    xin7 = *(input + 11);

    for (size_t i = 0; i < ITER; i += 8)
    {
        soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);


        *(output + i + 0) = xin0;
        *(output + i + 1) = xin1;
        *(output + i + 2) = xin2;
        *(output + i + 3) = xin3;

        //if(PREFETCH)
        //    _mm_prefetch((const char*)output + i + 0, _MM_HINT_T2);

        *(output + i + 4) = xin4;
        *(output + i + 5) = xin5;
        *(output + i + 6) = xin6;
        *(output + i + 7) = xin7;

        //if(PREFETCH)
        //    _mm_prefetch((const char*)output + i + 4, _MM_HINT_T2);
    }
}

void cn_implode_scratchpad(const xmr128i* input, xmr128i* output)
{
    // This is more than we have registers, compiler will assign 2 keys on the stack
    xmr128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    xmr128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = *(output + 4);
    xout1 = *(output + 5);
    xout2 = *(output + 6);
    xout3 = *(output + 7);
    xout4 = *(output + 8);
    xout5 = *(output + 9);
    xout6 = *(output + 10);
    xout7 = *(output + 11);

    for (size_t i = 0; i < ITER; i += 8)
    {
        //if(PREFETCH)
        //    _mm_prefetch((const char*)input + i + 0, _MM_HINT_NTA);

        xout0 = xor_si128(*(input + i + 0), xout0);
        xout1 = xor_si128(*(input + i + 1), xout1);
        xout2 = xor_si128(*(input + i + 2), xout2);
        xout3 = xor_si128(*(input + i + 3), xout3);

        //if(PREFETCH)
        //    _mm_prefetch((const char*)input + i + 4, _MM_HINT_NTA);

        xout4 = xor_si128(*(input + i + 4), xout4);
        xout5 = xor_si128(*(input + i + 5), xout5);
        xout6 = xor_si128(*(input + i + 6), xout6);
        xout7 = xor_si128(*(input + i + 7), xout7);

        soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    }

    *(output + 4) = xout0;
    *(output + 5) = xout1;
    *(output + 6) = xout2;
    *(output + 7) = xout3;
    *(output + 8) = xout4;
    *(output + 9) = xout5;
    *(output + 10) = xout6;
    *(output + 11) = xout7;
}

void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0)
{
    keccak((const uint8_t *)input, len, ctx0->hash_state, 200);

    // Optim - 99% time boundary
    cn_explode_scratchpad((xmr128i*)ctx0->hash_state, (xmr128i*)ctx0->long_state);

    uint8_t* l0 = ctx0->long_state;
    uint64_t* h0 = (uint64_t*)ctx0->hash_state;

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    xmr128i bx0 = set_epi64(h0[3] ^ h0[7], h0[2] ^ h0[6]);

    uint64_t idx0 = h0[0] ^ h0[4];

    // Optim - 90% time boundary
    for (size_t i = 0; i < ITERATIONS; ++i)
    {
        xmr128i cx;
        cx = *((xmr128i *)&l0[idx0 & 0x1FFFF0]);
        cx = soft_aesenc(cx, set_epi64(ah0, al0));

        *((xmr128i *)&l0[idx0 & 0x1FFFF0]) = xor_si128(bx0, cx);
        idx0 = cvtsi128_si64(cx);
        bx0 = cx;

        //if(PREFETCH)
        //    _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
        ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

        lo = _umul128(idx0, cl, &hi);

        al0 += hi;
        ah0 += lo;
        ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = al0;
        ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = ah0;
        ah0 ^= ch;
        al0 ^= cl;
        idx0 = al0;

        //if(PREFETCH)
        //    _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);
    }

    // Optim - 90% time boundary
    cn_implode_scratchpad((xmr128i*)ctx0->long_state, (xmr128i*)ctx0->hash_state);

    // Optim - 99% time boundary

    keccakf((uint64_t*)ctx0->hash_state, 24);
    extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx* __restrict ctx0, cryptonight_ctx* __restrict ctx1)
{
    keccak((const uint8_t *)input, len, ctx0->hash_state, 200);
    keccak((const uint8_t *)input + len, len, ctx1->hash_state, 200);

    // Optim - 99% time boundary
    cn_explode_scratchpad((xmr128i*)ctx0->hash_state, (xmr128i*)ctx0->long_state);
    cn_explode_scratchpad((xmr128i*)ctx1->hash_state, (xmr128i*)ctx1->long_state);

    uint8_t* l0 = ctx0->long_state;
    uint64_t* h0 = (uint64_t*)ctx0->hash_state;
    uint8_t* l1 = ctx1->long_state;
    uint64_t* h1 = (uint64_t*)ctx1->hash_state;

    xmr128i ax0 = set_epi64(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    xmr128i bx0 = set_epi64(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    xmr128i ax1 = set_epi64(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    xmr128i bx1 = set_epi64(h1[3] ^ h1[7], h1[2] ^ h1[6]);

    uint64_t idx0 = h0[0] ^ h0[4];
    uint64_t idx1 = h1[0] ^ h1[4];

    // Optim - 90% time boundary
    for (size_t i = 0; i < ITERATIONS; i++)
    {
        xmr128i cx;
        cx = *((xmr128i *)&l0[idx0 & 0x1FFFF0]);
        cx = soft_aesenc(cx, ax0);

        *((xmr128i *)&l0[idx0 & 0x1FFFF0]) = xor_si128(bx0, cx);
        idx0 = cvtsi128_si64(cx);
        bx0 = cx;

        //if(PREFETCH)
        //    _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

        cx = *((xmr128i *)&l1[idx1 & 0x1FFFF0]);
        cx = soft_aesenc(cx, ax1);

        *((xmr128i *)&l1[idx1 & 0x1FFFF0]) = xor_si128(bx1, cx);
        idx1 = cvtsi128_si64(cx);
        bx1 = cx;

        //if(PREFETCH)
        //    _mm_prefetch((const char*)&l1[idx1 & 0x1FFFF0], _MM_HINT_T0);

        uint64_t hi, lo;
        cx = *((xmr128i *)&l0[idx0 & 0x1FFFF0]);

        lo = _umul128(idx0, cvtsi128_si64(cx), &hi);

        ax0 = add_epi64(ax0, set_epi64(lo, hi));
        *((xmr128i*)&l0[idx0 & 0x1FFFF0]) = ax0;
        ax0 = xor_si128(ax0, cx);
        idx0 = cvtsi128_si64(ax0);

        //if(PREFETCH)
        //    _mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

        cx = *((xmr128i *)&l1[idx1 & 0x1FFFF0]);

        lo = _umul128(idx1, cvtsi128_si64(cx), &hi);

        ax1 = add_epi64(ax1, set_epi64(lo, hi));
        *((xmr128i*)&l1[idx1 & 0x1FFFF0]) = ax1;
        ax1 = xor_si128(ax1, cx);
        idx1 = cvtsi128_si64(ax1);

        //if(PREFETCH)
        //    _mm_prefetch((const char*)&l1[idx1 & 0x1FFFF0], _MM_HINT_T0);
    }

    // Optim - 90% time boundary
    cn_implode_scratchpad((xmr128i*)ctx0->long_state, (xmr128i*)ctx0->hash_state);
    cn_implode_scratchpad((xmr128i*)ctx1->long_state, (xmr128i*)ctx1->hash_state);

    // Optim - 99% time boundary

    keccakf((uint64_t*)ctx0->hash_state, 24);
    extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
    keccakf((uint64_t*)ctx1->hash_state, 24);
    extra_hashes[ctx1->hash_state[0] & 3](ctx1->hash_state, 200, (char*)output + 32);
}

