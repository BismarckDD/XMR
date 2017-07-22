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

#include <assert.h>
#include <cmath>
#include <chrono>
#include <thread>
#include <bitset>
#include "console.h"

#ifdef _WIN32
#include <windows.h>

void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
    SetThreadAffinityMask(h, 1ULL << cpu_id);
}
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"
#endif

void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
#if defined(__APPLE__)
    thread_port_t mach_thread;
    thread_affinity_policy_data_t policy = { cpu_id };
    mach_thread = pthread_mach_thread_np(h);
    thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1);
#else
    cpu_set_t mn;
    CPU_ZERO(&mn);
    CPU_SET(cpu_id, &mn);
    pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn);
#endif
}
#endif // _WIN32

#include "Executor.h"
#include "MineThread.h"
#include "jconf.h"
#include "crypto/cryptonight_aesni.h"

Telemetry::Telemetry(size_t p_iThread) :m_iThread(p_iThread)
{
    m_ppHashCounts = new uint64_t*[m_iThread];
    m_ppTimeStamps = new uint64_t*[m_iThread];
    m_piBucketTop = new uint32_t[m_iThread];

    for (size_t i = 0; i < m_iThread; ++i)
    {
        m_ppHashCounts[i] = new uint64_t[s_iBucketSize];
        m_ppTimeStamps[i] = new uint64_t[s_iBucketSize];
        m_piBucketTop[i] = 0;
        memset(m_ppHashCounts[0], 0, sizeof(uint64_t) * s_iBucketSize);
        memset(m_ppTimeStamps[0], 0, sizeof(uint64_t) * s_iBucketSize);
    }
}

Telemetry::~Telemetry()
{
    for (size_t i = 0; i < m_iThread; ++i)
    {
        if (m_ppHashCounts[i]) delete[] m_ppHashCounts[i];
        if (m_ppTimeStamps[i]) delete[] m_ppTimeStamps[i];
        // m_piBucketTop[i] = 0;
    }
    if (m_ppHashCounts) delete[] m_ppHashCounts;
    if (m_ppTimeStamps) delete[] m_ppTimeStamps;
    if (m_piBucketTop) delete[] m_piBucketTop;
}

double Telemetry::calc_telemetry_data(size_t iLastMilisec, size_t iThread)
{
    using namespace std::chrono;
    uint64_t iTimeNow = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();

    
    uint64_t iEarliestTimeStamp = 0;
    uint64_t iLastestTimeStamp = 0;
    uint64_t iEarliestHashCount = 0;
    uint64_t iLastestHashCount = 0;
    bool bHaveFullSet = false;

    //Start at 1, BucketTop points to next empty
    for (size_t i = 1; i < s_iBucketSize; ++i)
    {
        size_t idx = (m_piBucketTop[iThread] - i) & s_iBucketMask; //overflow expected here

        if (m_ppTimeStamps[iThread][idx] == 0)
            break; //That means we don't have the data yet

        if (iLastestTimeStamp == 0)
        {
            iLastestTimeStamp = m_ppTimeStamps[iThread][idx];
            iLastestHashCount = m_ppHashCounts[iThread][idx];
        }

        if (iTimeNow - m_ppTimeStamps[iThread][idx] > iLastMilisec)
        {
            bHaveFullSet = true;
            break; //We are out of the requested time period
        }

        iEarliestTimeStamp = m_ppTimeStamps[iThread][idx];
        iEarliestHashCount = m_ppHashCounts[iThread][idx];
    }

    if (!bHaveFullSet || iEarliestTimeStamp == 0 || iLastestTimeStamp == 0)
        return nan("");

    //Don't think that can happen, but just in case
    if (iLastestTimeStamp - iEarliestTimeStamp == 0)
        return nan("");

    double fHashes, fTime;
    fHashes = (double)(iLastestHashCount - iEarliestHashCount);
    fTime = (double)(iLastestTimeStamp - iEarliestTimeStamp);
    fTime /= 1000.0;

    return fHashes / fTime;
}

void Telemetry::push_perf_value(size_t p_iThread, uint64_t p_iHashCount, uint64_t p_iTimestamp)
{
    size_t iTop = m_piBucketTop[p_iThread];
    m_ppHashCounts[p_iThread][iTop] = p_iHashCount;
    m_ppTimeStamps[p_iThread][iTop] = p_iTimestamp;
    m_piBucketTop[p_iThread] = (iTop + 1) & s_iBucketMask;
}

MineThread::MineThread(MinerWork& p_rMinerWork, size_t p_iThreadNo, bool p_bDoubleWork, bool p_bNoPrefetch)
{
    m_oMinerWork = p_rMinerWork;
    m_bQuit = 0;
    m_iThreadNo = (uint8_t)p_iThreadNo;
    m_iJobNo = 0;
    m_iHashCount = 0;
    m_iTimestamp = 0;
    m_bNoPrefetch = p_bNoPrefetch;

    if(p_bDoubleWork)
        m_oWorkThread = std::thread(&MineThread::double_work_main, this);
    else
        m_oWorkThread = std::thread(&MineThread::work_main, this);
}

std::atomic<uint64_t> MineThread::s_iGlobalJobNo;
std::atomic<uint64_t> MineThread::s_iConsumeCnt; //Threads get jobs as they are initialized
MineThread::MinerWork MineThread::s_oGlobalMinerWork;
uint64_t MineThread::s_iThreadCount = 0;

cryptonight_ctx* minethd_alloc_ctx()
{
    cryptonight_ctx* ctx;
    alloc_msg msg = { 0 };

    switch (jconf::inst()->GetSlowMemSetting())
    {
    case jconf::never_use:
        ctx = cryptonight_alloc_ctx(1, 1, &msg);
        if (ctx == NULL)
            printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
        return ctx;

    case jconf::no_mlck:
        ctx = cryptonight_alloc_ctx(1, 0, &msg);
        if (ctx == NULL)
            printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
        return ctx;

    case jconf::print_warning:
        ctx = cryptonight_alloc_ctx(1, 1, &msg);
        if (msg.warning != NULL)
            printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
        if (ctx == NULL)
            ctx = cryptonight_alloc_ctx(0, 0, NULL);
        return ctx;

    case jconf::always_use:
        return cryptonight_alloc_ctx(0, 0, NULL);

    case jconf::unknown_value:
        return NULL; //Shut up compiler
    }

    return nullptr; //Should never happen
}

bool MineThread::self_test()
{
    alloc_msg msg = { 0 };
    size_t res;
    bool fatal = false;

    switch (jconf::inst()->GetSlowMemSetting())
    {
    case jconf::never_use:
        res = cryptonight_init(1, 1, &msg);
        fatal = true;
        break;

    case jconf::no_mlck:
        res = cryptonight_init(1, 0, &msg);
        fatal = true;
        break;

    case jconf::print_warning:
        res = cryptonight_init(1, 1, &msg);
        break;

    case jconf::always_use:
        res = cryptonight_init(0, 0, &msg);
        break;

    case jconf::unknown_value:
    default:
        return false; //Shut up compiler
    }

    if(msg.warning != nullptr)
        printer::inst()->print_msg(L0, "MEMORY INIT ERROR: %s", msg.warning);

    if(res == 0 && fatal)
        return false;

    cryptonight_ctx *ctx0, *ctx1;
    if((ctx0 = minethd_alloc_ctx()) == nullptr)
        return false;

    if((ctx1 = minethd_alloc_ctx()) == nullptr)
    {
        cryptonight_free_ctx(ctx0);
        return false;
    }

    unsigned char out[64];
    bool bResult;

    cn_hash_fun hashf;
    cn_hash_fun_dbl hashdf;

    hashf = func_selector(jconf::inst()->HaveHardwareAes(), false);
    hashf("This is a test", 14, out, ctx0);
    bResult = memcmp(out, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

    hashf = func_selector(jconf::inst()->HaveHardwareAes(), true);
    hashf("This is a test", 14, out, ctx0);
    bResult &= memcmp(out, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

    hashdf = func_dbl_selector(jconf::inst()->HaveHardwareAes(), false);
    hashdf("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy log", 43, out, ctx0, ctx1);
    bResult &= memcmp(out, "\x3e\xbb\x7f\x9f\x7d\x27\x3d\x7c\x31\x8d\x86\x94\x77\x55\x0c\xc8\x00\xcf\xb1\x1b\x0c\xad\xb7\xff\xbd\xf6\xf8\x9f\x3a\x47\x1c\x59"
                           "\xb4\x77\xd5\x02\xe4\xd8\x48\x7f\x42\xdf\xe3\x8e\xed\x73\x81\x7a\xda\x91\xb7\xe2\x63\xd2\x91\x71\xb6\x5c\x44\x3a\x01\x2a\x41\x22", 64) == 0;

    hashdf = func_dbl_selector(jconf::inst()->HaveHardwareAes(), true);
    hashdf("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy log", 43, out, ctx0, ctx1);
    bResult &= memcmp(out, "\x3e\xbb\x7f\x9f\x7d\x27\x3d\x7c\x31\x8d\x86\x94\x77\x55\x0c\xc8\x00\xcf\xb1\x1b\x0c\xad\xb7\xff\xbd\xf6\xf8\x9f\x3a\x47\x1c\x59"
                           "\xb4\x77\xd5\x02\xe4\xd8\x48\x7f\x42\xdf\xe3\x8e\xed\x73\x81\x7a\xda\x91\xb7\xe2\x63\xd2\x91\x71\xb6\x5c\x44\x3a\x01\x2a\x41\x22", 64) == 0;

    cryptonight_free_ctx(ctx0);
    cryptonight_free_ctx(ctx1);

    if(!bResult)
        printer::inst()->print_msg(L0,
            "Cryptonight hash self-test failed. This might be caused by bad compiler optimizations.");

    return bResult;
}

std::vector<MineThread*>* MineThread::thread_starter(MinerWork& pWork)
{
    s_iGlobalJobNo = 0;
    s_iConsumeCnt = 0;
    std::vector<MineThread*>* m_pvThreads = new std::vector<MineThread*>;

    //Launch the requested number of single and double threads, to distribute
    //load evenly we need to alternate single and double threads
    size_t i, n = jconf::inst()->GetThreadCount();
    m_pvThreads->reserve(n);

    jconf::thd_cfg cfg;
    for (i = 0; i < n; i++)
    {
        jconf::inst()->GetThreadConfig(i, cfg);

        MineThread* thd = new MineThread(pWork, i, cfg.bDoubleMode, cfg.bNoPrefetch);

        if(cfg.iCpuAff >= 0)
        {
#if defined(__APPLE__)
            printer::inst()->print_msg(L1, "WARNING on MacOS thread affinity is only advisory.");
#endif
            thd_setaffinity(thd->m_oWorkThread.native_handle(), cfg.iCpuAff);
        }

        m_pvThreads->push_back(thd);

        if(cfg.iCpuAff >= 0)
            printer::inst()->print_msg(L1, "Starting %s thread, affinity: %d.", cfg.bDoubleMode ? "double" : "single", (int)cfg.iCpuAff);
        else
            printer::inst()->print_msg(L1, "Starting %s thread, no affinity.", cfg.bDoubleMode ? "double" : "single");
    }

    s_iThreadCount = n;
    return m_pvThreads;
}

void MineThread::switch_work(MinerWork& pWork)
{
    // s_iConsumeCnt is a basic lock-like polling mechanism just in case we happen to push work
    // faster than threads can consume them. This should never happen in real life.
    // Pool can't physically send jobs faster than every 250ms or so due to net latency.
    // Notice: when switch to a new job, all current jobs should be done.
    while (s_iConsumeCnt.load(std::memory_order_seq_cst) < s_iThreadCount)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
 
    s_oGlobalMinerWork = pWork;
    s_iConsumeCnt.store(0, std::memory_order_seq_cst); // wait until all works consumed. here set to 0.
    // printer::inst()->print_msg(L3, "s_iGlobalJobNo changed");
    s_iGlobalJobNo++;
}

void MineThread::consume_work()
{
    // Actually, consume_work is not only finish the current work,
    // but also prepare for the next work.
    memcpy(&m_oMinerWork, &s_oGlobalMinerWork, sizeof(MinerWork));
    // printer::inst()->print_msg(L3, "Thread %u, m_iJobNo %u changed", this->m_iThreadNo, m_iJobNo);
    m_iJobNo++;
    s_iConsumeCnt++;
}

MineThread::cn_hash_fun MineThread::func_selector(bool bHaveAes, bool bNoPrefetch)
{
    // We have two independent flag bits in the functions
    // therefore we will build a binary digit and select the
    // function as a two digit binary
    // Digit order SOFT_AES, NO_PREFETCH

    static const cn_hash_fun func_table[4] = {
        cryptonight_hash<0x80000, MEMORY, false, false>,
        cryptonight_hash<0x80000, MEMORY, false, true>,
        cryptonight_hash<0x80000, MEMORY, true, false>,
        cryptonight_hash<0x80000, MEMORY, true, true>
    };

    std::bitset<2> digit;
    digit.set(0, !bNoPrefetch);
    digit.set(1, !bHaveAes);

    return func_table[digit.to_ulong()];
}

void MineThread::work_main()
{
    cn_hash_fun hash_fun;
    cryptonight_ctx* ctx;
    uint64_t iCount = 0, iStamp;
    uint64_t* piHash;
    uint32_t* piNonce;
    JobResult result;

    hash_fun = func_selector(jconf::inst()->HaveHardwareAes(), m_bNoPrefetch);
    ctx = minethd_alloc_ctx();

    piHash = (uint64_t*)(result.m_bResult + 24);
    piNonce = (uint32_t*)(m_oMinerWork.m_bWorkBlob + 39);
    uint32_t stNonce;
    s_iConsumeCnt++;

    while (m_bQuit == 0)
    {
        if (m_oMinerWork.m_bStall)
        {
            /*  We are stalled here because the Executor didn't find a job for us yet,
                either because of network latency, or a socket problem. */
            while (s_iGlobalJobNo.load(std::memory_order_relaxed) == m_iJobNo)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            consume_work();
            continue;
        }
        // printer::inst()->print_msg(L3, "starter nonce: %u", *piNonce);
        if(m_oMinerWork.m_bNiceHash)
            result.m_iNonce = calc_nicehash_nonce(*piNonce, m_oMinerWork.m_iResumeCnt);
        else
            result.m_iNonce = calc_start_nonce(m_oMinerWork.m_iResumeCnt);

        // stNonce = result.m_iNonce;
        // copy the m_sJobId from "miner work" to "result" used for submit.
        assert(sizeof(JobResult::m_sJobID) == sizeof(PoolJob::m_sJobID));
        memcpy(result.m_sJobID, m_oMinerWork.m_sJobID, sizeof(JobResult::m_sJobID));
        //size_t iHashCalculated = 0;
        while(s_iGlobalJobNo.load(std::memory_order_relaxed) == m_iJobNo)
        {
            if ((iCount & 0xFF) == 0) //Store stats every 255 hashes
            {
                using namespace std::chrono;
                iStamp = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();
                m_iHashCount.store(iCount, std::memory_order_relaxed);
                m_iTimestamp.store(iStamp, std::memory_order_relaxed);
            }
            iCount++;

            *piNonce = ++result.m_iNonce;
            // Main hash function, time mainly consume here.
            hash_fun(m_oMinerWork.m_bWorkBlob, m_oMinerWork.m_iWorkSize, result.m_bResult, ctx);
            //++iHashCalculated;
            if (*piHash < m_oMinerWork.m_iTarget)
                Executor::inst()->push_event(ex_event(result, m_oMinerWork.m_iPoolId));

            std::this_thread::yield(); // A hint to reschedule the execution of this thread, allow other threads to run.
        }
        // printer::inst()->print_msg(L3, "Thread:%u, stNonce:%u, edNonce:%u", this->m_iThreadNo, stNonce, *piNonce);
        consume_work();
    }

    cryptonight_free_ctx(ctx);
}

MineThread::cn_hash_fun_dbl MineThread::func_dbl_selector(bool p_bHaveAes, bool p_bNoPrefetch)
{
    // We have two independent flag bits in the functions
    // therefore we will build a binary digit and select the
    // function as a two digit binary
    // Digit order SOFT_AES, NO_PREFETCH

    static const cn_hash_fun_dbl func_table[4] =
    {
        cryptonight_double_hash<0x80000, MEMORY, false, false>,
        cryptonight_double_hash<0x80000, MEMORY, false, true>,
        cryptonight_double_hash<0x80000, MEMORY, true, false>,
        cryptonight_double_hash<0x80000, MEMORY, true, true>
    };

    std::bitset<2> digit;
    digit.set(0, !p_bNoPrefetch);
    digit.set(1, !p_bHaveAes);

    return func_table[digit.to_ulong()];
}

void MineThread::double_work_main()
{
    cn_hash_fun_dbl hash_fun;
    cryptonight_ctx* ctx0;
    cryptonight_ctx* ctx1;
    uint64_t iCount = 0;
    uint64_t *piHash0, *piHash1;
    uint32_t *piNonce0, *piNonce1;
    uint8_t bDoubleHashOut[64];
    uint8_t bDoubleWorkBlob[sizeof(MinerWork::m_bWorkBlob) * 2];
    uint32_t iNonce;

    hash_fun = func_dbl_selector(jconf::inst()->HaveHardwareAes(), m_bNoPrefetch);
    ctx0 = minethd_alloc_ctx();
    ctx1 = minethd_alloc_ctx();

    piHash0 = (uint64_t*)(bDoubleHashOut + 24);
    piHash1 = (uint64_t*)(bDoubleHashOut + 32 + 24);
    piNonce0 = (uint32_t*)(bDoubleWorkBlob + 39);
    piNonce1 = nullptr;

    s_iConsumeCnt++;

    while (m_bQuit == 0)
    {
        if (m_oMinerWork.m_bStall)
        {
            /*    We are stalled here because the Executor didn't find a job for us yet,
            either because of network latency, or a socket problem. Since we are
            raison d'etre of this software it us sensible to just wait until we have something*/

            while (s_iGlobalJobNo.load(std::memory_order_relaxed) == m_iJobNo)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            consume_work();
            memcpy(bDoubleWorkBlob, m_oMinerWork.m_bWorkBlob, m_oMinerWork.m_iWorkSize);
            memcpy(bDoubleWorkBlob + m_oMinerWork.m_iWorkSize, m_oMinerWork.m_bWorkBlob, m_oMinerWork.m_iWorkSize);
            piNonce1 = (uint32_t*)(bDoubleWorkBlob + m_oMinerWork.m_iWorkSize + 39);
            continue;
        }

        if(m_oMinerWork.m_bNiceHash)
            iNonce = calc_nicehash_nonce(*piNonce0, m_oMinerWork.m_iResumeCnt);
        else
            iNonce = calc_start_nonce(m_oMinerWork.m_iResumeCnt);

        assert(sizeof(JobResult::m_sJobID) == sizeof(PoolJob::m_sJobID));

        while (s_iGlobalJobNo.load(std::memory_order_relaxed) == m_iJobNo)
        {
            if ((iCount & 0x7) == 0) //Store stats every 16 hashes
            {
                using namespace std::chrono;
                uint64_t iStamp = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();
                m_iHashCount.store(iCount, std::memory_order_relaxed);
                m_iTimestamp.store(iStamp, std::memory_order_relaxed);
            }

            iCount += 2;

            *piNonce0 = ++iNonce;
            *piNonce1 = ++iNonce;

            hash_fun(bDoubleWorkBlob, m_oMinerWork.m_iWorkSize, bDoubleHashOut, ctx0, ctx1);

            if (*piHash0 < m_oMinerWork.m_iTarget)
                Executor::inst()->push_event(ex_event(JobResult(m_oMinerWork.m_sJobID, iNonce-1, bDoubleHashOut), m_oMinerWork.m_iPoolId));

            if (*piHash1 < m_oMinerWork.m_iTarget)
                Executor::inst()->push_event(ex_event(JobResult(m_oMinerWork.m_sJobID, iNonce, bDoubleHashOut + 32), m_oMinerWork.m_iPoolId));

            std::this_thread::yield();
        }

        consume_work();
        memcpy(bDoubleWorkBlob, m_oMinerWork.m_bWorkBlob, m_oMinerWork.m_iWorkSize);
        memcpy(bDoubleWorkBlob + m_oMinerWork.m_iWorkSize, m_oMinerWork.m_bWorkBlob, m_oMinerWork.m_iWorkSize);
        piNonce1 = (uint32_t*)(bDoubleWorkBlob + m_oMinerWork.m_iWorkSize + 39);
    }

    cryptonight_free_ctx(ctx0);
    cryptonight_free_ctx(ctx1);
}
