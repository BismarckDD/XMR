#pragma once
#include <thread>
#include <atomic>
#include "crypto/cryptonight.h"

/* measurement from the remote. */
class Telemetry
{
public:
    Telemetry(size_t p_iThread);
    ~Telemetry();
    void push_perf_value(size_t p_iThread, uint64_t p_iHashCount, uint64_t p_iTimestamp);
    double calc_telemetry_data(size_t iLastMilisec, size_t iThread);

private:
    size_t m_iThread;
    constexpr static size_t s_iBucketSize = 2048; // (1 << 12) Power of 2 to simplify calculations
    constexpr static size_t s_iBucketMask = s_iBucketSize - 1;
    uint32_t* m_piBucketTop;
    uint64_t** m_ppHashCounts;
    uint64_t** m_ppTimeStamps;
};

class MineThread
{
public:
    struct MinerWork
    {
        bool        m_bNiceHash;
        bool        m_bStall;
        char        m_sJobID[64];
        uint8_t     m_bWorkBlob[112];
        uint32_t    m_iWorkSize;
        uint32_t    m_iResumeCnt;
        uint64_t    m_iTarget;
        size_t      m_iPoolId;

        MinerWork() : m_iWorkSize(0), m_bStall(true), m_iPoolId(0) { }

        MinerWork(const char* p_sJobID, const uint8_t* p_bWork, uint32_t p_iWorkSize, uint32_t p_iResumeCnt,
            uint64_t p_iTarget, bool p_bNiceHash, size_t p_iPoolId) 
            : m_iWorkSize(p_iWorkSize), m_iResumeCnt(p_iResumeCnt), m_iTarget(p_iTarget), 
                m_bNiceHash(p_bNiceHash), m_bStall(false), m_iPoolId(p_iPoolId)
        {
            assert(m_iWorkSize <= sizeof(m_bWorkBlob));
            memcpy(m_sJobID, p_sJobID, sizeof(MinerWork::m_sJobID));
            memcpy(m_bWorkBlob, p_bWork, m_iWorkSize);
        }

        MinerWork(MinerWork const&) = delete;

        MinerWork& operator=(MinerWork const& from)
        {
            assert(this != &from);

            m_iWorkSize = from.m_iWorkSize;
            m_iResumeCnt = from.m_iResumeCnt;
            m_iTarget = from.m_iTarget;
            m_bNiceHash = from.m_bNiceHash;
            m_bStall = from.m_bStall;
            m_iPoolId = from.m_iPoolId;

            assert(m_iWorkSize <= sizeof(m_bWorkBlob));
            memcpy(m_sJobID, from.m_sJobID, sizeof(m_sJobID));
            memcpy(m_bWorkBlob, from.m_bWorkBlob, m_iWorkSize);

            return *this;
        }

        MinerWork(MinerWork&& from) : m_iWorkSize(from.m_iWorkSize), m_iTarget(from.m_iTarget),
            m_bStall(from.m_bStall), m_iPoolId(from.m_iPoolId)
        {
            assert(m_iWorkSize <= sizeof(m_bWorkBlob));
            memcpy(m_sJobID, from.m_sJobID, sizeof(m_sJobID));
            memcpy(m_bWorkBlob, from.m_bWorkBlob, m_iWorkSize);
        }

        MinerWork& operator=(MinerWork&& from)
        {
            assert(this != &from);

            m_iWorkSize = from.m_iWorkSize;
            m_iResumeCnt = from.m_iResumeCnt;
            m_iTarget = from.m_iTarget;
            m_bNiceHash = from.m_bNiceHash;
            m_bStall = from.m_bStall;
            m_iPoolId = from.m_iPoolId;

            assert(m_iWorkSize <= sizeof(m_bWorkBlob));
            memcpy(m_sJobID, from.m_sJobID, sizeof(m_sJobID));
            memcpy(m_bWorkBlob, from.m_bWorkBlob, m_iWorkSize);

            return *this;
        }
    };

    static void switch_work(MinerWork& p_rMinerWork);
    static std::vector<MineThread*>* thread_starter(MinerWork& p_rMinerWork);
    static bool self_test();

    std::atomic<uint64_t> m_iHashCount;
    std::atomic<uint64_t> m_iTimestamp;

private:
    /* one usage of typedef, to define a complex definition. */
    typedef void (*cn_hash_fun)(const void*, size_t, void*, cryptonight_ctx*);
    typedef void (*cn_hash_fun_dbl)(const void*, size_t, void*, cryptonight_ctx* __restrict, cryptonight_ctx* __restrict);

    MineThread(MinerWork& p_rWork, size_t p_iThreadNo, bool p_bDoubleWork, bool p_bNoPrefetch);

    // We use the top 10 bits of the nonce for thread and resume ( 2**10 = 1023, 512 / 128 == 4 )
    // This allows us to resume up to 128 threads 4 times before we get nonce collisions
    // Bottom 22 bits allow for an hour of work at 1000 H/s
    inline uint32_t calc_start_nonce(uint32_t p_resume)
        { return (uint32_t)((p_resume * s_iThreadCount + m_iThreadNo) << 22); }

    // Limited version of the nonce calc above /**.
    inline uint32_t calc_nicehash_nonce(uint32_t p_start, uint32_t p_resume)
        { return (uint32_t)(p_start | (p_resume * s_iThreadCount + m_iThreadNo) << 18); }

    static cn_hash_fun func_selector(bool p_bHaveAes, bool p_bNoPrefetch);
    static cn_hash_fun_dbl func_dbl_selector(bool p_bHaveAes, bool p_bNoPrefetch);

    void work_main();
    void double_work_main();
    void consume_work();

    static std::atomic<uint64_t> s_iGlobalJobNo;
    static std::atomic<uint64_t> s_iConsumeCnt;
    static uint64_t s_iThreadCount;
    uint64_t m_iJobNo;

    static MinerWork s_oGlobalMinerWork;
    MinerWork m_oMinerWork;

    std::thread m_oWorkThread;
    uint8_t m_iThreadNo;

    bool m_bQuit;
    bool m_bNoPrefetch;
};

