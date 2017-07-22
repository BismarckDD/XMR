#pragma once
#include <string>
#include <string.h>
#include <assert.h>

// Structures that we use to pass info between threads constructors are here just to make
// the stack allocation take up less space, heap is a shared resouce that needs locks too of course

struct PoolJob
{
    char        m_sJobID[64];
    uint8_t     m_bWorkBlob[112];   
    uint32_t    m_iWorkLen;
    uint32_t    m_iResumeCnt;
    uint64_t    m_iTarget;

    PoolJob() : m_iWorkLen(0), m_iResumeCnt(0) {}
    PoolJob(const char* p_sJobID, uint64_t p_iTarget, const uint8_t* p_bWorkBlob, uint32_t p_iWorkLen) :
        m_iTarget(p_iTarget), m_iWorkLen(p_iWorkLen), m_iResumeCnt(0)
    {
        assert(m_iWorkLen <= sizeof(PoolJob::m_bWorkBlob));
        memcpy(m_sJobID, p_sJobID, sizeof(PoolJob::m_sJobID));
        memcpy(m_bWorkBlob, p_bWorkBlob, m_iWorkLen);
    }
};

struct JobResult
{
    char        m_sJobID[64];
    uint8_t     m_bResult[32];
    uint32_t    m_iNonce;

    JobResult() {}
    JobResult(const char* p_sJobID, uint32_t p_iNonce, const uint8_t* p_bResult) : m_iNonce(p_iNonce)
    {
        memcpy(m_sJobID, p_sJobID, sizeof(JobResult::m_sJobID));
        memcpy(m_bResult, p_bResult, sizeof(JobResult::m_bResult));
    }
};

enum ex_event_name 
{ 
    EV_INVALID_VAL, 
    EV_SOCK_READY, 
    EV_SOCK_ERROR,
    EV_POOL_HAVE_JOB, 
    EV_MINER_HAVE_RESULT, 
    EV_PERF_TICK, 
    EV_RECONNECT,
    EV_SWITCH_POOL, 
    EV_DEV_POOL_EXIT, 
    EV_USR_HASHRATE, 
    EV_USR_RESULTS, 
    EV_USR_CONNSTAT,
    EV_HASHRATE_LOOP, 
    EV_HTML_HASHRATE, 
    EV_HTML_RESULTS, 
    EV_HTML_CONNSTAT 
};

/*
   This is how I learned to stop worrying and love c++11 =).
   Ghosts of endless heap allocations have finally been exorcised. 
   Thanks to the nifty magic of move semantics, string will only be 
   allocated once on the heap. Considering that it makes a jorney across stack,
   heap alloced queue, to another stack before being finally processed
   I think it is kind of nifty, don't you?
   Also note that for non-arg events we only copy two qwords
*/

struct ex_event
{
    ex_event_name iName;
    size_t m_iPoolId;

    union
    {
        PoolJob oPoolJob;
        JobResult oJobResult;
        std::string m_sSocketError;
    };

    ex_event() { iName = EV_INVALID_VAL; m_iPoolId = 0;}
    ex_event(std::string&& err, size_t id) : iName(EV_SOCK_ERROR), m_iPoolId(id), m_sSocketError(std::move(err)) { }
    ex_event(JobResult dat, size_t id) : iName(EV_MINER_HAVE_RESULT), m_iPoolId(id), oJobResult(dat) {}
    ex_event(PoolJob dat, size_t id) : iName(EV_POOL_HAVE_JOB), m_iPoolId(id), oPoolJob(dat) {}
    ex_event(ex_event_name ev, size_t id = 0) : iName(ev), m_iPoolId(id) {}

    // Delete the copy operators to make sure we are moving only what is needed
    ex_event(ex_event const&) = delete;
    ex_event& operator=(ex_event const&) = delete;

    ex_event(ex_event&& from)
    {
        iName = from.iName;
        m_iPoolId = from.m_iPoolId;

        switch(iName)
        {
        case EV_SOCK_ERROR:
            new (&m_sSocketError) std::string(std::move(from.m_sSocketError));
            break;
        case EV_MINER_HAVE_RESULT:
            oJobResult = from.oJobResult;
            break;
        case EV_POOL_HAVE_JOB:
            oPoolJob = from.oPoolJob;
            break;
        default:
            break;
        }
    }

    ex_event& operator=(ex_event&& from)
    {
        assert(this != &from);

        if(iName == EV_SOCK_ERROR)
            m_sSocketError.~basic_string();

        iName = from.iName;
        m_iPoolId = from.m_iPoolId;

        switch(iName)
        {
        case EV_SOCK_ERROR:
            new (&m_sSocketError) std::string();
            m_sSocketError = std::move(from.m_sSocketError);
            break;
        case EV_MINER_HAVE_RESULT:
            oJobResult = from.oJobResult;
            break;
        case EV_POOL_HAVE_JOB:
            oPoolJob = from.oPoolJob;
            break;
        default:
            break;
        }

        return *this;
    }

    ~ex_event()
    {
        if(iName == EV_SOCK_ERROR)
            m_sSocketError.~basic_string();
    }
};
