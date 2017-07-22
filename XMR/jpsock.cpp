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

#include <stdarg.h>
#include <assert.h>

#include "jpsock.h"
#include "Executor.h"
#include "jconf.h"
#include "console.h"
#include "rapidjson/document.h"
#include "jext.h"
#include "socks.h"
#include "socket.h"
#pragma comment(lib,"ws2_32.lib")
#define AGENTID_STR "xmr-stak-cpu/1.0.0"
#define LOGIN_STR "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"" AGENTID_STR "\"},\"id\":1}\n"
#define SUBMIT_STR "{\"method\":\"submit\",\"params\":{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result\":\"%s\"},\"id\":1}\n"

using namespace rapidjson;

struct jpsock::call_rsp
{
    bool bHaveResponse;
    uint64_t iCallId;
    Value* pCallData;
    std::string sCallErr;

    call_rsp(Value* val) : pCallData(val)
    {
        bHaveResponse = false;
        iCallId = 0;
        sCallErr.clear();
    }
};

typedef GenericDocument<UTF8<>, MemoryPoolAllocator<>, MemoryPoolAllocator<>> MemDocument;

/*
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ASSUMPTION - only one calling thread. Multiple calling threads would require better
 * thread safety. The calling thread is assumed to be the Executor thread.
 * If there is a reason to call the pool outside of the Executor context, consider
 * doing it via an Executor event.
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * Call values and allocators are for the calling thread (Executor). When processing
 * a call, the recv thread will make a copy of the call response and then erase its copy.
 */

struct jpsock::OpaquePrivate
{
    Value  oCallValue;

    MemoryPoolAllocator<> callAllocator;
    MemoryPoolAllocator<> recvAllocator;
    MemoryPoolAllocator<> parseAllocator;
    MemDocument jsonDoc;
    call_rsp oCallRsp;

    OpaquePrivate(uint8_t* bCallMem, uint8_t* bRecvMem, uint8_t* bParseMem) :
        callAllocator(bCallMem, jpsock::m_iJsonMemSize),
        recvAllocator(bRecvMem, jpsock::m_iJsonMemSize),
        parseAllocator(bParseMem, jpsock::m_iJsonMemSize),
        jsonDoc(&recvAllocator, jpsock::m_iJsonMemSize, &parseAllocator),
        oCallRsp(nullptr)
    {
    }
};

struct jpsock::opq_json_val
{
    const Value* val;
    opq_json_val(const Value* val) : val(val) {}
};

jpsock::jpsock(size_t id, bool tls) : m_iPoolId(id)
{
    sock_init();

    m_bJsonCallMem = (uint8_t*)malloc(m_iJsonMemSize);
    m_bJsonRecvMem = (uint8_t*)malloc(m_iJsonMemSize);
    m_bJsonParseMem = (uint8_t*)malloc(m_iJsonMemSize);

    m_opq = new OpaquePrivate(m_bJsonCallMem, m_bJsonRecvMem, m_bJsonParseMem);

#ifndef CONF_NO_TLS
    if(tls)
        m_sock = new tls_socket(this);
    else
        m_sock = new plain_socket(this);
#else
    m_sock = new plain_socket(this);
#endif

    m_receiveThread = nullptr;
    m_bRunning = false;
    m_bLoggedIn = false;
    m_iJobDiff = 0;

    memset(&m_poolJob, 0, sizeof(m_poolJob));
}

jpsock::~jpsock()
{
    delete m_opq;
    m_opq = nullptr;

    free(m_bJsonCallMem);
    free(m_bJsonRecvMem);
    free(m_bJsonParseMem);
}

std::string&& jpsock::get_call_error()
{
    return std::move(m_opq->oCallRsp.sCallErr);
}

bool jpsock::set_socket_error(const char* a)
{
    if(!m_bHaveSocketError)
    {
        m_bHaveSocketError = true;
        m_sSocketError.assign(a);
    }

    return false;
}

bool jpsock::set_socket_error(const char* a, const char* b)
{
    if(!m_bHaveSocketError)
    {
        m_bHaveSocketError = true;
        size_t ln_a = strlen(a);
        size_t ln_b = strlen(b);

        m_sSocketError.reserve(ln_a + ln_b + 2);
        m_sSocketError.assign(a, ln_a);
        m_sSocketError.append(b, ln_b);
    }

    return false;
}

bool jpsock::set_socket_error(const char* a, size_t len)
{
    if(!m_bHaveSocketError)
    {
        m_bHaveSocketError = true;
        m_sSocketError.assign(a, len);
    }

    return false;
}

bool jpsock::set_socket_error_strerr(const char* a)
{
    char sSockErrText[512];
    return set_socket_error(a, sock_strerror(sSockErrText, sizeof(sSockErrText)));
}

bool jpsock::set_socket_error_strerr(const char* a, int res)
{
    char sSockErrText[512];
    return set_socket_error(a, sock_gai_strerror(res, sSockErrText, sizeof(sSockErrText)));
}

void jpsock::jpsock_thread()
{
    jpsock_thread_main();
    Executor::inst()->push_event(ex_event(std::move(m_sSocketError), m_iPoolId));

    // If a call is wating, send an error to end it
    bool bCallWaiting = false;
    std::unique_lock<std::mutex> mlock(call_mutex);
    if(m_opq->oCallRsp.pCallData != nullptr)
    {
        m_opq->oCallRsp.bHaveResponse = true;
        m_opq->oCallRsp.iCallId = 0;
        m_opq->oCallRsp.pCallData = nullptr;
        bCallWaiting = true;
    }
    mlock.unlock();

    if(bCallWaiting)
        call_cond.notify_one();

    m_bRunning = false;
    m_bLoggedIn = false;

    std::unique_lock<std::mutex>(job_mutex);
    memset(&m_poolJob, 0, sizeof(m_poolJob));
}

bool jpsock::jpsock_thread_main()
{
    if(!m_sock->connect())
        return false;

    Executor::inst()->push_event(ex_event(EV_SOCK_READY, m_iPoolId));

    char buf[m_iSockBufferSize];
    size_t datalen = 0;
    while (true)
    {
        int ret = m_sock->recv(buf + datalen, sizeof(buf) - datalen);
        // printer::inst()->print_msg(L0, "Line Info %s", buf);
        if(ret <= 0) return false;

        datalen += ret;

        if (datalen >= sizeof(buf))
        {
            m_sock->close(false);
            return set_socket_error("RECEIVE error: data overflow");
        }

        char* lnend;
        char* lnstart = buf;
        while ((lnend = (char*)memchr(lnstart, '\n', datalen)) != nullptr)
        {
            lnend++;
            int lnlen = lnend - lnstart;

            if (!process_line(lnstart, lnlen))
            {
                m_sock->close(false);
                return false;
            }

            datalen -= lnlen;
            lnstart = lnend;
        }

        //Got leftover data? Move it to the front
        if (datalen > 0 && buf != lnstart)
            memmove(buf, lnstart, datalen);
    }
}

bool jpsock::process_line(char* line, size_t len)
{
    m_opq->jsonDoc.SetNull();
    m_opq->parseAllocator.Clear();
    m_opq->callAllocator.Clear();

    /*NULL terminate the line instead of '\n', parsing will add some more NULLs*/
    line[len-1] = '\0';
    // printer::inst()->print_msg(L0, "Line Info %s", line);
    // printf("RECV: %s\n", line);

    if (m_opq->jsonDoc.ParseInsitu(line).HasParseError())
        return set_socket_error("PARSE error: Invalid JSON");

    if (!m_opq->jsonDoc.IsObject())
        return set_socket_error("PARSE error: Invalid root");

    const Value* mt;
    if (m_opq->jsonDoc.HasMember("method"))
    {
        mt = GetObjectMember(m_opq->jsonDoc, "method");

        if(!mt->IsString())
            return set_socket_error("PARSE error: Protocol error 1");

        if(strcmp(mt->GetString(), "job") != 0)
            return set_socket_error("PARSE error: Unsupported server method ", mt->GetString());

        mt = GetObjectMember(m_opq->jsonDoc, "params");
        if(mt == nullptr || !mt->IsObject())
            return set_socket_error("PARSE error: Protocol error 2");

        opq_json_val v(mt);
        return process_pool_job(&v);
    }
    else
    {
        uint64_t iCallId;
        mt = GetObjectMember(m_opq->jsonDoc, "id");
        if (mt == nullptr || !mt->IsUint64())
            return set_socket_error("PARSE error: Protocol error 3");

        iCallId = mt->GetUint64();

        mt = GetObjectMember(m_opq->jsonDoc, "error");

        const char* sError = nullptr;
        size_t iErrorLn = 0;
        if (mt == nullptr || mt->IsNull())
        {
            /* If there was no error we need a result */
            if ((mt = GetObjectMember(m_opq->jsonDoc, "result")) == nullptr)
                return set_socket_error("PARSE error: Protocol error 7");
        }
        else
        {
            if(!mt->IsObject())
                return set_socket_error("PARSE error: Protocol error 5");

            const Value* msg = GetObjectMember(*mt, "message");

            if(msg == nullptr || !msg->IsString())
                return set_socket_error("PARSE error: Protocol error 6");

            iErrorLn = msg->GetStringLength();
            sError = msg->GetString();
        }

        std::unique_lock<std::mutex> mlock(call_mutex);
        if (m_opq->oCallRsp.pCallData == nullptr)
        {
            /*Server sent us a call reply without us making a call*/
            mlock.unlock();
            return set_socket_error("PARSE error: Unexpected call response");
        }

        m_opq->oCallRsp.bHaveResponse = true;
        m_opq->oCallRsp.iCallId = iCallId;

        if(sError != nullptr)
        {
            m_opq->oCallRsp.pCallData = nullptr;
            m_opq->oCallRsp.sCallErr.assign(sError, iErrorLn);
        }
        else
            m_opq->oCallRsp.pCallData->CopyFrom(*mt, m_opq->callAllocator);

        mlock.unlock();
        call_cond.notify_one();

        return true;
    }
}

bool jpsock::process_pool_job(const opq_json_val* params)
{
    if (!params->val->IsObject())
        return set_socket_error("PARSE error: Job error 1");

    const Value * blob, *jobid, *target;
    jobid = GetObjectMember(*params->val, "job_id");
    blob = GetObjectMember(*params->val, "blob");
    target = GetObjectMember(*params->val, "target");

    if (jobid == nullptr || blob == nullptr || target == nullptr ||
        !jobid->IsString() || !blob->IsString() || !target->IsString())
    {
        return set_socket_error("PARSE error: Job error 2");
    }

    if (jobid->GetStringLength() >= sizeof(PoolJob::m_sJobID)) // Note >=
        return set_socket_error("PARSE error: Job error 3");

    uint32_t iWorkLen = blob->GetStringLength() >> 1;
    if (iWorkLen > sizeof(PoolJob::m_bWorkBlob))
        return set_socket_error("PARSE error: Invalid job legth. Are you sure you are mining the correct coin?");

    PoolJob oPoolJob;
    if (!hex2bin(blob->GetString(), iWorkLen << 1, oPoolJob.m_bWorkBlob))
        return set_socket_error("PARSE error: Job error 4");

    oPoolJob.m_iWorkLen = iWorkLen;
    memset(oPoolJob.m_sJobID, 0, sizeof(PoolJob::m_sJobID));
    memcpy(oPoolJob.m_sJobID, jobid->GetString(), jobid->GetStringLength()); //Bounds checking at proto error 3

    size_t target_slen = target->GetStringLength();
    if(target_slen <= 8)
    {
        uint32_t iTempInt = 0;
        char sTempStr[] = "00000000"; // Little-endian CPU FTW
        memcpy(sTempStr, target->GetString(), target_slen);
        if(!hex2bin(sTempStr, 8, (unsigned char*)&iTempInt) || iTempInt == 0)
            return set_socket_error("PARSE error: Invalid target");

        oPoolJob.m_iTarget = t32_to_t64(iTempInt);
    }
    else if(target_slen <= 16)
    {
        oPoolJob.m_iTarget = 0;
        char sTempStr[] = "0000000000000000";
        memcpy(sTempStr, target->GetString(), target_slen);
        if(!hex2bin(sTempStr, 16, (unsigned char*)&oPoolJob.m_iTarget) || oPoolJob.m_iTarget == 0)
            return set_socket_error("PARSE error: Invalid target");
    }
    else
        return set_socket_error("PARSE error: Job error 5");

    m_iJobDiff = t64_to_diff(oPoolJob.m_iTarget);

    Executor::inst()->push_event(ex_event(oPoolJob, m_iPoolId));

    std::unique_lock<std::mutex>(job_mutex);
    m_poolJob = oPoolJob;
    return true;
}

bool jpsock::connect(const char* p_sAddr, std::string& p_sConnectError)
{
    m_bHaveSocketError = false;
    m_sSocketError.clear();
    m_iJobDiff = 0;

    if(m_sock->setHostname(p_sAddr))
    {
        m_bRunning = true;
        m_receiveThread = new std::thread(&jpsock::jpsock_thread, this);
        return true;
    }

    p_sConnectError = std::move(m_sSocketError);
    return false;
}

void jpsock::disconnect()
{
    m_sock->close(false);

    if(m_receiveThread != nullptr)
    {
        m_receiveThread->join();
        delete m_receiveThread;
        m_receiveThread = nullptr;
    }

    m_sock->close(true);
}

bool jpsock::cmd_ret_wait(const char* p_sPacket, opq_json_val& p_oResult)
{
    //printf("SEND: %s\n", sPacket);

    /*Set up the call rsp for the call reply*/
    m_opq->oCallValue.SetNull();
    m_opq->callAllocator.Clear();

    std::unique_lock<std::mutex> mlock(call_mutex);
    m_opq->oCallRsp = call_rsp(&m_opq->oCallValue);
    mlock.unlock();

    if(!m_sock->send(p_sPacket))
    {
        disconnect(); //This will join the other thread;
        return false;
    }

    //Success is true if the server approves, result is true if there was no socket error
    bool bSuccess;
    mlock.lock();
    bool bResult = call_cond.wait_for(mlock, std::chrono::seconds(jconf::inst()->GetCallTimeout()),
        [&]() { return m_opq->oCallRsp.bHaveResponse; });

    bSuccess = m_opq->oCallRsp.pCallData != nullptr;
    m_opq->oCallRsp.pCallData = nullptr;
    mlock.unlock();

    if(m_bHaveSocketError)
        return false;

    //This means that there was no socket error, but the server is not taking to us
    if(!bResult)
    {
        set_socket_error("CALL error: Timeout while waiting for a reply");
        disconnect();
        return false;
    }

    if(bSuccess)
        p_oResult.val = &m_opq->oCallValue;

    return bSuccess;
}

bool jpsock::cmd_login(const char* p_sLogin, const char* p_sPassword)
{
    char cmd_buffer[1024];

    snprintf(cmd_buffer, sizeof(cmd_buffer), LOGIN_STR,
        p_sLogin, p_sPassword);

    opq_json_val oResult(nullptr);

    /*Normal error conditions (failed login etc..) will end here*/
    if (!cmd_ret_wait(cmd_buffer, oResult))
        return false;

    if (!oResult.val->IsObject())
    {
        set_socket_error("PARSE error: Login protocol error 1");
        disconnect();
        return false;
    }

    const Value* id = GetObjectMember(*oResult.val, "id");
    const Value* job = GetObjectMember(*oResult.val, "job");

    if (id == nullptr || job == nullptr || !id->IsString())
    {
        set_socket_error("PARSE error: Login protocol error 2");
        disconnect();
        return false;
    }

    if (id->GetStringLength() >= sizeof(sMinerId))
    {
        set_socket_error("PARSE error: Login protocol error 3");
        disconnect();
        return false;
    }

    memset(sMinerId, 0, sizeof(sMinerId));
    memcpy(sMinerId, id->GetString(), id->GetStringLength());

    opq_json_val v(job);
    if(!process_pool_job(&v))
    {
        disconnect();
        return false;
    }

    m_bLoggedIn = true;

    return true;
}

bool jpsock::cmd_submit(const char* p_sJobId, uint32_t p_iNonce, const uint8_t* p_bResult)
{
    char cmd_buffer[1024];
    char sNonce[9];
    char sResult[65];

    bin2hex((unsigned char*)&p_iNonce, 4, sNonce);
    sNonce[8] = '\0';

    bin2hex(p_bResult, 32, sResult);
    sResult[64] = '\0';

    snprintf(cmd_buffer, sizeof(cmd_buffer), SUBMIT_STR, sMinerId, p_sJobId, sNonce, sResult);

    opq_json_val oResult(nullptr);
    return cmd_ret_wait(cmd_buffer, oResult);
}

bool jpsock::get_current_job(PoolJob& job)
{
    std::unique_lock<std::mutex>(job_mutex);
    if(m_poolJob.m_iWorkLen == 0) return false;
    ++m_poolJob.m_iResumeCnt;
    job = m_poolJob;
    return true;
}

/* Transform hex string to binary digit.*/
inline unsigned char helper_hex2bin(char c, bool &err)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 0xA;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 0xA;
    err = true;
    return 0;
}

bool jpsock::hex2bin(const char* p_in, unsigned int p_len, unsigned char* p_out)
{
    bool error = false;
    for (size_t i = 0; i < p_len; i += 2)
    {
        p_out[i >> 1] = (helper_hex2bin(p_in[i], error) << 4) | helper_hex2bin(p_in[i + 1], error);
        if (error) return false;
    }
    return true;
}

/* Transform binary digit to hex string.*/
inline char helper_bin2hex(unsigned char c)
{
    return c <= 0x9 ? c + '0' : c + 'a' - 0xA;
}

void jpsock::bin2hex(const unsigned char* p_in, unsigned int p_len, char* p_out)
{
    for (size_t i = 0; i < p_len; ++i)
    {
        p_out[(i << 1)] = helper_bin2hex((p_in[i] & 0xF0) >> 4);
        p_out[(i << 1) | 1] = helper_bin2hex(p_in[i] & 0x0F);
    }
}
