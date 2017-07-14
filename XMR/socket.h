#pragma once
#include "socks.h"
class jpsock;

class BaseSocket
{
public:
    virtual bool setHostname(const char* p_sAddr) = 0;
    virtual bool connect() = 0;
    virtual int recv(char* p_buf, unsigned int p_len) = 0;
    virtual bool send(const char* p_buf) = 0;
    virtual void close(bool p_free) = 0;
};

class plain_socket : public BaseSocket
{
public:
    plain_socket(jpsock* p_err_callback);

    bool setHostname(const char* p_sAddr);
    bool connect();
    int recv(char* p_buf, unsigned int p_len);
    bool send(const char* p_buf);
    void close(bool p_free);

private:
    jpsock* m_pCallback;
    addrinfo *m_pSockAddr;
    addrinfo *m_pAddrRoot;
    SOCKET m_hSocket;
};


#ifndef CONF_NO_TLS
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef struct ssl_st SSL;

class tls_socket : public BaseSocket
{
public:
    tls_socket(jpsock* err_callback);

    bool setHostname(const char* sAddr);
    bool connect();
    int recv(char* buf, unsigned int len);
    bool send(const char* buf);
    void close(bool free);

private:
    void init_ctx();
    void print_error();

    jpsock* pCallback;

    SSL_CTX* ctx = nullptr;
    BIO* bio = nullptr;
    SSL* ssl = nullptr;
};
#endif

