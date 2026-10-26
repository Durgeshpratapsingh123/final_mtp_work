#ifndef TLS_SERVER_HPP
#define TLS_SERVER_HPP

#include "redis_client.hpp"
#include "session_manager.hpp"
#include "ebpf_manager.hpp"
#include "dispatcher.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <string>
#include <thread>

class TLSServer {
public:
    TLSServer(int port);
    ~TLSServer();

    bool initialize();
    void start();

private:
    bool initializeOpenSSL();
    bool createContext();
    bool loadCertificates();
    bool configureVerification();

    // Runs on its own thread per accepted connection so multiple
    // tenants can stay subscribed and receive dispatched events
    // concurrently.
    void serveClient(int clientSocket, sockaddr_in clientAddr);

    void handleClientRequests(SSL* ssl,
                          const std::string& tenant,
                          const std::string& client);

    bool createServerSocket();
    bool bindAndListen();

private:
    int port_;

    int serverSocket_;

    SSL_CTX* sslContext_;

    SessionManager sessionManager_;

    RedisClient redisClient_;

    Dispatcher dispatcher_;

    EbpfManager ebpfManager_;

    std::thread ebpfThread_;
};

#endif
