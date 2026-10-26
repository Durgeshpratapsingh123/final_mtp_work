#include "tls_server.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <cstring>
#include <iostream>
#include <sstream>

bool TLSServer::loadCertificates()
{

    // Load the server certificate
    if (SSL_CTX_use_certificate_file(
            sslContext_,
            "../certs/server/server.crt",
            SSL_FILETYPE_PEM) <= 0)
    {

        ERR_print_errors_fp(stderr);
        return false;
    }

    // Load the server private key
    if (SSL_CTX_use_PrivateKey_file(
            sslContext_,
            "../certs/server/server.key",
            SSL_FILETYPE_PEM) <= 0)
    {

        ERR_print_errors_fp(stderr);
        return false;
    }

    // Check that the private key matches the certificate
    if (!SSL_CTX_check_private_key(sslContext_))
    {

        std::cerr << "Private key does not match the certificate.\n";
        return false;
    }

    // Load the trusted CA certificate
    if (!SSL_CTX_load_verify_locations(
            sslContext_,
            "../certs/ca/ca.crt",
            nullptr))
    {

        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}
TLSServer::TLSServer(int port)
    : port_(port),
      serverSocket_(-1),
      sslContext_(nullptr),
      dispatcher_(sessionManager_, redisClient_)
{
}

bool TLSServer::createServerSocket()
{

    serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket_ < 0)
    {
        perror("socket");
        return false;
    }

    // Allow quick restart of the server
    int opt = 1;
    setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR,
               &opt, sizeof(opt));

    return true;
}

bool TLSServer::bindAndListen()
{

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port_);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket_,
             reinterpret_cast<sockaddr *>(&serverAddr),
             sizeof(serverAddr)) < 0)
    {

        perror("bind");
        return false;
    }

    if (listen(serverSocket_, SOMAXCONN) < 0)
    {

        perror("listen");
        return false;
    }

    return true;
}

bool TLSServer::initializeOpenSSL()
{

    // Initialize the SSL library
    SSL_library_init();

    // Load SSL error strings
    SSL_load_error_strings();

    // Register available cryptographic algorithms
    OpenSSL_add_ssl_algorithms();

    return true;
}
bool TLSServer::configureVerification()
{

    SSL_CTX_set_verify(
        sslContext_,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        nullptr);

    SSL_CTX_set_verify_depth(sslContext_, 4);

    return true;
}
bool TLSServer::initialize()
{

    if (!initializeOpenSSL())
        return false;

    if (!redisClient_.connect("127.0.0.1", 6379))
    {
        std::cerr << "Failed to connect to Redis\n";
        return false;
    }

    if (!createContext())
        return false;

    if (!loadCertificates())
        return false;

    if (!configureVerification())
        return false;

    if (!createServerSocket())
        return false;

    if (!bindAndListen())
        return false;

    // Wire the eBPF ring buffer straight into the dispatcher, then
    // start pulling kernel events on a background thread.
    ebpfManager_.setEventCallback(
        [this](const event& e)
        {
            dispatcher_.dispatch(e);
        });

    if (!ebpfManager_.initialize())
    {
        std::cerr << "Failed to initialize eBPF manager\n";
        return false;
    }

    ebpfThread_ = std::thread(&EbpfManager::run, &ebpfManager_);

    return true;
}

bool TLSServer::createContext()
{

    // Create a TLS server context
    sslContext_ = SSL_CTX_new(TLS_server_method());

    if (sslContext_ == nullptr)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

void TLSServer::start()
{

    std::cout << "TLS Server listening on port "
              << port_
              << "...\n";

    while (true)
    {

        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);

        int clientSocket = accept(
            serverSocket_,
            reinterpret_cast<sockaddr *>(&clientAddr),
            &clientLen);

        if (clientSocket < 0)
        {
            perror("accept");
            continue;
        }

        // Each client gets its own thread so multiple tenants can
        // stay connected and subscribed at once, receiving events
        // dispatched from the eBPF thread concurrently.
        std::thread(&TLSServer::serveClient, this, clientSocket, clientAddr).detach();
    }
}

void TLSServer::serveClient(int clientSocket, sockaddr_in clientAddr)
{
    std::cout << "\n=============================\n";
    std::cout << "TCP Client Connected\n";

    // Create SSL object
    SSL *ssl = SSL_new(sslContext_);

    if (ssl == nullptr)
    {
        ERR_print_errors_fp(stderr);
        close(clientSocket);
        return;
    }

    SSL_set_fd(ssl, clientSocket);

    std::cout << "Starting TLS Handshake...\n";

    std::string tenant;
    std::string client;

    if (SSL_accept(ssl) <= 0)
    {
        std::cout << "TLS Handshake Failed\n";
        ERR_print_errors_fp(stderr);

        SSL_free(ssl);
        close(clientSocket);

        return;
    }

    std::cout << "TLS Handshake Successful!\n\n";

    X509 *cert = SSL_get_peer_certificate(ssl);

    if (cert == nullptr)
    {
        std::cout << "No client certificate received.\n";

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);

        return;
    }

    char buffer[256];

    X509_NAME *subject = X509_get_subject_name(cert);

    X509_NAME_get_text_by_NID(
        subject,
        NID_countryName,
        buffer,
        sizeof(buffer));

    std::cout << "Country      : " << buffer << '\n';

    X509_NAME_get_text_by_NID(
        subject,
        NID_stateOrProvinceName,
        buffer,
        sizeof(buffer));

    std::cout << "State        : " << buffer << '\n';

    X509_NAME_get_text_by_NID(
        subject,
        NID_organizationName,
        buffer,
        sizeof(buffer));

    std::cout << "Organization : " << buffer << '\n';

    X509_NAME_get_text_by_NID(
        subject,
        NID_organizationalUnitName,
        buffer,
        sizeof(buffer));

    tenant = buffer;

    std::cout << "Tenant       : " << tenant << '\n';

    X509_NAME_get_text_by_NID(
        subject,
        NID_commonName,
        buffer,
        sizeof(buffer));

    client = buffer;

    std::cout << "Client       : " << client << '\n';

    if (!redisClient_.tenantExists(tenant))
    {
        std::cout << "\nUnauthorized Tenant : "
                  << tenant
                  << std::endl;

        X509_free(cert);

        SSL_shutdown(ssl);
        SSL_free(ssl);

        close(clientSocket);

        return;
    }

    std::cout << "Tenant validation successful.\n";

    char ip[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &clientAddr.sin_addr,
        ip,
        sizeof(ip));

    ClientSession session;

    session.tenant = tenant;
    session.client = client;
    session.ipAddress = ip;
    session.ssl = ssl;

    sessionManager_.addSession(session);

    sessionManager_.printSessions();

    X509_free(cert);

    handleClientRequests(
        ssl,
        tenant,
        client);

    sessionManager_.removeSession(client);

    sessionManager_.printSessions();

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientSocket);

    std::cout << "Connection Closed\n";
    std::cout << "=============================\n";
}

void TLSServer::handleClientRequests(SSL *ssl,
                                     const std::string &tenant,
                                     const std::string &client)
{
    char buffer[1024];

    while (true)
    {
        std::memset(buffer, 0, sizeof(buffer));

        int bytes = SSL_read(
            ssl,
            buffer,
            sizeof(buffer) - 1);

        if (bytes <= 0)
        {
            std::cout << "Client disconnected.\n";
            break;
        }

        std::string request(buffer);

        // Trim trailing CR/LF.
        while (!request.empty() &&
               (request.back() == '\n' || request.back() == '\r'))
        {
            request.pop_back();
        }

        std::cout << "Received : "
                  << request
                  << std::endl;

        std::string response = "UNKNOWN COMMAND\n";

        if (request.rfind("SUBSCRIBE ", 0) == 0)
        {
            std::string syscall = request.substr(10);

            if (redisClient_.isAuthorized(tenant, syscall))
            {
                sessionManager_.subscribe(client, syscall);
                response = "OK\n";
            }
            else
            {
                response = "DENIED\n";
            }
        }
        else if (request.rfind("UNSUBSCRIBE ", 0) == 0)
        {
            std::string syscall = request.substr(12);

            sessionManager_.unsubscribe(client, syscall);
            response = "OK\n";
        }
        else if (request == "LIST")
        {
            std::ostringstream out;
            for (const auto& syscall : sessionManager_.getSubscriptions(client))
            {
                out << syscall << ' ';
            }
            out << '\n';
            response = out.str();
        }
        else if (request == "STATS")
        {
            response = dispatcher_.statsSummary();
        }
        else if (request == "QUIT")
        {
            SSL_write(ssl, "BYE\n", 4);
            break;
        }

        SSL_write(
            ssl,
            response.c_str(),
            response.size());
    }
}

TLSServer::~TLSServer()
{
    ebpfManager_.stop();

    if (ebpfThread_.joinable())
        ebpfThread_.join();

    if (sslContext_ != nullptr)
    {
        SSL_CTX_free(sslContext_);
    }

    EVP_cleanup();
}
