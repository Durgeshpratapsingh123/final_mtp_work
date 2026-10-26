#ifndef SESSION_MANAGER_HPP
#define SESSION_MANAGER_HPP

#include <openssl/ssl.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <functional>

struct ClientSession
{
    std::string tenant;
    std::string client;
    std::string ipAddress;
    SSL* ssl;
    std::set<std::string> subscriptions;
};

// Thread-safe: sessions are added/removed from each client's own
// connection thread, and looked up from the eBPF dispatch thread.
class SessionManager
{
public:
    void addSession(const ClientSession& session);

    void removeSession(const std::string& client);

    void printSessions() const;

    void subscribe(const std::string& client, const std::string& syscall);

    void unsubscribe(const std::string& client, const std::string& syscall);

    std::set<std::string> getSubscriptions(const std::string& client) const;

    // Invokes fn(session) for every currently connected session
    // subscribed to `syscall`. fn runs while the internal lock is
    // held, so it must not call back into SessionManager.
    void forEachSubscriber(const std::string& syscall,
                            const std::function<void(const ClientSession&)>& fn);

private:
    mutable std::mutex mutex_;
    std::vector<ClientSession> sessions_;
};

#endif
