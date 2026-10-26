#ifndef REDIS_CLIENT_HPP
#define REDIS_CLIENT_HPP

#include <string>
#include <mutex>
#include <hiredis/hiredis.h>

// A single hiredis connection is not safe to share across threads.
// SecureProxy calls this from each client's connection thread and
// from the eBPF dispatch thread, so every command is serialized
// behind mutex_.
class RedisClient
{
public:
    RedisClient();
    ~RedisClient();

    bool connect(const std::string& host, int port);

    void disconnect();

    bool setValue(const std::string& key,
                  const std::string& value);

    std::string getValue(const std::string& key);

    bool tenantExists(const std::string& tenant);

    bool isAuthorized(const std::string& tenant,
                      const std::string& syscall);

private:
    redisContext* context_;
    std::mutex mutex_;
};

#endif