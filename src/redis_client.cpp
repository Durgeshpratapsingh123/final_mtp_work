#include "redis_client.hpp"

#include <iostream>

RedisClient::RedisClient()
    : context_(nullptr)
{
}

RedisClient::~RedisClient()
{
    disconnect();
}

bool RedisClient::connect(const std::string& host, int port)
{
    std::lock_guard<std::mutex> lock(mutex_);

    context_ = redisConnect(host.c_str(), port);

    if (context_ == nullptr)
    {
        std::cerr << "Failed to allocate Redis context.\n";
        return false;
    }

    if (context_->err)
    {
        std::cerr << "Redis Connection Error: "
                  << context_->errstr << '\n';

        redisFree(context_);
        context_ = nullptr;
        return false;
    }

    std::cout << "Connected to Redis Server.\n";
    return true;
}

void RedisClient::disconnect()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (context_ != nullptr)
    {
        redisFree(context_);
        context_ = nullptr;

        std::cout << "Disconnected from Redis Server.\n";
    }
}

bool RedisClient::setValue(const std::string& key,
                           const std::string& value)
{
    std::lock_guard<std::mutex> lock(mutex_);

    redisReply* reply =
        (redisReply*)redisCommand(
            context_,
            "SET %s %s",
            key.c_str(),
            value.c_str());

    if (reply == nullptr)
        return false;

    freeReplyObject(reply);
    return true;
}

std::string RedisClient::getValue(const std::string& key)
{
    std::lock_guard<std::mutex> lock(mutex_);

    redisReply* reply =
        (redisReply*)redisCommand(
            context_,
            "GET %s",
            key.c_str());

    if (reply == nullptr)
        return "";

    std::string value;

    if (reply->type == REDIS_REPLY_STRING)
        value = reply->str;

    freeReplyObject(reply);

    return value;
}

bool RedisClient::isAuthorized(const std::string& tenant,
                               const std::string& syscall)
{
    std::lock_guard<std::mutex> lock(mutex_);

    redisReply* reply =
        (redisReply*)redisCommand(
            context_,
            "SISMEMBER %s %s",
            tenant.c_str(),
            syscall.c_str());

    if (reply == nullptr)
    {
        return false;
    }

    bool authorized = false;

    if (reply->type == REDIS_REPLY_INTEGER)
    {
        authorized = (reply->integer == 1);
    }

    freeReplyObject(reply);

    return authorized;
}

bool RedisClient::tenantExists(const std::string& tenant)
{
    std::lock_guard<std::mutex> lock(mutex_);

    redisReply* reply =
        (redisReply*)redisCommand(
            context_,
            "SISMEMBER tenants %s",
            tenant.c_str());

    if (reply == nullptr)
    {
        return false;
    }

    bool exists = false;

    if (reply->type == REDIS_REPLY_INTEGER)
    {
        exists = (reply->integer == 1);
    }

    freeReplyObject(reply);

    return exists;
}
