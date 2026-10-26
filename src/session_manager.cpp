#include "session_manager.hpp"

#include <algorithm>
#include <iostream>

void SessionManager::addSession(const ClientSession& session)
{
    std::lock_guard<std::mutex> lock(mutex_);

    sessions_.push_back(session);

    std::cout << "\n[SessionManager] Session Added\n";
    std::cout << "Tenant : " << session.tenant << '\n';
    std::cout << "Client : " << session.client << '\n';
    std::cout << "Active Sessions : " << sessions_.size() << "\n\n";
}

void SessionManager::removeSession(const std::string& client)
{
    std::lock_guard<std::mutex> lock(mutex_);

    sessions_.erase(
        std::remove_if(
            sessions_.begin(),
            sessions_.end(),
            [&](const ClientSession& session)
            {
                return session.client == client;
            }),
        sessions_.end());

    std::cout << "[SessionManager] Session Removed : "
              << client << '\n';

    std::cout << "Active Sessions : "
              << sessions_.size() << "\n\n";
}

void SessionManager::printSessions() const
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << "\n========== Active Sessions ==========\n";

    if (sessions_.empty())
    {
        std::cout << "No Active Sessions\n";
    }
    else
    {
        for (const auto& session : sessions_)
        {
            std::cout
                << "Tenant : " << session.tenant
                << " | Client : " << session.client
                << " | IP : " << session.ipAddress
                << '\n';
        }
    }

    std::cout << "=====================================\n\n";
}

void SessionManager::subscribe(const std::string& client, const std::string& syscall)
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& session : sessions_)
    {
        if (session.client == client)
        {
            session.subscriptions.insert(syscall);
            return;
        }
    }
}

void SessionManager::unsubscribe(const std::string& client, const std::string& syscall)
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& session : sessions_)
    {
        if (session.client == client)
        {
            session.subscriptions.erase(syscall);
            return;
        }
    }
}

std::set<std::string> SessionManager::getSubscriptions(const std::string& client) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& session : sessions_)
    {
        if (session.client == client)
            return session.subscriptions;
    }

    return {};
}

void SessionManager::forEachSubscriber(const std::string& syscall,
                                        const std::function<void(const ClientSession&)>& fn)
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& session : sessions_)
    {
        if (session.subscriptions.count(syscall))
            fn(session);
    }
}
