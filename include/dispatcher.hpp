#pragma once

#include "monitor.h"
#include "session_manager.hpp"
#include "redis_client.hpp"

#include <string>
#include <mutex>
#include <unordered_map>
#include <fstream>
#include <cstdint>
#include <chrono>

// Per-syscall latency accumulator. All times are nanoseconds, measured
// as (userspace-observed-time - e.timestamp_ns), i.e. kernel event
// capture -> Dispatcher::dispatch() entry. That covers ring-buffer
// transit + poll-thread wakeup latency, which is the overhead the
// eBPF Proxy Observer architecture itself adds on top of the kernel
// event actually happening.
struct LatencyStats
{
    uint64_t count = 0;
    uint64_t sumNs = 0;
    uint64_t minNs = UINT64_MAX;
    uint64_t maxNs = 0;
};

// Bridges the eBPF ring-buffer callback (background thread) to the
// TLS client sessions: for every kernel event it looks up which
// connected clients are subscribed to that syscall, re-checks Redis
// authorization, and writes the event to their TLS socket.
class Dispatcher
{
public:
    Dispatcher(SessionManager& sessionManager, RedisClient& redisClient);

    // Called from EbpfManager's ring-buffer poll thread.
    void dispatch(const event& e);

    // Human-readable summary of accumulated latency stats and overall
    // throughput since the proxy started. Safe to call from any thread
    // (e.g. a client's "STATS" request).
    std::string statsSummary() const;

private:
    static std::string syscallName(unsigned int eventType);
    static std::string formatEvent(const event& e, const std::string& syscall);
    static uint64_t monotonicNowNs();

    // Records kernel->dispatch latency for every event (regardless of
    // the demo noise filter below), and appends a raw CSV line for
    // offline analysis/plotting.
    void recordLatency(const event& e, const std::string& syscall);

    SessionManager& sessionManager_;
    RedisClient& redisClient_;

    mutable std::mutex statsMutex_;
    std::unordered_map<std::string, LatencyStats> stats_;

    std::mutex logMutex_;
    std::ofstream latencyLog_;
    uint64_t logLineCount_ = 0;

    std::chrono::steady_clock::time_point startTime_;
};
