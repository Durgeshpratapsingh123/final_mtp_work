#include "dispatcher.hpp"

#include <openssl/ssl.h>
#include <sstream>
#include <cstring>
#include <ctime>
#include <iomanip>

Dispatcher::Dispatcher(SessionManager& sessionManager, RedisClient& redisClient)
    : sessionManager_(sessionManager),
      redisClient_(redisClient),
      startTime_(std::chrono::steady_clock::now())
{
    // Relative to build/ (where the proxy binary runs from), matching
    // the ../certs convention already used elsewhere in this project.
    latencyLog_.open("../logs/latency_events.csv", std::ios::app);

    if (latencyLog_.is_open() && latencyLog_.tellp() == 0)
    {
        latencyLog_
            << "kernel_ts_ns,dispatch_ts_ns,latency_ns,pid,comm,syscall,cgroup\n";
        latencyLog_.flush();
    }
}

std::string Dispatcher::syscallName(unsigned int eventType)
{
    switch (eventType)
    {
        case EVENT_OPENAT: return "openat";
        case EVENT_READ:   return "read";
        case EVENT_WRITE:  return "write";
        case EVENT_EXECVE: return "execve";
        default:           return "";
    }
}

uint64_t Dispatcher::monotonicNowNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL
         + static_cast<uint64_t>(ts.tv_nsec);
}

void Dispatcher::recordLatency(const event& e, const std::string& syscall)
{
    // bpf_ktime_get_ns() (kernel side, see monitor.bpf.c) and
    // clock_gettime(CLOCK_MONOTONIC) (here) both measure nanoseconds
    // since boot, so they're directly comparable.
    const uint64_t nowNs = monotonicNowNs();

    if (nowNs < e.timestamp_ns)
        return; // clock skew / bad sample, skip rather than underflow

    const uint64_t latencyNs = nowNs - e.timestamp_ns;

    {
        std::lock_guard<std::mutex> lock(statsMutex_);

        LatencyStats& stats = stats_[syscall];

        stats.count++;
        stats.sumNs += latencyNs;

        if (latencyNs < stats.minNs)
            stats.minNs = latencyNs;

        if (latencyNs > stats.maxNs)
            stats.maxNs = latencyNs;
    }

    std::lock_guard<std::mutex> lock(logMutex_);

    if (latencyLog_.is_open())
    {
        latencyLog_
            << e.timestamp_ns << ','
            << nowNs << ','
            << latencyNs << ','
            << e.pid << ','
            << e.comm << ','
            << syscall << ','
            << e.cgroup_id << '\n';

        // Flush periodically rather than per-line: keeps the data safe
        // if the proxy is killed mid-run without a syscall() per event.
        if (++logLineCount_ % 50 == 0)
            latencyLog_.flush();
    }
}

std::string Dispatcher::formatEvent(const event& e, const std::string& syscall)
{
    std::ostringstream out;

    out << "EVENT syscall=" << syscall
        << " pid="    << e.pid
        << " comm="   << e.comm
        << " file="   << e.filename
        << " cgroup=" << e.cgroup_id
        << " ts="     << e.timestamp_ns
        << '\n';

    return out.str();
}

std::string Dispatcher::statsSummary() const
{
    std::ostringstream out;

    const auto elapsed =
        std::chrono::duration_cast<std::chrono::duration<double>>(
            std::chrono::steady_clock::now() - startTime_).count();

    uint64_t totalCount = 0;

    {
        std::lock_guard<std::mutex> lock(statsMutex_);

        out << std::fixed << std::setprecision(2);

        for (const auto& [syscall, stats] : stats_)
        {
            if (stats.count == 0)
                continue;

            const double avgUs = (stats.sumNs / static_cast<double>(stats.count)) / 1000.0;
            const double minUs = stats.minNs / 1000.0;
            const double maxUs = stats.maxNs / 1000.0;

            out << syscall
                << " count=" << stats.count
                << " avg_us=" << avgUs
                << " min_us=" << minUs
                << " max_us=" << maxUs
                << '\n';

            totalCount += stats.count;
        }
    }

    const double eventsPerSec = elapsed > 0.0 ? totalCount / elapsed : 0.0;

    out << "elapsed_s=" << elapsed
        << " total_events=" << totalCount
        << " events_per_sec=" << eventsPerSec
        << '\n';

    return out.str();
}

// Demo-mode noise filter: the box is constantly full of self-monitoring
// chatter — ps/top-style tools walking /proc/<pid>/*, Redis polling its
// own /proc/self/stat, systemd-oomd reading cgroup pressure files, editors
// polling /proc/<pid>/cmdline to check if a process is still alive, the
// dynamic linker resolving shared libraries and locale data on every
// process start, desktop compositors/browsers touching /dev/shm sockets,
// etc. None of that reflects real tenant activity, so it's dropped before
// dispatch rather than flooding subscribed clients with it.
//
// This is intentionally coarse (path/comm based) for demo readability.
// It is NOT a security or tenant-isolation boundary — Redis authorization
// still governs what a client is allowed to see; this only trims what's
// worth showing. Latency is still recorded for filtered events (see
// dispatch() below), since it measures true pipeline overhead, not just
// what a demo chooses to display.
static bool containsSubstring(const char* haystack, const char* needle)
{
    return std::strstr(haystack, needle) != nullptr;
}

static bool isNoise(const event& e)
{
    static const char* noisyPrefixes[] = {
        "/proc/",
        "/sys/",
        "/dev/shm/",
        "/dev/tty",
        "/dev/null",
        "/dev/fd/",
    };

    for (const char* prefix : noisyPrefixes)
    {
        if (std::strncmp(e.filename, prefix, std::strlen(prefix)) == 0)
            return true;
    }

    // Dynamic-linker / locale lookups: happens on essentially every
    // process start (ld.so.cache, *.so libraries, locale-archive,
    // gettext .mo catalogs, gconv-modules.cache) and swamps a demo
    // with library-loading noise rather than the file the process
    // actually cares about.
    static const char* noisySubstrings[] = {
        "ld.so.cache",
        ".so",
        "/locale",
        "locale-archive",
        "gconv-modules",
        ".config/microsoft-edge",
        ".config/Code",
        "/etc/opt/edge",
        "/usr/share/applications",
    };

    for (const char* needle : noisySubstrings)
    {
        if (containsSubstring(e.filename, needle))
            return true;
    }

    static const char* noisyComms[] = {
        "redis-server",
        "systemd-oomd",
        "systemd-timesyn",
        "Compositor",
        "CompositorTileW",
        "Chrome_ChildIOT",
        "Chrome_IOThread",
        "ThreadPoolForeg",
        "xdg-desktop-por",
        "libuv-worker",
        "tokio-rt-worker",
    };

    for (const char* comm : noisyComms)
    {
        if (std::strcmp(e.comm, comm) == 0)
            return true;
    }

    return false;
}

void Dispatcher::dispatch(const event& e)
{
    const std::string syscall = syscallName(e.event_type);

    if (syscall.empty())
        return;

    // Always measured, even for events the demo filter below hides,
    // so latency/throughput numbers reflect the real pipeline.
    recordLatency(e, syscall);

    if (isNoise(e))
        return;

    const std::string message = formatEvent(e, syscall);

    sessionManager_.forEachSubscriber(syscall, [&](const ClientSession& session)
    {
        // Defense in depth: re-check Redis authorization at dispatch
        // time, in case permissions changed after the client subscribed.
        if (!redisClient_.isAuthorized(session.tenant, syscall))
            return;

        SSL_write(session.ssl, message.c_str(), static_cast<int>(message.size()));
    });
}
