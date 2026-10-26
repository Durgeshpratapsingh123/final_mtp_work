#pragma once

#include <bpf/libbpf.h>
#include <atomic>
#include <functional>

#include "monitor.h"
#include "monitor.skel.h"

class EbpfManager
{
public:
    EbpfManager();
    ~EbpfManager();

    // Called from run()'s polling thread for every kernel event
    // pulled off the ring buffer. Set this before calling run().
    void setEventCallback(std::function<void(const event&)> callback);

    bool initialize();

    // Blocks, polling the ring buffer, until stop() is called.
    // Intended to be run on its own thread.
    void run();

    void stop();

private:
    static int handleEvent(void* ctx, void* data, size_t len);

    monitor_bpf* skel_;
    ring_buffer* ringBuffer_;
    std::function<void(const event&)> callback_;
    std::atomic<bool> running_;
};
