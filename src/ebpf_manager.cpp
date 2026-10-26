#include "ebpf_manager.hpp"

#include <iostream>

EbpfManager::EbpfManager()
    : skel_(nullptr),
      ringBuffer_(nullptr),
      running_(false)
{
}

EbpfManager::~EbpfManager()
{
    stop();

    if (ringBuffer_)
        ring_buffer__free(ringBuffer_);

    if (skel_)
        monitor_bpf__destroy(skel_);
}

void EbpfManager::setEventCallback(std::function<void(const event&)> callback)
{
    callback_ = std::move(callback);
}

int EbpfManager::handleEvent(
    void *ctx,
    void *data,
    size_t len)
{
    auto* self = static_cast<EbpfManager*>(ctx);
    const event *e = static_cast<const event *>(data);

    if (self && self->callback_)
    {
        self->callback_(*e);
    }
    else
    {
        // Fallback: no dispatcher wired up, just log to stdout.
        std::cout
            << e->pid
            << " "
            << e->comm
            << " "
            << e->filename
            << " "
            << e->cgroup_id
            << std::endl;
    }

    return 0;
}

bool EbpfManager::initialize()
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel_ = monitor_bpf__open();

    if (!skel_)
    {
        std::cerr
            << "Failed to open skeleton\n";
        return false;
    }

    if (monitor_bpf__load(skel_))
    {
        std::cerr
            << "Failed to load BPF\n";
        return false;
    }

    if (monitor_bpf__attach(skel_))
    {
        std::cerr
            << "Failed to attach BPF\n";
        return false;
    }

    ringBuffer_ =
        ring_buffer__new(
            bpf_map__fd(skel_->maps.events),
            handleEvent,
            this,
            nullptr);

    if (!ringBuffer_)
    {
        std::cerr
            << "Failed to create ring buffer\n";
        return false;
    }

    std::cout
        << "eBPF Manager initialized.\n";

    return true;
}

void EbpfManager::run()
{
    running_ = true;

    std::cout
        << "Waiting for kernel events...\n";

    while (running_)
    {
        int err =
            ring_buffer__poll(
                ringBuffer_,
                100);

        if (err == -EINTR)
            break;

        if (err < 0)
        {
            std::cerr
                << "Ring buffer error\n";
            break;
        }
    }
}

void EbpfManager::stop()
{
    running_ = false;
}
