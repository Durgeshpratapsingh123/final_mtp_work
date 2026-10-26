#include "tls_server.hpp"

int main()
{
    TLSServer server(8443);

    // initialize() also loads the eBPF monitor program and starts
    // its ring-buffer polling thread; start() then accepts clients,
    // each on its own thread, and dispatches subscribed kernel
    // events to them as they arrive.
    if (!server.initialize())
    {
        return 1;
    }

    server.start();

    return 0;
}
