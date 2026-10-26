# SecureProxy: Secure Multi-Tenant eBPF Event Proxy

## Project Overview

SecureProxy is a secure multi-tenant event distribution framework built on top of eBPF. It securely streams kernel events to authorized clients using Mutual TLS authentication and Redis-based authorization.

The project is designed as part of an M.Tech Major Technical Project (MTP) to provide secure, scalable, and tenant-aware observability.

---

# Architecture

```
                +----------------------+
                |      Client          |
                +----------+-----------+
                           |
                     Mutual TLS
                           |
                           ▼
                +----------------------+
                |     Secure Proxy     |
                |----------------------|
                | TLS Authentication   |
                | Session Manager      |
                | Redis Validation     |
                | Authorization        |
                +----------+-----------+
                           |
                           ▼
                       Redis Server
                           |
                           ▼
                    (Future Integration)
                           |
                           ▼
                     eBPF Event Stream
                           |
                           ▼
                        Linux Kernel
```

---

# Technologies Used

- C++17
- eBPF
- libbpf
- OpenSSL
- Redis
- CMake
- Linux Socket Programming

---

# Project Structure

```
SecureProxy/
│
├── certs/
│   ├── ca/
│   ├── server/
│   ├── clients/
│   └── generate_certs.sh
│
├── include/
│   ├── tls_server.hpp
│   ├── redis_client.hpp
│   ├── session_manager.hpp
│   ├── ebpf_manager.hpp
│   └── ...
│
├── src/
│   ├── proxy.cpp
│   ├── tls_server.cpp
│   ├── redis_client.cpp
│   ├── session_manager.cpp
│   ├── ebpf_manager.cpp
│   └── ...
│
├── client/
│
├── build/
│
└── CMakeLists.txt
```

---

# Features Implemented

## 1. Secure TLS Server

Implemented a TCP server secured using OpenSSL.

Features:

- TLS Server
- SSL Context
- Certificate Loading
- Private Key Verification
- CA Verification

---

## 2. Mutual TLS Authentication

Implemented complete Mutual TLS authentication.

### Server

- Loads server certificate
- Loads server private key
- Verifies client certificate
- Validates certificate chain

### Client

- Uses client certificate
- Uses client private key
- Authenticated using Root CA

---

## 3. Certificate Infrastructure

Created complete PKI.

Generated:

- Root CA
- Server Certificate
- Client Certificate

Certificate generation automated using:

```
generate_certs.sh
```

Certificate hierarchy:

```
Root CA
   │
   ├── Server Certificate
   └── Client Certificate
```

---

## 4. Certificate Parsing

Extracted identity information from X.509 certificates.

Fields extracted:

- Country
- State
- Organization
- Organizational Unit (Tenant)
- Common Name (Client)

Example:

```
Country      : IN
State        : West Bengal
Organization : IIT Kharagpur
Tenant       : TenantA
Client       : client01
```

---

## 5. Session Manager

Implemented secure client session management.

Each session stores:

- Tenant
- Client
- Client IP
- SSL Connection

Operations implemented:

- Add Session
- Remove Session
- Print Active Sessions

Example:

```
========== Active Sessions ==========
Tenant : TenantA
Client : client01
IP     : 127.0.0.1
=====================================
```

---

## 6. Redis Integration

Integrated Redis with SecureProxy.

Implemented:

- Redis Connection
- Redis Disconnection
- Command Execution

Verified using:

```
redis-cli
```

---

## 7. Tenant Validation

Implemented Redis-backed tenant authentication.

Function:

```cpp
tenantExists(tenant)
```

Workflow:

```
Certificate

↓

Extract Tenant

↓

Redis Lookup

↓

Valid ?

↓

Allow / Reject
```

Example:

```
TenantA : 1

TenantB : 1

HackerTenant : 0
```

---

## 8. Authorization

Implemented syscall-level authorization.

Redis stores permissions as Sets.

Example:

```
TenantA

↓

openat
read
write
```

Functions implemented:

```cpp
isAuthorized()
```

Example:

```
TenantA + openat

↓

Allowed
```

```
TenantA + execve

↓

Denied
```

---

## 9. Secure Client Protocol

Implemented a simple application-layer protocol over TLS.

Supported command:

```
SUBSCRIBE <syscall>
```

Example:

```
SUBSCRIBE openat
```

Server checks Redis authorization.

Responses:

```
OK
```

or

```
DENIED
```

Example:

```
Client

↓

SUBSCRIBE openat

↓

Redis

↓

Allowed

↓

OK
```

---

## 10. Persistent TLS Sessions

The server now maintains persistent TLS connections.

Workflow:

```
TLS Handshake

↓

Authenticate

↓

Validate Tenant

↓

Create Session

↓

Wait for Commands

↓

Disconnect

↓

Remove Session
```

---

## 11. Build System

Implemented CMake-based build system.

```
mkdir build
cd build

cmake ..

make
```

---

# Current Execution Flow

```
Client

↓

TCP Connection

↓

TLS Handshake

↓

Certificate Verification

↓

Extract Tenant

↓

Redis Validation

↓

Create Session

↓

SUBSCRIBE openat

↓

Redis Authorization

↓

OK / DENIED

↓

(Client remains connected)
```

---

# Current Status

| Module | Status |
|---------|--------|
| TLS Server | ✅ |
| Mutual TLS | ✅ |
| Certificate Parsing | ✅ |
| Session Manager | ✅ |
| Redis Connectivity | ✅ |
| Tenant Validation | ✅ |
| Authorization | ✅ |
| Client Protocol | ✅ |
| Persistent Connections | ✅ |
| CMake Build | ✅ |
| Certificate Generator | ✅ |
| eBPF Manager | ✅ |
| Event Dispatcher | ✅ |
| Kernel Event Streaming | ✅ |
| Multi-client Event Distribution | ✅ |

---

# eBPF Integration

The eBPF monitor program (`monitor.bpf.c`, `monitor.h`, `monitor.skel.h`,
`vmlinux.h`) now lives under `ebpf/` and is compiled directly into the
`proxy` binary:

- `EbpfManager` (`include/ebpf_manager.hpp`, `src/ebpf_manager.cpp`) loads,
  attaches, and polls the BPF skeleton's ring buffer on its own thread, and
  invokes a caller-supplied `std::function<void(const event&)>` callback
  for every kernel event instead of just printing it.
- `Dispatcher` (`include/dispatcher.hpp`, `src/dispatcher.cpp`) is that
  callback target: it maps the event's `event_type` to a syscall name,
  asks `SessionManager` which connected clients are subscribed to it,
  re-checks Redis authorization for each one (in case permissions changed
  after the client subscribed), and writes the event line to their TLS
  socket.
- `TLSServer::initialize()` wires `EbpfManager` to `Dispatcher` and starts
  the polling thread; `TLSServer::start()` now spawns a detached thread per
  accepted client (`serveClient`) instead of blocking on one connection at
  a time, so multiple tenants can stay subscribed concurrently.
- `SessionManager` and `RedisClient` gained internal mutexes since they're
  now called from the accept thread, each client thread, and the eBPF
  thread simultaneously.

Note: `monitor.h` originally used the vmlinux-only `u32`/`u64` aliases,
which don't exist in plain userspace headers — it's been switched to the
portable `__u32`/`__u64` types from `<linux/types.h>` so it compiles
cleanly on both the BPF and userspace (EbpfManager/Dispatcher) sides.

### Subscription Engine

Supported client commands:

```
SUBSCRIBE openat

UNSUBSCRIBE openat

LIST

STATS

QUIT
```

### Performance Instrumentation (for MTP result collection)

`Dispatcher` times every kernel event from `bpf_ktime_get_ns()` capture
(set in `monitor.bpf.c`) to the moment it reaches `Dispatcher::dispatch()`
in userspace, using `clock_gettime(CLOCK_MONOTONIC)` — the two clocks are
directly comparable since both measure time since boot. This is the
latency the eBPF Proxy Observer architecture itself adds on top of the
kernel event happening (ring-buffer transit + poll-thread wakeup), which
is the number to cite when comparing against a conventional per-tenant
probe approach.

Two ways to pull it:

- **Live, via a connected client:** send `STATS` (any subscribed client
  can do this). Returns per-syscall `count`, `avg_us`, `min_us`, `max_us`,
  plus overall `elapsed_s`, `total_events`, `events_per_sec`.
- **Raw, for offline analysis/graphs:** every event (including ones the
  demo noise filter hides from clients) is appended to
  `logs/latency_events.csv` as it happens:
  `kernel_ts_ns,dispatch_ts_ns,latency_ns,pid,comm,syscall,cgroup`.
  Load that into a notebook/spreadsheet for distributions, percentiles,
  or before/after comparison plots. The file is opened in append mode,
  so it accumulates across restarts — delete it to start a fresh run.

Latency is recorded for *every* event regardless of the demo filter, so
these numbers reflect true pipeline overhead, not just what's shown on
screen.

### Secure Event Streaming

```
Kernel

↓

eBPF (monitor.bpf.c)

↓

Ring Buffer

↓

EbpfManager → Dispatcher

↓

Authorized, Subscribed Clients (TLS)
```

---

# Known Limitations / Next Steps

- Only `sys_enter_openat` is currently instrumented in `monitor.bpf.c`;
  `read`/`write`/`execve` are defined in the `event_type` enum but have no
  attached tracepoint yet.
- Authorization is per-tenant/per-syscall via Redis, not per-namespace —
  every subscribed, authorized client receives the same system-wide
  event stream rather than events scoped to their own container/namespace.
  (Namespace-scoped fan-out is the direction of the MTP thesis work.)
- `redis-server` must be running on `127.0.0.1:6379` with `tenants` and
  per-tenant permission sets populated (see `Tenant Validation` /
  `Authorization` sections above) before starting `proxy`.
- Loading/attaching the BPF program requires `CAP_BPF`/`CAP_SYS_ADMIN`
  (i.e. run `proxy` as root or with the appropriate capabilities).
- The recorded latency covers kernel-capture → `Dispatcher::dispatch()`
  entry only; it does not include the final `SSL_write()` to each client,
  which is comparatively small and network/TLS-dependent rather than a
  property of the eBPF pipeline itself.
- `Dispatcher` drops a set of self-monitoring/startup noise before
  dispatch: any `/proc/*`, `/sys/*`, or `/dev/tty` open; Chromium's
  `/dev/shm/.org.chromium.*` sockets; dynamic-linker and locale lookups
  (`ld.so.cache`, `*.so` libraries, `locale-archive`, `.mo` catalogs,
  `gconv-modules.cache`) that happen on nearly every process start; and
  events from `redis-server`, `systemd-oomd`, `systemd-timesyncd`, and
  desktop compositor/browser helper processes. On a typical desktop that
  chatter otherwise drowns out real demo activity. It's a coarse,
  readability-only filter (see the comment above `isNoise()` in
  `src/dispatcher.cpp`), not a tenant/security boundary; Redis
  authorization is still what actually gates what a client can see.
  Edit `noisyPrefixes`/`noisySubstrings`/`noisyComms` there to tune it.

---

# Project Goal

The final objective is to build a secure, scalable, multi-tenant eBPF observability platform capable of:

- Collecting kernel events using eBPF
- Authenticating clients using Mutual TLS
- Validating tenants using Redis
- Enforcing authorization policies
- Streaming only authorized events over encrypted TLS channels

---

# Author

Durgesh Pratap Singh

M.Tech, Computer Science and Engineering

Indian Institute of Technology Kharagpur