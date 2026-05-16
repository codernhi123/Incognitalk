# E2EE TCP IPv6 Group Chat — C / POSIX / OpenSSL

> A high-performance, End-to-End Encrypted group chat application built from scratch in C, using raw POSIX sockets, `epoll`, `pthreads`, and OpenSSL — with a custom binary TLV protocol over IPv6 TCP.
>
> **v1.1:** Server upgraded from single-threaded `epoll` to a hybrid `epoll` + bounded thread pool architecture for multi-core parallelism.

---

## Table of Contents

- [Objective](#-objective)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Approach & Design](#-approach--design)
- [Implementation Details](#-implementation-details)
- [Pros, Cons & Future Improvements](#-pros-cons--future-improvements)
- [Benchmarking](#-benchmarking)

---

## Objective

Build a **group chat system** where:
- Multiple clients can create or join named rooms over **IPv6 TCP**
- All chat messages are **end-to-end encrypted** — the server never sees plaintext
- The system is resilient to **fd-recycling (ABA)** bugs and handles **partial TCP reads** correctly via a strict binary framing protocol
- The system is processed **concurrently** in **parrallel CPU cores**, optimizing CPU utilization to achieve **high throughputs**.
- The entire stack — networking, concurrency, and cryptography — is implemented using **low-level POSIX and OpenSSL APIs**, with no high-level frameworks

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Language** | C (POSIX APIs) |
| **Networking** | IPv6, Non-blocking sockets (`O_NONBLOCK`) |
| **I/O Multiplexing** | `epoll` (Level-Triggered) |
| **Concurrency** | `pthreads` (Producer-Consumer model) |
| **Cryptography** | OpenSSL — `EVP_*` APIs, Memory BIOs |
| **Symmetric Encryption** | AES-256-CBC, fresh 16-byte IV per message |
| **Asymmetric Encryption** | RSA-2048-OAEP (ephemeral keypairs, in-RAM only) |
| **Build System** | CMake |
| **Dev Environment** | WSL 2 (Ubuntu), VS Code |

---

## Getting Started

### Prerequisites

```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

### Build

```bash
git clone <git@github.com:codernhi123/Incognitalk.git>
cd <incognitication> # Don't worry about the mis-matched name
cmake -S . -B build
cmake --build build
cd build
# Then run the compiled files below
```

### Run

**Terminal 1 — Start the server:**
```bash
./server <port> <MAX_CLIENTS> 
```

**Terminal 2 — Start a host client (creates a room):**
```bash
./client <IP> <PORT> <Hoster_Boolean> <GroupID> <log_path>
# Hoster_Boolean = 1
# GroupID = [Random integer] since we don't care for hoster's groupID
```

**Terminal 3 — Start a joining client:**
```bash
./client <IP> <PORT> <Hoster_Boolean> <GroupID> <log_path>
# Hoster_Boolean = 0
# GroupID = [ID given to the Hoster]
```

**In-band commands:**
| Command | Description |
|---|---|
| `/exit` | Gracefully disconnect |

---

## Approach & Design

### 1. High-Level Architecture

<img src="./img/ArchitectureDiagramV1.1.png" width="100%"/>

The system has two binaries: `server` and `client`. The server runs a **hybrid `epoll` + thread pool** architecture — the main thread is a dedicated event-loop that accepts connections and detects readable sockets, then delegates all message processing to a pool of worker threads. Each client runs a **two-thread Producer-Consumer model**: one thread drives the `epoll` network loop, the other reads stdin and sends messages.

---

### 2. Client State Machine

Each client follows a strict 4-state handshake before it can chat:

```
STATE_JUST_CONNECTED
        │
        ▼  (sends TYPE 4 or TYPE 0)
STATE_WAITING_FOR_KEY
        │
        ▼  (receives TYPE 2 key exchange)
STATE_IN_ROOM
        │
        ▼  (/exit → TYPE 3)
STATE_DISCONNECTED
```

---

### 3. Cryptographic Handshake

The system uses a **Hybrid E2EE model**:

1. On startup, every client generates an **ephemeral RSA-2048 keypair entirely in RAM** (via OpenSSL Memory BIOs — keys are never written to disk)
2. A joining client sends its **public key** to the server alongside its `TYPE 0` Join frame
3. The server forwards the public key to the **Room Host**
4. The Host encrypts the **shared AES-256 symmetric key** with the newcomer's RSA public key (OAEP padding) and signs the bundle
5. The server forwards the `TYPE 2` Key Exchange frame to the newcomer
6. From this point, all `TYPE 1` Chat frames carry: `<Sender ID> | <16-byte IV> | <AES-256 Ciphertext>`

Because keypairs are ephemeral, there is **no persistent identity** — each session is cryptographically isolated.

---

### 4. TLV Binary Protocol (Details in 'TLVBinaryProtocal.md')

Every TCP transmission uses a fixed **Type-Length-Value** binary frame. There are no newline delimiters — this correctly handles TCP's stream-oriented nature and partial reads.

```
┌──────────┬──────────────────────┬─────────────────────────────┐
│  Type    │  Payload Length      │  Payload                    │
│  1 byte  │  2 bytes (Big-Endian)│  <Length> bytes             │
└──────────┴──────────────────────┴─────────────────────────────┘
```

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0` | Join | Newcomer → Server → Host | `<Group ID> <Public Key>` |
| `1` | Chat | Client ↔ Server ↔ Clients | `<Sender ID> <IV> <Ciphertext>` |
| `2` | Key Exchange | Host → Server → Newcomer | `<Target ID> <Host Pubkey> <Encrypted SymKey> <Signature>` |
| `3` | Leave | Client → Server | *(graceful disconnect)* |
| `4` | Host Init | Host → Server | Server responds with `<Group ID>` |

---

## Implementation Details

### Server: `epoll` + Thread Pool + ABA-Safe Client IDs (v1.1)
 
**Architecture overview — two layers:**
 
- **Main thread (event loop):** Runs `epoll_wait` in a tight loop. It handles only two responsibilities: accepting new connections and detecting which existing clients have data ready to read. When a client socket becomes readable, the main thread pushes the client's `Client_Metadata*` pointer into a circular task queue and posts a semaphore — then immediately goes back to `epoll_wait`. It does zero message processing itself.
- **Worker thread pool:** `sysconf(_SC_NPROCESSORS_ONLN)` threads are spawned at startup, each blocking on `sem_wait`. When woken, a worker pulls one `Client_Metadata*` from the circular task queue (protected by a `pthread_mutex`) and calls `message_processor()` to handle all state transitions, frame parsing, and message forwarding for that client.
**Key design decisions extracted from the code:**
 
- **`EPOLLONESHOT`:** Every client fd is registered with `EPOLLONESHOT`. Once `epoll` fires for a client, it is automatically disarmed — no other thread can be woken for the same fd concurrently. After the worker finishes processing, it re-arms the fd via `epoll_ctl(EPOLL_CTL_MOD)`. This eliminates the need for per-socket read locks between worker threads.
- **Read quota (`READ_QUOTA = 8192`):** Each worker reads at most 8 192 bytes per dispatch cycle. If a client sends a burst larger than the quota, the remainder is handled in the next `epoll` firing — preventing one chatty client from starving others in the queue. This ensures fair-treatment (adapted from Round-robin Scheduling) to all waiting tasks.
- **Circular task queue (size 100 000):** A fixed-size ring buffer stores `Client_Metadata*` pointers. The main thread writes at `queue_rear`; workers consume from `queue_front`. Both ends are protected by a single `pthread_mutex`. If the queue fills (overflow guard), the server aborts rather than silently dropping events.
- **ABA-safe client IDs:** Each accepted connection is assigned a unique `uint16_t client_id` (monotonically incrementing `CLIENTS_CNT`). The `Client_Metadata*` pointer lives in `epoll_event.data.ptr` for O(1) dispatch — no hash map lookup. Because identity is tied to the pointer and ID rather than the raw fd number, fd recycling by the OS cannot cause stale-pointer misdirection.
- **Reference counting (`atomic ref_count`):** Each `Client_Metadata` struct is reference-counted using C11 atomics. The epoll/main track holds one reference; the room holds one reference per member. Workers temporarily increment the count before operating on a target client and decrement after. The struct is `free()`'d only when the count reaches zero — preventing use-after-free across concurrent worker threads.


### Client: Producer-Consumer Threading

- **Consumer (main) thread:** Consumer thread - handles incoming data sent from the Server concurrently.
- **Producer (secondary) thread:** Producer thread - activates automatic handshake procedure, handling send message through STDIN input and pipe through encrypting workflow before sending.
- **Condition Variables and Mutexes** are used throughout the structure to ensure serializing when needed to prevent from race cases, while allowing concurrence and parrallel executions to occur.
- **Encryption and decryption** are only executed in Client-side's code, ensuring data's confidentiality and protect from unwanted interference to the server.

### Non-blocking I/O & Partial Reads

- All sockets are set to `O_NONBLOCK`
- The TLV framing ensures the receiver always knows exactly how many bytes to expect, correctly handling **partial TCP reads** that would break newline-delimited protocols

### Cryptography: Memory-Only Keypairs

- RSA keypairs are generated and stored **only in OpenSSL Memory BIOs** — they are never serialized to disk, preventing key leakage via filesystem artifacts
- AES-256-CBC uses a **fresh `RAND_bytes()` IV per message**, ensuring ciphertext non-determinism even for repeated plaintexts

---

## Pros, Cons & Future Improvements

### Pros

- **True E2EE:** The server routes encrypted blobs — it has zero access to plaintext messages
- **Correct TCP handling:** TLV framing eliminates delimiter-based parsing bugs and handles stream fragmentation properly
- **ABA-safe design:** Unique `client_id` decouples identity from the raw socket fd lifecycle
- **Minimal trusted surface:** Ephemeral keypairs mean no persistent key material to compromise
- **Multi-core server (v1.1):** The `epoll` + thread pool design keeps the event loop lean (accept + enqueue only) while worker threads saturate all CPU cores for message processing — context switches are bounded by the physical CPU cores, hence approaches much higher throughput and utilization than v1.0.

### Cons

- **No persistent identity / authentication:** Because keypairs are ephemeral, there is no way to verify a returning user is who they claim to be — a malicious server could perform a MITM during the key exchange.
- **Host has to stay until the end:** For simplicity, my project assumes that Hosting client has to stay in the room until everyone left, this could be fixed by changing Hoster dynamically. 
- **Host has to endure higher load for larger scale:** Hosting client is responsible for secret key distribution, hence as it scales, hardware of hoster has more task to do.

### What Could Be Improved

*High Architecture Level:*

- **Authenticated Key Exchange:** Replace the bare RSA key distribution with a proper **Station-to-Station (STS)** or **Signal-style X3DH** protocol to prevent MITM during handshake
- **Forward Secrecy per message:** Replace the static per-room AES key with a **Double Ratchet**-style key derivation so compromising one message key doesn't expose past messages
- **Distribute the load for Hoster**: Instead of having 1 Hoster, anyone could be doing key distribution and will be decided by the server to lower the load from the current unique Hoster.

*Lower Level, more into details:*

- **Host re-keying:** Implement a host-migration protocol so the server can designate a new host if the original disconnects, re-distributing the symmetric key
- **Message sequence numbers:** Add a `uint32_t seq` field to `TYPE 1` frames to detect replay attacks and out-of-order delivery

---

## Benchmarking

> **Coming Soon**

Planned stress tests to validate the server's `epoll`-based architecture under load (Update v1.1):

- **100,000 connections** — verify the server holds concurrent connections without fd exhaustion or memory leaks
- **200,000 messages/sec throughput** — measure end-to-end message relay rate under sustained load, including AES encryption/decryption overhead on the client side

Results and methodology will be documented here once testing is complete.

---


<p align="center">
  Built with C, POSIX, and OpenSSL &nbsp;·&nbsp; Developed on WSL 2 (Ubuntu) &nbsp;·&nbsp; Done it with Love and Passion
</p>
