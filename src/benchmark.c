/****************************************************************************************************************
  benchmark.c — Stress-test the Incognitication server (threaded non‑hosters for 30K+ scalability)

  Usage: ./benchmark <num_non_hosters> <server_port>

  Flow:
   1. Fork + exec the server binary
   2. Fork 1 host
   3. Spawn X non‑hoster pthreads — each does full RSA keygen, key exchange,
      barrier sync, sends "Hello world", then leaves
   4. After all non‑hoster threads exit, the host leaves
   5. The server prints [BENCHMARK] Peak concurrent clients in room 0: N
****************************************************************************************************************/

#define _GNU_SOURCE
#include "client.h"          /* RSA_Keypair, AES_KEY_LEN, crypto prototypes, error_handle */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/resource.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* shared-memory barrier  (process‑shared via mmap MAP_SHARED)        */
/* ------------------------------------------------------------------ */
struct barrier {
  volatile int ready_count;
  volatile int go_flag;
  int total;
};

/* ------------------------------------------------------------------ */
/* tiny I/O helpers                                                   */
/* ------------------------------------------------------------------ */
static int write_all(int fd, const void *buf, size_t len) {
  const char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    p += n;
    len -= n;
  }
  return 0;
}

static int read_exact(int fd, void *buf, size_t len) {
  char *p = buf;
  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return -1;
    p += n;
    len -= n;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* wire-protocol send / recv (with error checking)                    */
/* ------------------------------------------------------------------ */
static int send_msg(int fd, uint8_t type, const uint8_t *payload,
                    uint16_t plen) {
  uint8_t hdr[3];
  hdr[0] = type;
  uint16_t net = htons(plen);
  memcpy(hdr + 1, &net, 2);
  if (write_all(fd, hdr, 3) < 0) return -1;
  if (plen && write_all(fd, payload, plen) < 0) return -1;
  return 0;
}

static int recv_msg(int fd, uint8_t *type, uint8_t *payload, int max_payload) {
  uint8_t hdr[3];
  if (read_exact(fd, hdr, 3) < 0) return -1;
  *type = hdr[0];
  uint16_t plen;
  memcpy(&plen, hdr + 1, 2);
  plen = ntohs(plen);
  if (plen > (uint16_t)max_payload) return -1;
  if (plen && read_exact(fd, payload, plen) < 0) return -1;
  return (int)plen;
}

/* ------------------------------------------------------------------ */
/* connect (IPv4 → mapped IPv6), retry up to 60s                      */
/* ------------------------------------------------------------------ */
static int connect_server(const char *ip_str, int port) {
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd < 0) error_handle("bench socket");

  struct sockaddr_in6 addr6;
  memset(&addr6, 0, sizeof(addr6));
  addr6.sin6_family = AF_INET6;
  addr6.sin6_port = htons(port);

  if (inet_pton(AF_INET6, ip_str, &addr6.sin6_addr) <= 0) {
    struct in_addr a4;
    if (inet_pton(AF_INET, ip_str, &a4) > 0) {
      char mapped[64];
      snprintf(mapped, sizeof(mapped), "::ffff:%s", ip_str);
      if (inet_pton(AF_INET6, mapped, &addr6.sin6_addr) <= 0)
        error_handle("inet_pton mapped");
    } else {
      error_handle("inet_pton");
    }
  }

  for (int attempt = 0; attempt < 240; attempt++) {
    if (connect(fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0)
      return fd;
    usleep(250000);
  }
  error_handle("connect – server not reachable");
  return -1;
}

/* ================================================================== */
/*  HOST process                                                       */
/* ================================================================== */
static void run_host(const char *ip, int port) {
  int fd = connect_server(ip, port);

  RSA_Keypair kp;
  memset(&kp, 0, sizeof(kp));
  if (generate_rsa_keypair(&kp) < 0) error_handle("host keypair");
  int pubkey_len = (int)strlen(kp.public_key_pem);

  unsigned char shared_key[2048];
  if (generate_symmetric_key(shared_key) < 0) error_handle("host symkey");

  send_msg(fd, 4, NULL, 0); /* create room */

  uint8_t type, buf[4096];
  int plen = recv_msg(fd, &type, buf, (int)sizeof(buf));
  if (plen < 4 || type != 4) error_handle("host expected type 4");

  int non_hosters = 0;

  for (;;) {
    plen = recv_msg(fd, &type, buf, (int)sizeof(buf));
    if (plen < 0) break;

    if (type == 0) {
      uint16_t cid;
      memcpy(&cid, buf, 2);
      cid = ntohs(cid);
      int pkey_len = plen - 2;

      char peer_pubkey[2048] = {0};
      if (pkey_len > (int)sizeof(peer_pubkey) - 1)
        error_handle("peer pubkey too large");
      memcpy(peer_pubkey, buf + 2, pkey_len);
      non_hosters++;

      unsigned char enc_key[256];
      size_t ek_len = sizeof(enc_key);
      if (rsa_encrypt_with_public_key(peer_pubkey, shared_key, AES_KEY_LEN,
                                      enc_key, &ek_len) < 0)
        error_handle("host rsa_encrypt");

      unsigned char sig[256];
      size_t sig_len = sizeof(sig);
      if (rsa_sign_with_private_key(kp.private_key_pem, enc_key, ek_len,
                                    sig, &sig_len) < 0)
        error_handle("host rsa_sign");

      uint8_t p2[4096];
      uint16_t nc = htons(cid);
      memcpy(p2, &nc, 2);
      memcpy(p2 + 2, kp.public_key_pem, pubkey_len);
      memcpy(p2 + 2 + pubkey_len, enc_key, ek_len);
      memcpy(p2 + 2 + pubkey_len + ek_len, sig, sig_len);
      uint16_t p2len = 2 + (uint16_t)pubkey_len + (uint16_t)ek_len +
                       (uint16_t)sig_len;
      send_msg(fd, 2, p2, p2len);

    } else if (type == 3) {
      non_hosters--;
      if (non_hosters == 0) {
        send_msg(fd, 3, NULL, 0);
        break;
      }
    }
  }
  shutdown(fd, SHUT_WR);
  { uint8_t d[64]; while (read(fd, d, sizeof(d)) > 0) {} }
  close(fd);
}

/* ================================================================== */
/*  NON-HOSTER thread data                                             */
/* ================================================================== */
struct nh_args {
  const char *ip;
  int port;
  uint32_t gid;
  struct barrier *bar;
};

/* ================================================================== */
/*  NON-HOSTER thread function                                         */
/* ================================================================== */
static void *run_nonhoster_thread(void *arg) {
  struct nh_args *a = (struct nh_args *)arg;
  int fd = connect_server(a->ip, a->port);

  RSA_Keypair kp;
  memset(&kp, 0, sizeof(kp));
  if (generate_rsa_keypair(&kp) < 0) { _exit(1); }
  int pkey_len = (int)strlen(kp.public_key_pem);

  /* join room */
  uint8_t join[4096];
  uint32_t ng = htonl(a->gid);
  memcpy(join, &ng, 4);
  memcpy(join + 4, kp.public_key_pem, pkey_len);
  if (send_msg(fd, 0, join, 4 + (uint16_t)pkey_len) < 0) {
    close(fd); return (void *)(intptr_t)-1;
  }

  /* wait for key (type 2) */
  uint8_t type, buf[4096];
  int plen;
  unsigned char shared_key[2048];
  int got_key = 0;

  while (!got_key) {
    plen = recv_msg(fd, &type, buf, (int)sizeof(buf));
    if (plen < 0) { close(fd); return (void *)(intptr_t)-2; }
    if (type == 2) {
      int hpk_len = plen - 512;
      char host_pubkey[2048] = {0};
      memcpy(host_pubkey, buf, hpk_len);
      unsigned char *enc_key = buf + hpk_len;
      unsigned char *sig = buf + hpk_len + 256;

      if (rsa_verify_with_public_key(host_pubkey, enc_key, 256, sig, 256) < 0) {
        close(fd); return (void *)(intptr_t)-3;
      }
      size_t out_len = 2048;
      if (rsa_decrypt_with_private_key(kp.private_key_pem, enc_key, 256,
                                       shared_key, &out_len) < 0) {
        close(fd); return (void *)(intptr_t)-4;
      }
      got_key = 1;
    }
  }

  /* barrier: signal ready, wait for go */
  __sync_fetch_and_add(&a->bar->ready_count, 1);
  while (!__atomic_load_n(&a->bar->go_flag, __ATOMIC_ACQUIRE))
    usleep(1000);

  /* send "Hello world" */
  unsigned char iv[16];
  if (RAND_bytes(iv, sizeof(iv)) != 1) { close(fd); return (void *)(intptr_t)-5; }
  const char *pt = "Hello world";
  int pt_len = (int)strlen(pt);
  unsigned char ct[1024];
  int ct_len = aes_encrypt((const unsigned char *)pt, pt_len, shared_key,
                           iv, ct);
  if (ct_len < 0) { close(fd); return (void *)(intptr_t)-6; }

  uint8_t chat[1040];
  memcpy(chat, iv, 16);
  memcpy(chat + 16, ct, ct_len);
  send_msg(fd, 1, chat, 16 + (uint16_t)ct_len);

  /* leave */
  send_msg(fd, 3, NULL, 0);
  shutdown(fd, SHUT_WR);
  { uint8_t d[64]; while (read(fd, d, sizeof(d)) > 0) {} }
  close(fd);
  return NULL;
}

/* ================================================================== */
/*  MAIN                                                               */
/* ================================================================== */
int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <num_non_hosters> <server_port>\n", argv[0]);
    return 1;
  }
  int X = atoi(argv[1]);
  int port = atoi(argv[2]);

  if (X < 1) {
    fprintf(stderr, "num_non_hosters must be >= 1\n");
    return 1;
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_DFL);

  /* ---- shared barrier ---- */
  struct barrier *bar = mmap(NULL, sizeof(*bar),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bar == MAP_FAILED) error_handle("mmap barrier");
  memset((void*)bar, 0, sizeof(*bar));
  bar->total = X;

  /* ---- spawn server ---- */
  pid_t spid = fork();
  if (spid < 0) error_handle("fork server");
  if (spid == 0) {
    char pstr[16], mstr[16];
    snprintf(pstr, sizeof(pstr), "%d", port);
    snprintf(mstr, sizeof(mstr), "%d", X + 10);
    execl("./server", "./server", pstr, mstr, NULL);
    execl("./build/server", "./build/server", pstr, mstr, NULL);
    perror("execl server");
    _exit(1);
  }

  sleep(2);

  /* ---- spawn host ---- */
  pid_t hpid = fork();
  if (hpid < 0) error_handle("fork host");
  if (hpid == 0) {
    run_host("127.0.0.1", port);
    _exit(0);
  }

  sleep(1);

  /* ---- spawn X non-hoster threads ---- */
  pthread_t *threads = (pthread_t *)malloc((size_t)X * sizeof(pthread_t));
  struct nh_args *args = (struct nh_args *)malloc((size_t)X * sizeof(struct nh_args));

  /* use small thread stacks so 30K threads don't exhaust virtual memory */
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 256 * 1024); /* 256 KB */

  fprintf(stderr, "[benchmark] spawning %d non-hoster threads (batch size 500)...\n", X);
  for (int i = 0; i < X; i++) {
    args[i].ip = "127.0.0.1";
    args[i].port = port;
    args[i].gid = 0;
    args[i].bar = bar;
    if (pthread_create(&threads[i], &attr, run_nonhoster_thread, &args[i]) != 0) {
      fprintf(stderr, "[benchmark] failed to create thread %d (errno=%d)\n", i, errno);
      for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
      free(threads); free(args);
      error_handle("pthread_create");
    }
    /* batch throttle: every 500 threads, pause briefly to let the server drain its accept queue */
    if ((i + 1) % 500 == 0) usleep(50000);
  }
  pthread_attr_destroy(&attr);

  /* ---- barrier: wait for all to be ready, then RELEASE ---- */
  fprintf(stderr, "[benchmark] waiting for all threads to get keys...\n");
  while (__atomic_load_n(&bar->ready_count, __ATOMIC_ACQUIRE) < X)
    usleep(100000);
  fprintf(stderr, "[benchmark] all %d ready, releasing!\n", X);
  __atomic_store_n(&bar->go_flag, 1, __ATOMIC_RELEASE);

  /* ---- reap non-hoster threads ---- */
  for (int i = 0; i < X; i++)
    pthread_join(threads[i], NULL);
  fprintf(stderr, "[benchmark] all non-hosters done\n");

  free(threads);
  free(args);

  /* ---- reap host ---- */
  waitpid(hpid, NULL, 0);

  /* ---- let server print the benchmark line ---- */
  sleep(2);

  /* ---- stop server ---- */
  kill(spid, SIGTERM);
  waitpid(spid, NULL, 0);

  munmap((void*)bar, sizeof(*bar));
  printf("[benchmark] done.\n");
  return 0;
}