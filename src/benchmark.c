/****************************************************************************************************************
  benchmark.c — Stress-test the Incognitication server (pre-baked keys, zero keygen at runtime)

  Usage: ./benchmark <num_non_hosters> <server_port>

  All RSA keypairs and the AES key are hardcoded as string literals — no key generation
  at runtime means the bottleneck is purely the server, not the benchmark harness.

  Flow:
   1. Fork + exec the server binary
   2. Fork 1 host (uses PRE_HOST keys)
   3. Spawn X non-hoster pthreads (all share PRE_PEER keys)
   4. Barrier sync → burst "Hello world" → leave → host leaves
   5. Server prints [BENCHMARK] Peak concurrent clients in room 0: N
****************************************************************************************************************/

#define _GNU_SOURCE
#include "client.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/rand.h>
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

/* ================================================================== */
/*  PRE-GENERATED KEYS  (zero runtime keygen)                          */
/* ================================================================== */
static const char PRE_HOST_PRIVKEY[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFZFAg1Uvpfsfs\n"
  "lTWTZC7yKa8NL9hYgVZ/j5SaBoFM92+mSNUM3HXXuKpZe/S1lc91/H+lxe7BZvXT\n"
  "wbZI02c9+PJD8QCzR6rk5q93+L9CvazvVaZJGzbg/9AsZnHxz0ZNmNxzDpkmojT8\n"
  "G3xdz9nqUc9TgsJaiFXSWgSOp9O0bS+lIUy8hpZnZxwLqvY2tUMOb8SWBGc7V04X\n"
  "xNAMTswraA7emhgP7EhhZs6/7w6D7EHKPJ69g/85rUEjxQiPj9U6nUIBjkmZHEFA\n"
  "eoo0x5e4ZG1XE/O9WCIuiErYELX43dDnH+1khIfbMgHMAXyO5NhV26bDB0HelY+O\n"
  "ILaYLRH/AgMBAAECggEAQHZmjpppvJrJOpNt2DEW/cGsJ7/QxPKUJ3th2b03G8YQ\n"
  "wbq2TQlwOJ9XjnqjK2v9wPfRTfdqZeG0dU+lMnpLlJsIrzR0+Jd2kWNeuWzUNT0R\n"
  "TWXotKY9EVSpjN515rS8rlm14KNLU6kUaaKmRlK7RUErVof05bDxag04wMfBJQIS\n"
  "gbFLsnatPoClRXAiGXYvjwohkSoRrwIatZY5AjOD23POgK3PjEZv1cUSGcTU4GIn\n"
  "77Jb06mj9V8JkgphqU7xsED40V+ivwEGS2UVLQzNYwgU9phRigyLxTYrOgurySFW\n"
  "IcB467wHB9ovlJpxeJH6HvlzxJhwlkKrmkUilJ0ivQKBgQDiWzMDUPs9Ceod7yZa\n"
  "Me1+4PdcLxLJgtJFtASDh5rw0UoVjMiOeV0KvTgso1tLz3d5KyKt453mDFPgBARX\n"
  "Lc3b29heQWaCZRLZRTQKLCe4uhTfJWSvxYRe5HylSCOIhD/k7yGP2RC0/lVKLZYw\n"
  "Xms883tckW/VXiyGnLX2GapGiwKBgQDfPg5BJVPXLuBvV15MFjFFH3MT7Cd/Sl8P\n"
  "LORQICZ5es+lekSBh/2u8o8mXmaNKG6JPaG+BAbRGsweOuAWs/1lwSFZWWQghaII\n"
  "o76hvSMzNVa23DA94aNbot7H6xJ7C1tQBG0SBm0lah8gcxC+i1/71xMsRawBxO1T\n"
  "4XtYC7wE3QKBgQCcgxjTyzPc8bUKu6iWJv2jhGQlPntMEIPaJG4WkDYnG1+RZQXr\n"
  "1ajq2wkzfESNN8fRZW0WNVOhlJaOR9jEeuxjgDCsg6YgtUiCKOKhwgQ5K5lw7gcf\n"
  "roAnqO8yzZ2cMG2Jm3tmXl25+D37C2hUy4R04ZpD2GAudW5uKX97yiU9nwKBgACH\n"
  "Kgt3ZiJdJwS8ZSmy57ztHR2P8mv3pg/oIEYcPVsOMk2G44CW7L+sLTB/CqkMzm4e\n"
  "qjJD2ixGbvMnWn5TQKcr9MM8VeNJzZ9Nm9bQFrQ5TRIzpR2QWg2Obg50/N8zoKyo\n"
  "xgVD5KAxBw/RldmNhNWYpZ/2Ljj22UTYhK0pofE1AoGBAJU8/O4Vg0CzUh+BZDuL\n"
  "S+47dGUH8lTbLYFbpaiGfadIxFOTyZ3s5rqh/EZl+U1VAFoW8WPaNNBGJUjkIxaO\n"
  "JRR/kcQR/lT+X8ScoztTgHdMxYN4FX9hcIFV3kwFY+CRqkUduusJVnTba4rz6u2r\n"
  "jMF6F1gI7+inFZSv7PFAr9bc\n"
  "-----END PRIVATE KEY-----\n"
  "";

static const char PRE_HOST_PUBKEY[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWRQINVL6X7H7JU1k2Qu\n"
  "8imvDS/YWIFWf4+UmgaBTPdvpkjVDNx117iqWXv0tZXPdfx/pcXuwWb108G2SNNn\n"
  "PfjyQ/EAs0eq5Oavd/i/Qr2s71WmSRs24P/QLGZx8c9GTZjccw6ZJqI0/Bt8Xc/Z\n"
  "6lHPU4LCWohV0loEjqfTtG0vpSFMvIaWZ2ccC6r2NrVDDm/ElgRnO1dOF8TQDE7M\n"
  "K2gO3poYD+xIYWbOv+8Og+xByjyevYP/Oa1BI8UIj4/VOp1CAY5JmRxBQHqKNMeX\n"
  "uGRtVxPzvVgiLohK2BC1+N3Q5x/tZISH2zIBzAF8juTYVdumwwdB3pWPjiC2mC0R\n"
  "/wIDAQAB\n"
  "-----END PUBLIC KEY-----\n"
  "";

static const char PRE_PEER_PRIVKEY[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6fsOyZ6LQx4Sv\n"
  "4h1qUfUYKj6qe6M0fEgQxQPj1pSSmGAW9XOVE8/ZsLvrq19KuXrpzAJgq8yTexbV\n"
  "fvgeZsG8nbIDbGVzO6xpplj4EjCBOsW2IzcgDAUW75xIqihDhiG/x5MDXHQavfnf\n"
  "eQV2CofGgdfUqbkQmxq55u0lMErGaE5fV7P11Tc89GTOCpOIf9vBikDgeZSZKNlr\n"
  "vZQ4ilkW5irqUy1DMZLfImqgqvA4k+MnmpI54GZQuPP+enq+aMjIrssqWFfndAm2\n"
  "6abKTnQcrusvKJpJBoZHN8/8VudteRfGu0iOQ5qOltLd+aBrD3IoQZI1YAJIcayp\n"
  "s47TeND9AgMBAAECggEABeAkCL0goUzD5qmsTRL3cpM0Jble9zKaL6MRYA584FB6\n"
  "KIcDpPT6laxugzqDNk65K2AAzCxlddkJK2FEbmrE3E0olFiIKrT81dhGkcw66Hti\n"
  "Sr55yGHwkBws85Ie0h/J9OmT/WVeiBAnrO16aVFkHTIui1XsjXQhh61Zl9QZav5F\n"
  "AMP0INrZb8MJD9Y/ur+4es9ktALODbPWiEroE49OplOmjYszSG3qI5kSmk3X0X0W\n"
  "iEhhp4NOOA8KoydZO17LtU3Vj+IJNCJTnDbud/BcFdROef79CsCxmAehFlg3OmCd\n"
  "1EPZZ/m6vAH9VoO32W+Ns+H/VZ4Ov7B/o5Fj1T36cQKBgQDi0dftuwRCSwQhKC6L\n"
  "e6aAGlCanerP+r0rUmBvv8UNW/cnssnS0nqP0lMP1ZLOKiAPMC0jHJEZ3CtXsqXj\n"
  "qmO98Uot/EYr0XYBQuufi62gsZyIPBHfFE9kmXYN2/KADEoFdy3NKZH11PDLL7Tz\n"
  "bslN7yDAKmPMo2I7Fw8Wey278QKBgQDSfNwAhuJnF2LBkksNeY9XT1W7ChyxZmxl\n"
  "Fg4GUPxR0eVTWYoOg4lImsdVKtFyJClfMBGZaCPn43URaGFEMow9QqK3cCSyhxBS\n"
  "V/dfUl0AplHMZKIeJda8ap8uxcB8QnxR9hMeHZonMOUwYOzRS1O7VsRcrQxYJOvR\n"
  "p1gzNNNhzQKBgQDVjAel1PuPhp0esnwP6py54wycZa1bnpBXpzkQPRbDGyC5CYUm\n"
  "re+iVLzLHaMX42VHp233rr+V/0n3SUUR8avyeqgCX4+ZVZ2qVl0MWy9fKZlcUmHp\n"
  "C3AsIKebKMdJc0iFmM1QaaD4OEF0qzfMMTPp4geNpNtNIU4sn+semV5XoQKBgQDD\n"
  "2T+PEfJI//54pBlHYWsZTw0y6nbGLcn/yKSmBeawbr+VbUPCu2sabkG4og2dyb3g\n"
  "/sXxWm/GTOLZnqiaHvpT6dOjISpUHs32ADmArQ8yEo8bwisCKC0ExaR1jbTLKcWp\n"
  "MXCaXerYOmuWNylCmHdBYbt1i+JnhXsSaUXs52MjpQKBgF08zs5gySsumTkrzssv\n"
  "ofoH1tvHxnvePJWDi5wvgmKnsKnq6DmtqOE16kujrEjZuU8lJtDw9vnPwYT+9v0r\n"
  "Ss/plgA9Q0LOGtb96KfIYkFekt9dxLjmcHuH9LG1xpIcaYKiElUHVQr1gsraZF6x\n"
  "/Jfy2gBKrg1UGWNh1m+qz5J7\n"
  "-----END PRIVATE KEY-----\n"
  "";

static const char PRE_PEER_PUBKEY[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAun7Dsmei0MeEr+IdalH1\n"
  "GCo+qnujNHxIEMUD49aUkphgFvVzlRPP2bC766tfSrl66cwCYKvMk3sW1X74HmbB\n"
  "vJ2yA2xlczusaaZY+BIwgTrFtiM3IAwFFu+cSKooQ4Yhv8eTA1x0Gr3533kFdgqH\n"
  "xoHX1Km5EJsauebtJTBKxmhOX1ez9dU3PPRkzgqTiH/bwYpA4HmUmSjZa72UOIpZ\n"
  "FuYq6lMtQzGS3yJqoKrwOJPjJ5qSOeBmULjz/np6vmjIyK7LKlhX53QJtummyk50\n"
  "HK7rLyiaSQaGRzfP/FbnbXkXxrtIjkOajpbS3fmgaw9yKEGSNWACSHGsqbOO03jQ\n"
  "/QIDAQAB\n"
  "-----END PUBLIC KEY-----\n"
  "";

static const unsigned char PRE_AES_KEY[32] = {0x06, 0xaa, 0x46, 0x8f, 0xcb, 0xf4, 0xda, 0x0d, 0x3a, 0xf8, 0x12, 0xc6, 0x5d, 0x81, 0x69, 0xc7, 0x64, 0xb3, 0x89, 0x43, 0x79, 0xb6, 0xe5, 0xeb, 0xd8, 0xf7, 0x16, 0x7e, 0xaf, 0xaf, 0xf4, 0x81};

/* ================================================================== */
/* shared-memory barrier                                              */
/* ================================================================== */
struct barrier {
  volatile int ready_count;
  volatile int go_flag;
  int total;
};

/* ================================================================== */
/* tiny I/O helpers                                                   */
/* ================================================================== */
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

/* ================================================================== */
/* wire-protocol send / recv                                          */
/* ================================================================== */
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

/* ================================================================== */
/* connect (IPv4 → mapped IPv6), retry up to 60s                      */
/* ================================================================== */
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
/*  HOST process  (uses PRE_HOST keys, no keygen)                      */
/* ================================================================== */
static void run_host(const char *ip, int port) {
  int fd = connect_server(ip, port);

  /* keypair from pre-baked string literal — no runtime keygen */
  RSA_Keypair kp;
  memset(&kp, 0, sizeof(kp));
  memcpy(kp.private_key_pem, PRE_HOST_PRIVKEY, strlen(PRE_HOST_PRIVKEY));
  memcpy(kp.public_key_pem, PRE_HOST_PUBKEY, strlen(PRE_HOST_PUBKEY));
  int pubkey_len = (int)strlen(kp.public_key_pem);

  unsigned char shared_key[2048];
  memcpy(shared_key, PRE_AES_KEY, 32);

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
/*  NON-HOSTER thread  (uses PRE_PEER keys, no keygen)                 */
/* ================================================================== */
static void *run_nonhoster_thread(void *arg) {
  struct nh_args *a = (struct nh_args *)arg;
  int fd = connect_server(a->ip, a->port);

  /* keypair from pre-baked string literal — no runtime keygen */
  RSA_Keypair kp;
  memset(&kp, 0, sizeof(kp));
  memcpy(kp.private_key_pem, PRE_PEER_PRIVKEY, strlen(PRE_PEER_PRIVKEY));
  memcpy(kp.public_key_pem, PRE_PEER_PUBKEY, strlen(PRE_PEER_PUBKEY));
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

  /* barrier */
  __sync_fetch_and_add(&a->bar->ready_count, 1);
  while (!__atomic_load_n(&a->bar->go_flag, __ATOMIC_ACQUIRE))
    usleep(1000);

  /* send "Hello world" */
  unsigned char iv[16];
  if (RAND_bytes(iv, sizeof(iv)) != 1) { close(fd); return (void *)(intptr_t)-5; }
  const char *pt = "Hello world";
  int pt_len = (int)strlen(pt);
  unsigned char ct[1024];
  int ct_len = aes_encrypt((const unsigned char *)pt, pt_len, shared_key, iv, ct);
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

  /* shared barrier */
  struct barrier *bar = mmap(NULL, sizeof(*bar),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (bar == MAP_FAILED) error_handle("mmap barrier");
  memset((void*)bar, 0, sizeof(*bar));
  bar->total = X;

  /* spawn server */
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

  /* spawn host */
  pid_t hpid = fork();
  if (hpid < 0) error_handle("fork host");
  if (hpid == 0) {
    run_host("127.0.0.1", port);
    _exit(0);
  }

  sleep(1);

  /* spawn X non-hoster threads */
  pthread_t *threads = (pthread_t *)malloc((size_t)X * sizeof(pthread_t));
  struct nh_args *args = (struct nh_args *)malloc((size_t)X * sizeof(struct nh_args));

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 256 * 1024); /* 256 KB stacks for 20K+ threads */

  fprintf(stderr, "[benchmark] spawning %d non-hoster threads (batch 500, no keygen)...\n", X);
  for (int i = 0; i < X; i++) {
    args[i].ip = "127.0.0.1";
    args[i].port = port;
    args[i].gid = 0;
    args[i].bar = bar;
    if (pthread_create(&threads[i], &attr, run_nonhoster_thread, &args[i]) != 0) {
      fprintf(stderr, "[benchmark] thread %d failed (errno=%d)\n", i, errno);
      for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
      free(threads); free(args);
      error_handle("pthread_create");
    }
    if ((i + 1) % 500 == 0) usleep(50000);
  }
  pthread_attr_destroy(&attr);

  /* wait for all threads to get keys, then release */
  fprintf(stderr, "[benchmark] waiting for all threads to get keys...\n");
  while (__atomic_load_n(&bar->ready_count, __ATOMIC_ACQUIRE) < X)
    usleep(100000);
  fprintf(stderr, "[benchmark] all %d ready, releasing!\n", X);
  __atomic_store_n(&bar->go_flag, 1, __ATOMIC_RELEASE);

  /* reap threads */
  for (int i = 0; i < X; i++)
    pthread_join(threads[i], NULL);
  fprintf(stderr, "[benchmark] all non-hosters done\n");

  free(threads);
  free(args);

  /* reap host */
  waitpid(hpid, NULL, 0);

  sleep(2);

  /* stop server */
  kill(spid, SIGTERM);
  waitpid(spid, NULL, 0);

  munmap((void*)bar, sizeof(*bar));
  printf("[benchmark] done.\n");
  return 0;
}