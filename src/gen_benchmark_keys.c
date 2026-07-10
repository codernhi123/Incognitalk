#define _GNU_SOURCE
#include "client.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  RSA_Keypair kp;
  memset(&kp, 0, sizeof(kp));
  if (generate_rsa_keypair(&kp) < 0) {
    fprintf(stderr, "keygen failed\n");
    return 1;
  }

  unsigned char aes[32];
  if (generate_symmetric_key(aes) < 0) {
    fprintf(stderr, "aes keygen failed\n");
    return 1;
  }

  printf("/* --- Pre-generated benchmark keys --- */\n\n");

  /* host RSA keypair */
  printf("static const char PRE_HOST_PRIVKEY[] =\n");
  for (const char *p = kp.private_key_pem; *p; p++) {
    if (p == kp.private_key_pem) printf("  \"");
    switch (*p) {
      case '\n': printf("\\n\"\n  \""); break;
      case '\"': printf("\\\""); break;
      case '\\': printf("\\\\"); break;
      default:   putchar(*p);
    }
  }
  printf("\";\n\n");

  printf("static const char PRE_HOST_PUBKEY[] =\n");
  for (const char *p = kp.public_key_pem; *p; p++) {
    if (p == kp.public_key_pem) printf("  \"");
    switch (*p) {
      case '\n': printf("\\n\"\n  \""); break;
      case '\"': printf("\\\""); break;
      case '\\': printf("\\\\"); break;
      default:   putchar(*p);
    }
  }
  printf("\";\n\n");

  /* peer (non-hoster) RSA keypair */
  RSA_Keypair kp2;
  memset(&kp2, 0, sizeof(kp2));
  if (generate_rsa_keypair(&kp2) < 0) { fprintf(stderr, "keygen 2 failed\n"); return 1; }

  printf("static const char PRE_PEER_PRIVKEY[] =\n");
  for (const char *p = kp2.private_key_pem; *p; p++) {
    if (p == kp2.private_key_pem) printf("  \"");
    switch (*p) {
      case '\n': printf("\\n\"\n  \""); break;
      case '\"': printf("\\\""); break;
      case '\\': printf("\\\\"); break;
      default:   putchar(*p);
    }
  }
  printf("\";\n\n");

  printf("static const char PRE_PEER_PUBKEY[] =\n");
  for (const char *p = kp2.public_key_pem; *p; p++) {
    if (p == kp2.public_key_pem) printf("  \"");
    switch (*p) {
      case '\n': printf("\\n\"\n  \""); break;
      case '\"': printf("\\\""); break;
      case '\\': printf("\\\\"); break;
      default:   putchar(*p);
    }
  }
  printf("\";\n\n");

  /* AES key */
  printf("static const unsigned char PRE_AES_KEY[32] = {");
  for (int i = 0; i < 32; i++) {
    printf("%s0x%02x", i ? ", " : "", aes[i]);
  }
  printf("};\n");

  return 0;
}