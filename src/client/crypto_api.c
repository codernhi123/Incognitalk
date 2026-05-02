#include "client.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// 1. Generate a pair of public-private key as PEM strings
int generate_rsa_keypair(RSA_Keypair *keypair) {
  memset(keypair, 0, sizeof(RSA_Keypair));

  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx) return -1;
  
  if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
  EVP_PKEY_CTX_free(ctx);

  // Write keys to memory BIOs to extract PEM strings
  BIO *pub_bio = BIO_new(BIO_s_mem());
  BIO *priv_bio = BIO_new(BIO_s_mem());

  PEM_write_bio_PUBKEY(pub_bio, pkey);
  PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL);

  BIO_read(pub_bio, keypair->public_key_pem, PEM_BUFFER_SIZE - 1);
  BIO_read(priv_bio, keypair->private_key_pem, PEM_BUFFER_SIZE - 1);

  BIO_free(pub_bio);
  BIO_free(priv_bio);
  EVP_PKEY_free(pkey);

  return 0;
}

// 2. Encrypt pure bytes using PUBLIC key (Used to encrypt the symmetric key during exchange)
int rsa_encrypt_with_public_key(const char *public_key_pem, const unsigned char *plaintext, size_t pt_len, unsigned char *ciphertext, size_t *ct_len) {
  BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
  EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pubkey) return -1;

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
  if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    EVP_PKEY_free(pubkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (EVP_PKEY_encrypt(ctx, ciphertext, ct_len, plaintext, pt_len) <= 0) {
    EVP_PKEY_free(pubkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_free(pubkey);
  EVP_PKEY_CTX_free(ctx);
  return 0;
}

// 3. Decrypt the encrypted message using PRIVATE key 
int rsa_decrypt_with_private_key(const char *private_key_pem, const unsigned char *ciphertext, size_t ct_len, unsigned char *plaintext, size_t *pt_len) {
  BIO *bio = BIO_new_mem_buf(private_key_pem, -1);
  EVP_PKEY *privkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!privkey) return -1;

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
  if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    EVP_PKEY_free(privkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (EVP_PKEY_decrypt(ctx, plaintext, pt_len, ciphertext, ct_len) <= 0) {
    EVP_PKEY_free(privkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_free(privkey);
  EVP_PKEY_CTX_free(ctx);
  return 0;
}

// 4. Generate symmetric key (AES-256) for later use
int generate_symmetric_key(unsigned char *key) {
  // Uses cryptographically secure PRNG internally
  if (RAND_bytes(key, AES_KEY_LEN) != 1) return -1;
  return 0;
}

// 5a. Encrypt using AES symmetric key (AES-256-CBC)
// Requires an IV which typically should be transmitted alongside the ciphertext.
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

// 5b. Decrypt using AES symmetric key (AES-256-CBC)
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

// 6. Sign data (e.g., the encrypted symmetric key) using the host's PRIVATE key
int rsa_sign_with_private_key(const char *private_key_pem, const unsigned char *message, size_t msg_len, unsigned char *signature, size_t *sig_len) {
  BIO *bio = BIO_new_mem_buf(private_key_pem, -1);
  EVP_PKEY *privkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!privkey) return -1;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx || EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privkey) <= 0) {
    EVP_PKEY_free(privkey);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return -1;
  }

  // Passing NULL for signature returns the required size
  if (signature == NULL) {
    EVP_DigestSignFinal(mdctx, NULL, sig_len);
    EVP_PKEY_free(privkey);
    EVP_MD_CTX_free(mdctx);
    return 0;
  }

  if (EVP_DigestSignUpdate(mdctx, message, msg_len) <= 0 || EVP_DigestSignFinal(mdctx, signature, sig_len) <= 0) {
    EVP_PKEY_free(privkey);
    EVP_MD_CTX_free(mdctx);
    return -1;
  }

  EVP_PKEY_free(privkey);
  EVP_MD_CTX_free(mdctx);
  return 0;
}

// 7. Verify the signature using the host's PUBLIC key
int rsa_verify_with_public_key(const char *public_key_pem, const unsigned char *message, size_t msg_len, const unsigned char *signature, size_t sig_len) {
  BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
  EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pubkey) return -1;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx || EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) {
    EVP_PKEY_free(pubkey);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return -1;
  }

  if (EVP_DigestVerifyUpdate(mdctx, message, msg_len) <= 0) {
    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_free(mdctx);
    return -1;
  }

  int ret = EVP_DigestVerifyFinal(mdctx, signature, sig_len);
  
  EVP_PKEY_free(pubkey);
  EVP_MD_CTX_free(mdctx);
  
  return (ret == 1) ? 0 : -1; // 0 for success, -1 for failure
}

