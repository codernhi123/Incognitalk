#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

extern pthread_mutex_t thread_mutex; // for writing to log file, shared_secret, etc. - any shared resource between threads
extern pthread_cond_t cond;

#define error_handle(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

extern int PORT;
extern int BUFF_MAX;
extern char IP_str[2048];

extern char log_path[2048];
extern char disk_pubkey[2048];
extern char disk_prikey[2048];
extern unsigned char shared_seckey[2048];

#define PEM_BUFFER_SIZE 4096
#define AES_KEY_LEN 32 // 256-bit AES key
#define AES_IV_LEN 16  // 128-bit IV

struct __attribute((packed)) Universal_Send_Packet {
  uint8_t type;
  uint16_t length;
  uint32_t group_id;
  uint16_t target_client_id; // for type 1 message, to specify the recipient of the message, ignored for type 0 message
  uint8_t iv[16];
  uint8_t pubkey[2048];
  uint8_t ciphertext[2048]; // used for both encrypted symmetric key (type 0) and encrypted message (type 1)
};

typedef enum {
  STATE_JUST_CONNECTED, // connected successfully
  STATE_WAITING_FOR_KEY, // after sending type 0 message - before getting the encrypted symmetric key back from server
  STATE_IN_ROOM, // contain groupchat_id, *room, public_key
  STATE_DISCONNECTED // after type 3
} Client_State;

struct Client_Waiting_Queue {
  int sfd; //server_fd 
  uint16_t new_client_id;
  char new_client_pubkey[2048];
  struct Client_Waiting_Queue *next;
};

struct Client_Metadata {
  int sfd;
  int is_hoster; // whether this client is the hoster of the room, only hoster is responsible for key sharing
  uint32_t group_id; // the group this client is in
  Client_State state; // for handshake procedure
  char pubkey[2048];
  int pubkey_len;
  struct Client_Waiting_Queue *waiting_queue_head; // for hoster to keep track of clients that have sent type 0 message but haven't received the encrypted symmetric key yet
};

// 0.a. Struct to store pair of public-private keys as pure PEM strings
typedef struct {
  char public_key_pem[PEM_BUFFER_SIZE];
  char private_key_pem[PEM_BUFFER_SIZE];
} RSA_Keypair;


size_t read_all_bytes(const char *filename, void *buffer, size_t buffer_size);

void message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len);

void *send_handler(void *arg);

void *waiting_queue_handler(void *arg);

int generate_symmetric_key(unsigned char *key);

int generate_rsa_keypair(RSA_Keypair *keypair);

int rsa_encrypt_with_public_key(const char *public_key_pem, const unsigned char *plaintext, size_t pt_len, unsigned char *ciphertext, size_t *ct_len);

int rsa_sign_with_private_key(const char *private_key_pem, const unsigned char *message, size_t msg_len, unsigned char *signature, size_t *sig_len);