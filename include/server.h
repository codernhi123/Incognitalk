/****************************************************************************************************************
#################################################################################################################
  Authors: Viet Huy (Finnick) Pham, a.k.a Fintanyl
  Date: 2026-05-08
  Permission: All rights reserved. No commercial use. For educational use only. Citation required when reference.
  Author's messages to readers: Be kind, happy coding and pet some tabby cats!
  Suggesstion or contact is always welcome and appreciated, reach out to me via email: pvhuy060606@gmail.com
#################################################################################################################
****************************************************************************************************************/

#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <openssl/cryptoerr_legacy.h>
#include <pthread.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>

#define error_handle(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

extern int PORT;
extern int BUFF_MAX;
extern int MAX_CLIENTS;
extern int LISTEN_BACKLOG; // to be set in argument
extern short CLIENTS_CNT;
extern int READ_QUOTA;

extern short GLOB_GROUPCHAT_CNT;
extern int epoll_fd;

extern sem_t task_sem;
extern struct Client_Metadata *task_circular_queue[100000];
extern int queue_front;
extern int queue_rear;
extern int queue_size;
extern pthread_mutex_t task_queue_mutex;

typedef enum {
  STATE_JUST_CONNECTED, // connected successfully
  STATE_WAITING_FOR_KEY, // after sending type 0 message - before getting the encrypted symmetric key back from server
  STATE_IN_ROOM, // contain groupchat_id, *room, public_key
  STATE_DISCONNECTED // after type 3
} Client_State;

struct Client_Metadata {
  // --- network stack attributes
  int fd;
  struct sockaddr_in6 addr;
  // --- concurrency attributes
  pthread_mutex_t client_mutex; 
  atomic_int ref_count; 
  // --- application attributes (set in handshake)
  int is_hoster; // 1 if host, 0 if not
  uint16_t client_id; // unique, incremental
  Client_State state;
  uint32_t groupchat_id;
  struct GroupChat_Metadata *room;
  uint16_t room_idx;
  // --- default attributes
  uint8_t recv_buf[2048];
  int leftover_bytes;
};

struct GroupChat_Metadata {
  uint32_t id;              // the 5-digit chat ID
  int is_active;        // 0 if groupchat ended, 1 if active
  struct Client_Metadata *host; // the first client that created the room, responsible for key sharing
  struct Client_Metadata *members[1000]; // array (or linked list) of clients in this room
  int member_count;

  pthread_mutex_t room_mutex; // to protect the members array and member_count when adding/removing members, and also protect the is_active flag when host leaves and end the room
};

extern struct GroupChat_Metadata glob_groupchats[100]; // server keeps track of all rooms
extern pthread_mutex_t glob_groupchats_mutex;

void *message_handler(void *arg);

int message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len);