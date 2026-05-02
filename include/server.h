#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

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

typedef enum {
  STATE_JUST_CONNECTED, // only contain fd, addr 
  STATE_IN_ROOM // contain groupchat_id, *room, public_key
} Client_State;

struct Client_Metadata {
  int fd;
  uint16_t client_id; // unique
  struct sockaddr_in6 addr;
  Client_State state; // for handshake procedure

  int groupchat_id;
  char public_key[1024];
  int public_key_len;
  struct GroupChat_Metadata *room;

  uint8_t recv_buf[2048];
  int leftover_bytes;
};

struct GroupChat_Metadata {
  int id;              // the 5-digit chat ID
  int is_active;        // 0 if waiting for key, 1 if key established

  struct Client_Metadata *host; // the first client that created the room, responsible for key sharing
  struct Client_Metadata *members[100]; // array (or linked list) of clients in this room
  int member_count;
};

extern struct GroupChat_Metadata glob_groupchats[10000]; // server keeps track of all rooms

void message_handler(struct Client_Metadata *arg);

void message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len);