#include <openssl/types.h>
#include <netinet/in.h>
#include "client.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/*
Intended workflow:
1. Server initiated, waiting for clients to connect (done)
2. Client A (host) connects, sends type 4 message to server, server creates a new room and set client A as host (done)
2.1. Server sends the assigned groupchat_id back to host A with type 4 message, and host A updates its state with the assigned groupchat_id (done)
3. Client B (non-host) connects, sends type 0 message with its group_id and public key to server. (done)
3.1. Server forwards client B's public key and client id to host A with type 0 message. (done) 
4. Host A adds client B to the waiting queue for key distribution, and trigger the waiting queue handler thread to do the key distribution: encrypt the shared symmetric key with client B's public key, sign it with host A's private key, and send both the encrypted symmetric key and signature in a bundle to server with type 2 message. (done)
5. Server forwards the bundle to client B with type 2 message. (done)
6. Client B verifies the signature with host A's public key, decrypts the symmetric key with its private key, and store the symmetric key for future use. (done)
7. Client B can now send encrypted messages to server with type 1 message, and server will forward the encrypted message to all other clients in the same room, and those clients will decrypt with the shared symmetric key and print/log the plaintext message.
8. If any client wants to leave, it sends a type 3 message to server, and server will do the cleanup, if the host leaves, server will end the room, assume the host leaves the last.

Concurrency issue (where mutex needed):
1. All attributes in client code are read-only and/or set 1 time before enter any threads, except for the state and waiting queue for host, so we need mutex when accessing/updating those attributes.
2. For the waiting queue, since it's only modified by the host and only accessed by the waiting queue handler thread, we can use a simple mutex to protect it, and a condition variable to signal the waiting queue handler thread when there's a new client in the waiting queue, to avoid busy waiting
3. For state, we use mutex to protect the state change and make sure the state change is atomic, since the state is used to determine the type of message to send to server, and also used in the message processor for received messages from server
*/

int PORT = 0;
int BUFF_MAX = 2048; // assume all full messages (header + payload) can fit in 2048 bytes, so that we can read the full message in one read call, and avoid dealing with fragmentation and reassembly for now
char IP_str[2048] = {0};
char log_path[2048] = {0};
int log_fd = 0;

int non_hoster_count = INT_MIN;

char disk_prikey[2048] = {0};
unsigned char shared_seckey[2048] = {0};
size_t shared_seckey_len = 32;

pthread_mutex_t waiting_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int main(int argc, char *argv[]) { // ./client <IP> <PORT> <Hoster_Boolean> <GroupID> <log_path> 
  // -- Using Producer-Consumer pattern for client, i.e two threads for sending and receiving
  if (argc != 6) {
    error_handle("CLI argument client");
  }
  strcpy(IP_str, argv[1]);
  PORT = atoi(argv[2]);
  int is_hoster = atoi(argv[3]);
  uint32_t group_id = (uint32_t)atoi(argv[4]); // if host then group_id be ignored
  strcpy(log_path, argv[5]); // to save decrypted messages some where on client's disk

  struct sockaddr_in6 addr;
  int sfd;
  sfd = socket(AF_INET6, SOCK_STREAM, 0);
  if (sfd == -1) {
    error_handle("socket in client");
  }

  memset(&addr, 0, sizeof(struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(PORT);
  if (inet_pton(AF_INET6, IP_str, &addr.sin6_addr) <= 0) {
    error_handle("inet_pton in client");
  }

  if (connect(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
    error_handle("connect in client");
  }

  struct Client_Metadata client_info;
  memset(&client_info, 0, sizeof(client_info));

  // --- setting up producer part - send to server
  client_info.sfd = sfd;
  client_info.group_id = group_id;
  client_info.is_hoster = is_hoster;
  client_info.state = STATE_JUST_CONNECTED; // will later be given by server
  client_info.waiting_queue_head = NULL;
  // using Ephemeral Session Keys (regenerated constantly in memory)
  generate_rsa_keypair(&client_info.keypair);
  client_info.pubkey_len = strlen(client_info.keypair.public_key_pem);
  client_info.prikey_len = strlen(client_info.keypair.private_key_pem);
  strcpy(disk_prikey, client_info.keypair.private_key_pem);

  // hoster making the mutual secret key
  if (client_info.is_hoster) {
    if (generate_symmetric_key(shared_seckey) == -1) {
      error_handle("generate symmetric key in client");
    }
    shared_seckey_len = 32;
    non_hoster_count = 0; // initialize the non_hoster_count for host
  }
  
  pthread_t send_tid;
  if (pthread_create(&send_tid, NULL, send_handler, &client_info) == -1) {
    error_handle("thread in client");
  }
  
  // --- consumer part - receive from server (only for host to do key distro, or receive encrypted -> decrypt/verify -> print/log)
  log_fd = open(log_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ssize_t num_read = 0;
  uint8_t recv_buf[2048];
  int leftover_bytes = 0;

  while ((num_read = read(sfd, recv_buf + leftover_bytes, BUFF_MAX - leftover_bytes)) > 0) {
    leftover_bytes += num_read;
    //... extract message from server, categorize, and print decrypted message to terminal and log file
    while (leftover_bytes >= 3) {
      uint8_t type = recv_buf[0];
      int16_t payload_len = 0;
      memcpy(&payload_len, recv_buf + 1, sizeof(uint16_t));
      payload_len = ntohs(payload_len);

      int total_msg_size = 3 + payload_len;
      if (leftover_bytes >= total_msg_size) {
        // extract the full message
        uint8_t *payload = recv_buf + 3;
        //... message processor for received message from server, including decryption and verification
        message_processor(&client_info, type, payload, payload_len);

        //shifting the rest to front of buffer for the next loop
        int remaining = leftover_bytes - total_msg_size;
        if (remaining > 0) {
          memmove(recv_buf, recv_buf + total_msg_size, remaining);
        }
        leftover_bytes = remaining;
      } else {
        // wait for another read
        break;
      }
    }
  }
  if (num_read == -1) {
    error_handle("read in client");
  }
  return 0;
}