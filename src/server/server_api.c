#include "server.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

void message_handler(struct Client_Metadata *arg) {
  struct Client_Metadata *client = (struct Client_Metadata *)arg;
  int c_fd = (int)client->fd;
  // *might be unnessecary, just in case
  in_port_t c_port = client->addr.sin6_port;
  struct in6_addr c_IP = client->addr.sin6_addr;

  ssize_t num_read;
  num_read = read(c_fd, client->recv_buf + client->leftover_bytes, BUFF_MAX - client->leftover_bytes);

  if (num_read > 0){
    client->leftover_bytes += num_read;
    //... extract message from client A, categorize, and send to the correct client B
    while (client->leftover_bytes >= 3) {
      uint8_t type = client->recv_buf[0];
      int16_t payload_len = 0;
      memcpy(&payload_len, client->recv_buf + 1, sizeof(uint16_t));
      payload_len = ntohs(payload_len);

      int total_msg_size = 3 + payload_len;
      if (client->leftover_bytes >= payload_len) {
        // extract the full message
        uint8_t *payload = client->recv_buf + 3;
        message_processor(client, type, payload, payload_len);

        //shifting the rest to front of buffer for the next loop
        int remaining = client->leftover_bytes - total_msg_size;
        if (remaining > 0) {
          memmove(client->recv_buf, client->recv_buf + total_msg_size, remaining);
        }
        client->leftover_bytes = remaining;
      } else {
        // wait for another epoll
        break;
      }
    }
  } else if (num_read == 0) {
    //... clean up
  } else if (num_read == -1) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      free(client);
      error_handle("read issue");
    }
    //... EAGAIN is fine
  }
  free(client);
  client = NULL;
}


void message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len) {
  if (client->state == STATE_JUST_CONNECTED) { // announce arrival to all and trigger symmetric key sharing process 
    if (type != 0) {
      free(client);
      perror("Unexpected behavior");
      exit(EXIT_FAILURE);
    }
    client->groupchat_id = 0; 
    memcpy(&client->groupchat_id, payload, 4);
    memcpy(client->public_key, payload + 4, payload_len - 4);
    client->room = (struct GroupChat_Metadata*)(glob_groupchats + client->groupchat_id);
    client->room->members[client->room->member_count] = client;
    client->room->member_count++;
    struct Client_Metadata **client_arr = (client->room)->members;
    for (int i = 0; i < client->room->member_count; i++) {
      uint8_t broadcast_buf[2048] = {0};
      broadcast_buf[0] = 0;
      uint16_t s_payload_len = 2 + PUBKEY_LEN;
      uint16_t net_s_payload_len = htons(s_payload_len);
      memcpy(broadcast_buf + 1, &net_s_payload_len, sizeof(uint16_t));

      uint16_t net_client_id = htons(client->client_id);
      memcpy(broadcast_buf + 3, &net_client_id, sizeof(int16_t));

      memcpy(broadcast_buf + 5, client->public_key, PUBKEY_LEN);

    }
  } else if (client->state == STATE_IN_ROOM) {

  }
}