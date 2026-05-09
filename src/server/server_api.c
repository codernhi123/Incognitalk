/****************************************************************************************************************
#################################################################################################################
  Authors: Viet Huy (Finnick) Pham, a.k.a Fintanyl
  Date: 2026-05-08
  Permission: All rights reserved. No commercial use. For educational use only. Citation required when reference.
  Author's messages to readers: Be kind, happy coding and pet some tabby cats!
  Suggesstion or contact is always welcome and appreciated, reach out to me via email: pvhuy060606@gmail.com
#################################################################################################################
****************************************************************************************************************/

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
#include <sys/types.h>
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
      if (client->leftover_bytes >= total_msg_size) {
        // extract the full message
        uint8_t *payload = client->recv_buf + 3;
        if (message_processor(client, type, payload, payload_len) == 1) {
            return;
        }

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
  } else if (num_read == 0) { //... assuming client unexpectedly leave the room by killing the program instead using /exit (type 3)
    if (client != NULL && client->room != NULL) {
      struct GroupChat_Metadata *room = client->room;
      if (client->state == STATE_IN_ROOM) {

        int last_idx = room->member_count - 1;
        struct Client_Metadata *last_client = room->members[last_idx];
        last_client->room_idx = client->room_idx;
        room->members[client->room_idx] = last_client;

        room->members[last_idx] = NULL;
        room->member_count--;
        client->state = STATE_DISCONNECTED;
      }
      free(client);
      client = NULL;
      close(c_fd);
      write(STDOUT_FILENO, "Client disconnected\n", 20);
    }
  } else if (num_read == -1) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      free(client);
      error_handle("read issue");
    }
    //... EAGAIN is fine
  }
}


int message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len) {
  if (client->state == STATE_JUST_CONNECTED) { // trigger symmetric key sharing process or setting up for host
    if (type == 4) { // new groupchat created by the host
      client->is_hoster = 1;
      client->state = STATE_IN_ROOM;
      client->room = (struct GroupChat_Metadata*)(glob_groupchats + GLOB_GROUPCHAT_CNT);
      client->groupchat_id = GLOB_GROUPCHAT_CNT;
      client->room_idx = 0;

      glob_groupchats[GLOB_GROUPCHAT_CNT].id = GLOB_GROUPCHAT_CNT;
      glob_groupchats[GLOB_GROUPCHAT_CNT].is_active = 1;
      glob_groupchats[GLOB_GROUPCHAT_CNT].host = client;
      glob_groupchats[GLOB_GROUPCHAT_CNT].members[0] = client;
      glob_groupchats[GLOB_GROUPCHAT_CNT].member_count++;

      // Send the assigned Group ID back to the host
      uint8_t resp_buf[7] = {0};
      resp_buf[0] = (uint8_t)4;
      uint16_t net_len = htons(4);
      memcpy(resp_buf + 1, &net_len, sizeof(uint16_t));
      uint32_t net_group_id = htonl(client->groupchat_id);
      memcpy(resp_buf + 3, &net_group_id, sizeof(uint32_t));
      write(client->fd, resp_buf, 7);

      GLOB_GROUPCHAT_CNT++;
    }
    else if (type == 0) {
      client->is_hoster = 0;
      client->state = STATE_WAITING_FOR_KEY;
      memcpy(&client->groupchat_id, payload, sizeof(uint32_t));
      client->groupchat_id = ntohl(client->groupchat_id);
      
      if (client->groupchat_id >= 100) {
        free(client);
        perror("Invalid groupchat_id out of bounds");
        exit(EXIT_FAILURE);
      }
      
      client->room = (struct GroupChat_Metadata*)(glob_groupchats + client->groupchat_id);
      if (client->room == NULL || client->room->is_active == 0) {
        free(client);
        perror("Invalid groupchat_id in type 0 message");
        exit(EXIT_FAILURE);
      }
      client->room->members[client->room->member_count] = client;
      client->room_idx = client->room->member_count;
      client->room->member_count++;
      struct Client_Metadata **client_arr = (client->room)->members;
      // if this client is not the hoster, send to host to add to waiting queue for key distro
      uint8_t trigger_buf[2048] = {0};
      trigger_buf[0] = 0;
      
      uint16_t s_payload_len = 2 + (payload_len - 4); // client_id + pubkey in payload
      uint16_t net_s_payload_len = htons(s_payload_len);
      memcpy(trigger_buf + 1, &net_s_payload_len, sizeof(uint16_t));

      uint16_t net_client_id = htons(client->client_id);
      memcpy(trigger_buf + 3, &net_client_id, sizeof(int16_t));

      memcpy(trigger_buf + 5, payload + 4, payload_len - 4); // client's pubkey

      write(client->room->host->fd, trigger_buf, 3 + s_payload_len);
    }
  } else if (client->state == STATE_IN_ROOM) { // host does seckey distro or clients do chat
    if (type == 1) {
      //... transfer the encrypted message to all other clients in the same room, no need to decrypt or verify signature at server side, just forward the ciphertext + iv + sender's pubkey for receiver to do decryption and verification
      struct GroupChat_Metadata *room = client->room;
      for (int i = 0; i < room->member_count; i++) {
        if (room->members[i]->client_id != client->client_id && room->members[i]->state == STATE_IN_ROOM) {
          uint8_t forward_buf[2048] = {0};
          forward_buf[0] = (uint8_t)1;
          uint16_t net_len = htons(payload_len + 2);
          uint16_t net_sender_id = htons(client->client_id);
          memcpy(forward_buf + 1, &net_len, sizeof(uint16_t));
          memcpy(forward_buf + 3, &net_sender_id, sizeof(uint16_t));
          memcpy(forward_buf + 5, payload, payload_len); // iv + ciphertext
          write(room->members[i]->fd, forward_buf, 5 + payload_len);
        }
      }
    } else if (type == 3) {
      //... trigger disconnect procedure, if non-host leaves, notify all clients in the room, else, just end the room cuz no one left
      struct GroupChat_Metadata *room = client->room;
      if (client->is_hoster == 0) {
        for (int i = 0; i < room->member_count; i++) {
          if (room->members[i]->client_id != client->client_id && room->members[i]->state == STATE_IN_ROOM) {
            uint8_t forward_buf[2048] = {0};
            forward_buf[0] = (uint8_t)3;
            uint16_t net_len = htons(2);
            memcpy(forward_buf + 1, &net_len, sizeof(uint16_t));
            uint16_t net_sender_id = htons(client->client_id);
            memcpy(forward_buf + 3, &net_sender_id, sizeof(uint16_t));
            write(room->members[i]->fd, forward_buf, 5);
          }
        }
        if (!(client->room != NULL && client->state == STATE_IN_ROOM)) {
          error_handle("Client has left before, unexpected behavior");
        }
        int last_idx = room->member_count - 1;
        struct Client_Metadata *last_client = room->members[last_idx];
        last_client->room_idx = client->room_idx;
        room->members[client->room_idx] = last_client; // move the last member to the leaving

        room->members[last_idx] = NULL;
        room->member_count--;
        client->state = STATE_DISCONNECTED;
      } else {
        room->is_active = 0;
        for (int i = 0; i < room->member_count; i++) {
          if (room->members[i]->state == STATE_IN_ROOM) {
            room->members[i]->state = STATE_DISCONNECTED;
          }
        }
      }
      close(client->fd);
      free(client);
      client = NULL;
      return 1;
    } else if (type == 2 && client->is_hoster) {
      //... hoster send to server the bundle, now server have to forward that to the corresponding new client + change state of new client
      uint16_t new_client_id = 0;
      memcpy(&new_client_id, payload, sizeof(uint16_t));
      new_client_id = ntohs(new_client_id);
      struct Client_Metadata *new_client = NULL;
      for (int i = 0; i < client->room->member_count; i++) {
        if (client->room->members[i]->client_id == new_client_id) {
          new_client = client->room->members[i];
          break;
        }
      }
      if (new_client == NULL) {
        perror("New client not found in host's room when forwarding key distro message");
        exit(EXIT_FAILURE);
      }
      new_client->state = STATE_IN_ROOM;
      uint8_t forward_buf[2048] = {0};
      forward_buf[0] = (uint8_t)2;
      uint16_t net_len = htons(payload_len - 2);
      memcpy(forward_buf + 1, &net_len, sizeof(uint16_t));
      memcpy(forward_buf + 3, payload + 2, payload_len - 2); // the bundle
      write(new_client->fd, forward_buf, 3 + payload_len - 2);
    }
  }
  return 0;
}
