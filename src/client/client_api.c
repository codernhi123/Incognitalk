#include <sys/types.h>
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

size_t read_all_bytes(const char *filename, void *buffer, size_t buffer_size) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    error_handle("Error opening file");
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size > buffer_size) {
    error_handle("File size is too large");
  }

  if (fread(buffer, 1, file_size, file) != file_size) {
    error_handle("Error reading file");
  }

  fclose(file);
  return file_size;
}

void *send_handle(void *arg) {
  struct Client_MetaData *client_info = (struct Client_MetaData *)arg;
  struct Universal_Send_Packet send_packet = {0};
  send_packet.group_id = client_info->group_id;
  memcpy(send_packet.pubkey, client_info->pubkey, strlen(client_info->pubkey));

  int8_t send_buffer[2048] = {0};
  if (client_info->is_hoster) {
    // host handshake with server
    uint16_t net_len = htons(4);
    uint32_t net_group_id = htonl(send_packet.group_id);

    send_buffer[0] = (int8_t)4; 
    memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
    memcpy(send_buffer + 3, &net_group_id, sizeof(uint32_t));

    write(client_info->sfd, send_buffer, 7);
    
    // fire waiting queue thread
    pthread_t waiting_queue_tid;
    if (pthread_create(&waiting_queue_tid, NULL, waiting_queue_handler, client_info) == -1) {
      error_handle("thread in client for waiting queue");
    }

  } else {
    // non host connects and send type 0 message to get in the room.
    pthread_mutex_lock(&thread_mutex);
    if (client_info->state == STATE_JUST_CONNECTED) { //... type 0 (client -> server)
        // Payload
        
        // Header
        send_packet.length = 4 + strlen(client_info->pubkey);
        uint16_t net_len = htons(send_packet.length);
        uint32_t net_group_id = htonl(send_packet.group_id);

        send_buffer[0] = (int8_t)0;
        memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
        memcpy(send_buffer + 3, &net_group_id, sizeof(uint32_t));
        memcpy(send_buffer + 7, send_packet.pubkey, strlen(client_info->pubkey));

      write(client_info->sfd, send_buffer, 3 + send_packet.length);
    }
    pthread_mutex_unlock(&thread_mutex);
  }

  while (1) {
    int8_t send_buffer[2048] = {0};
    // categorize type for Global Framing Rule
    if (client_info->state == STATE_IN_ROOM) {
      //... chat
      send_buffer[0] = (int8_t)1;
      // I will make a signal handler to catch SIGINT for graceful shutdown, so I can set the state to DISCONNECTED and trigger type 3 message to server for leaving room and cleanup
    } else if (client_info->state == STATE_DISCONNECTED) {
      //... disconnect
      send_buffer[0] = (int8_t)3;
    } else {
      //... unexpected behavior
      free(client_info);
      perror("Unexpected behavior in send handler");
      exit(EXIT_FAILURE);
    }
  
    //... construct the packet according to the Global Framing Rule and send to server  
  }
  
  return NULL;
}

void *waiting_queue_handler(void *arg) {
  struct Client_Waiting_Queue *waiting_queue_head = (struct Client_Waiting_Queue *)arg;

  for (;;) { // I will use a condition variable to signal this thread when there's a new client in the waiting queue, to avoid busy waiting
    pthread_mutex_lock(&thread_mutex);

    while (waiting_queue_head == NULL) {
      pthread_cond_wait(&cond, &thread_mutex);
    }
    
    while (waiting_queue_head != NULL) {
      //... encrypt the symmetric key with the new client's public key and send to server for key distribution
      struct Client_Waiting_Queue *current = waiting_queue_head;
      while (current != NULL) {
        uint8_t send_buffer[2048] = {0};
        send_buffer[0] = (int8_t)2; // type 2 for key distribution
        uint16_t net_len = htons(PUBKEY_LEN);
        memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
        memcpy(send_buffer + 3, &current->new_client_id, sizeof(uint16_t));
        // hoster now sign (using his pivate key) and encrypt the signed sec key using newcomer's pubkey
        
        // signing
        // encrypting
        memcpy(send_buffer + 5, signed_and_hashed_seckey, PUBKEY_LEN);
        // construct the rest of the packet and send to server
        current = current->next;
      }
      waiting_queue_head = current;
    }
    pthread_mutex_unlock(&thread_mutex);
    
  }
  return NULL;
}