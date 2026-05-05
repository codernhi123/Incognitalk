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

void message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len) {
  //... categorize the message type and process accordingly, including decryption and verification
  pthread_mutex_lock(&thread_mutex);
    if (type == 0 && client->is_hoster) { // hoster receive type 0 msg from newcomer
      
      // trigger conditional variable to wake up waiting queue thread to do key distro
      pthread_cond_signal(&cond);
    } else if (type == 1) { // receive encrypted chat message, decrypt and print/log

    } else if (type == 2) { // newcomer receive encrypted symmetric key from hoster, verify signature, decrypt and store the symmetric key for future use

    } else if (type == 3) { // receive disconnect signal, do cleanup

    } else {
      perror("Unexpected message type in message processor");
      exit(EXIT_FAILURE);
    }
  pthread_mutex_unlock(&thread_mutex);
}

void *send_handler(void *arg) {
  struct Client_Metadata *client_info = (struct Client_Metadata *)arg;
  struct Universal_Send_Packet send_packet = {0};
  send_packet.group_id = client_info->group_id;
  memcpy(send_packet.pubkey, client_info->pubkey, strlen(client_info->pubkey));

  int8_t send_buffer[2048] = {0};
  if (client_info->is_hoster) {
    // host handshake with server
    send_packet.length = 4 + strlen(client_info->pubkey);
    uint16_t net_len = htons(send_packet.length);
    uint32_t net_group_id = htonl(send_packet.group_id);

    send_buffer[0] = (int8_t)4; 
    memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
    memcpy(send_buffer + 3, &net_group_id, sizeof(uint32_t));
    memcpy(send_buffer + 7, send_packet.pubkey, strlen(client_info->pubkey));

    write(client_info->sfd, send_buffer, 3 + send_packet.length);
    
    // fire waiting queue thread
    pthread_t waiting_queue_tid;
    if (pthread_create(&waiting_queue_tid, NULL, waiting_queue_handler, client_info->waiting_queue_head) == -1) {
      error_handle("thread in client for waiting queue");
    }
  } else {
    // non host connects and send type 0 message to get in the room.
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
      struct Client_Waiting_Queue *current_new_client = waiting_queue_head;
      while (current_new_client != NULL) {
        uint8_t send_buffer[2048] = {0};
        send_buffer[0] = (int8_t)2; // type 2 for key distribution
        uint16_t net_new_client_id = htons(current_new_client->new_client_id);
        memcpy(send_buffer + 3, &net_new_client_id, sizeof(uint16_t));
        //... hoster now encrypt the shared_seckey using newcomer's pubkey, sign it and put both [ecrypted_shared_seckey] + [signature] in the payload (call it bundle)
        
        // encrypting seckey with newcomer's pubkey, encrypted_seckey = 256
        unsigned char encrypted_seckey[256] = {0};
        size_t encrypted_seckey_len = sizeof(encrypted_seckey);
        if (rsa_encrypt_with_public_key(current_new_client->new_client_pubkey, shared_seckey, AES_KEY_LEN, encrypted_seckey, &encrypted_seckey_len) == -1) {
          error_handle("RSA encryption in waiting queue handler");
        }
        // signing the symmetric key with hoster's private key, signature = 256 
        unsigned char signature[256] = {0};
        size_t signature_len = sizeof(signature);
        if (rsa_sign_with_private_key(disk_prikey, encrypted_seckey, encrypted_seckey_len, signature, &signature_len) == -1) {
          error_handle("RSA signing in waiting queue handler");
        }
        // putting bundle (512) and payload length to the send buffer
        unsigned char bundle[512] = {0};
        memcpy(bundle, encrypted_seckey, encrypted_seckey_len);
        memcpy(bundle + encrypted_seckey_len, signature, signature_len);
        memcpy(send_buffer + 5, bundle, encrypted_seckey_len + signature_len);

        size_t Bundle_len = encrypted_seckey_len + signature_len;
        uint16_t net_len = htons(2 + Bundle_len); // new_client_id + Bundle_len in payload
        memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));

        write(current_new_client->sfd, send_buffer, 3 + 2 + Bundle_len); // send back to server for distro
        // construct the rest of the packet and send to server
        current_new_client = current_new_client->next;
      }
      waiting_queue_head = current_new_client;
    }
    pthread_mutex_unlock(&thread_mutex);
    
  }
  return NULL;
}