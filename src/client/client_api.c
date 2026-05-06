#include <sys/types.h>
#include <openssl/rand.h>
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


// --- Helper functions, might be unused, but keep for now ---
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

// --- Consumer part - receive messages from server and process ---
void message_processor(struct Client_Metadata *client, uint8_t type, uint8_t *payload, int payload_len) {
  //... categorize the message type and process accordingly, including decryption and verification
  if (type == 0 && client->is_hoster) { // hoster receive type 0 msg from newcomer
    pthread_mutex_lock(&waiting_queue_mutex);
      struct Client_Waiting_Queue *new_client = (struct Client_Waiting_Queue *)malloc(sizeof(struct Client_Waiting_Queue));
      new_client->sfd = client->sfd;
      uint16_t net_client_id = 0;
      memcpy(&net_client_id, payload, sizeof(uint16_t));
      new_client->new_client_id = ntohs(net_client_id);
      memcpy(new_client->new_client_pubkey, payload + 2, payload_len - 2);
      new_client->next = NULL;

      //add the new client to the waiting queue for key distribution
      if (client->waiting_queue_head == NULL) {
        client->waiting_queue_head = new_client;
      } else  {
        client->waiting_queue_tail->next = new_client;
      }
      client->waiting_queue_tail = new_client;
    pthread_mutex_unlock(&waiting_queue_mutex);
    // trigger conditional variable to wake up waiting queue thread to do key distro
    pthread_cond_signal(&cond);
  } else if (type == 1) { // receive encrypted chat message, decrypt and print/log

  } else if (type == 2 && client->is_hoster == 0) { // newcomer receive encrypted symmetric key from hoster, verify signature, decrypt and store the symmetric key for future use
    //a. verify the signature with hoster's pubkey
    char host_pubkey[2048] = {0};
    memcpy(host_pubkey, payload, payload_len - 512); // host_pubkey + encrypted_seckey (256) + signature (256)
    int host_pubkey_len = payload_len - 512;
    unsigned char encrypted_seckey[256] = {0};
    memcpy(encrypted_seckey, payload + host_pubkey_len, 256);
    unsigned char signature[256] = {0};
    memcpy(signature, payload + host_pubkey_len + 256, 256);
    if (rsa_verify_with_public_key(host_pubkey, encrypted_seckey, 256, signature, 256) == -1) {
      error_handle("Verification failed in message processor, beware of potential MITM attack");
    }
    //b. decrypt the symmetric key with newcomer's private key
    if (rsa_decrypt_with_private_key(client->keypair.private_key_pem, encrypted_seckey, 256, shared_seckey, &shared_seckey_len) == -1) {
      error_handle("Decryption failed in message processor");
    }
    //c. update client's state to IN_ROOM, now the client can send type 1 or 3 messages to server
    pthread_mutex_lock(&state_mutex);
    client->state = STATE_IN_ROOM;
    pthread_cond_signal(&state_cond);
    pthread_mutex_unlock(&state_mutex);
  } else if (type == 3) { // receive disconnect signal, do cleanup

  } else if (type == 4 && client->is_hoster) { // receive the assigned groupchat_id from server after hoster send type 4 message to server for room creation
    //... extract the assigned groupchat_id from the payload and update the client's state
    uint32_t net_group_id = 0;
    memcpy(&net_group_id, payload, sizeof(uint32_t));
    client->group_id = ntohl(net_group_id);
    
    pthread_mutex_lock(&state_mutex);
    client->state = STATE_IN_ROOM;
    pthread_cond_signal(&state_cond);
    pthread_mutex_unlock(&state_mutex);
  } else {
    error_handle("Unexpected message type in message processor");
  }
}

// --- Producer part - function handler for producer thread: sending messages to server ---
void *send_handler(void *arg) {
  struct Client_Metadata *client_info = (struct Client_Metadata *)arg;
  struct Universal_Send_Packet send_packet = {0};

  int8_t send_buffer[2048] = {0};
  if (client_info->is_hoster) {
    // host handshake with server (request to create room)

    send_buffer[0] = (int8_t)4; 
    uint16_t net_len = htons(0);
    memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));

    write(client_info->sfd, send_buffer, 3);
    
    // Note: we can fire the waiting queue thread here, but we don't know the room ID yet.
    // The message_processor will handle the TYPE 4 response and print the Room ID to the terminal for the host.
    pthread_t waiting_queue_tid;
    if (pthread_create(&waiting_queue_tid, NULL, waiting_queue_handler, (void *)client_info) == -1) {
      error_handle("thread in client for waiting queue");
    }
  } else {
    // non host connects and send type 0 message to get in the room.
    send_packet.group_id = client_info->group_id;
    memcpy(send_packet.pubkey, client_info->keypair.public_key_pem, client_info->pubkey_len);
    if (client_info->state == STATE_JUST_CONNECTED) { //... type 0 (client -> server)
        // Header
      send_packet.length = 4 + client_info->pubkey_len;
      uint16_t net_len = htons(send_packet.length);
      uint32_t net_group_id = htonl(send_packet.group_id);
      send_buffer[0] = (int8_t)0;
      memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
      // Payload
      memcpy(send_buffer + 3, &net_group_id, sizeof(uint32_t));
      memcpy(send_buffer + 7, send_packet.pubkey, client_info->pubkey_len);

      write(client_info->sfd, send_buffer, 3 + send_packet.length);
    }
  }

  // Wait safely until the state transitions to STATE_IN_ROOM before allowing any chat loops
  pthread_mutex_lock(&state_mutex);
  while (client_info->state != STATE_IN_ROOM && client_info->state != STATE_DISCONNECTED) {
    pthread_cond_wait(&state_cond, &state_mutex);
  }
  pthread_mutex_unlock(&state_mutex);

  while (1) {
    int8_t send_buffer[2048] = {0};
    if (client_info->state == STATE_IN_ROOM) {
      //... type 1
      send_buffer[0] = (int8_t)1;
      char chat_input[1024] = {0};
      if (fgets(chat_input, sizeof(chat_input), stdin)) {
        chat_input[strcspn(chat_input, "\n")] = 0;
        int pt_len = strlen(chat_input);

        if (pt_len > 0) {
            unsigned char iv[16];
            if (RAND_bytes(iv, sizeof(iv)) != 1) {
                error_handle("Failed to generate IV");
            }
            unsigned char ciphertext[1024 + 16]; 
            int ct_len = aes_encrypt((unsigned char*)chat_input, pt_len, shared_seckey, iv, ciphertext);
            if (ct_len < 0) {
                error_handle("AES encryption failed");
            }
            // construct the Payload: <IV (16)> + <Ciphertext (ct_len)>
            uint16_t payload_len = 16 + ct_len;
            uint16_t net_len = htons(payload_len);

            // construct the packet
            send_buffer[0] = (int8_t)1; // TYPE 1
            memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
            memcpy(send_buffer + 3, iv, 16);
            memcpy(send_buffer + 19, ciphertext, ct_len);

            // send to Server (Total bytes = 3 byte header + Payload)
            write(client_info->sfd, send_buffer, 3 + payload_len);
        }
      }
    } else if (client_info->state == STATE_DISCONNECTED) {
      //... disconnect
      send_buffer[0] = (int8_t)3;
    } else {
      //... unexpected behavior
      error_handle("Unexpected behavior in send handler");
    }
  
    //... construct the packet according to the Global Framing Rule and send to server  
  }
  
  return NULL;
}

// --- secondary consumer part - function handler for a sub-thread that handles the waiting queue with condition variable to avoid busy waiting ---
void *waiting_queue_handler(void *arg) {
  struct Client_Metadata *client_info = (struct Client_Metadata *)arg;
  
  for (;;) {
    pthread_mutex_lock(&waiting_queue_mutex);

    while (client_info->waiting_queue_head == NULL) {
      pthread_cond_wait(&cond, &waiting_queue_mutex);
    }

    struct Client_Waiting_Queue *processing_queue = client_info->waiting_queue_head;
    client_info->waiting_queue_head = NULL;
    client_info->waiting_queue_tail = NULL;

    pthread_mutex_unlock(&waiting_queue_mutex);

    while (processing_queue != NULL) {
      uint8_t send_buffer[2048] = {0};
      send_buffer[0] = (int8_t)2; // type 2 for key distribution

      //... Payload = [newcomer_id] + [Host pubkey] + [ecrypted_shared_seckey] + [signature]
      // a. encrypting seckey with newcomer's pubkey, encrypted_seckey = 256
      unsigned char encrypted_seckey[256] = {0};
      size_t encrypted_seckey_len = sizeof(encrypted_seckey);
      if (rsa_encrypt_with_public_key(processing_queue->new_client_pubkey, shared_seckey, AES_KEY_LEN, encrypted_seckey, &encrypted_seckey_len) == -1) {
        error_handle("RSA encryption in waiting queue handler");
      }
      // b. signing the symmetric key with hoster's private key, signature = 256 
      unsigned char signature[256] = {0};
      size_t signature_len = sizeof(signature);
      if (rsa_sign_with_private_key(disk_prikey, encrypted_seckey, encrypted_seckey_len, signature, &signature_len) == -1) {
        error_handle("RSA signing in waiting queue handler");
      }
      // c. Payload Construction 
      int host_pubkey_len = client_info->pubkey_len;
      int payload_len = 2 + host_pubkey_len + encrypted_seckey_len + signature_len;

      uint16_t net_len = htons(payload_len); // new_client_id + host_pubkey + encrypted_seckey + signature
      memcpy(send_buffer + 1, &net_len, sizeof(uint16_t));
      uint16_t net_new_client_id = htons(processing_queue->new_client_id);
      memcpy(send_buffer + 3, &net_new_client_id, sizeof(uint16_t));

      memcpy(send_buffer + 5, client_info->keypair.public_key_pem, host_pubkey_len);
      memcpy(send_buffer + 5 + host_pubkey_len, encrypted_seckey, encrypted_seckey_len);
      memcpy(send_buffer + 5 + host_pubkey_len + encrypted_seckey_len, signature, signature_len);

      write(processing_queue->sfd, send_buffer, 3 + payload_len); // send back to server for distro

      // move to next & free current client
      struct Client_Waiting_Queue *temp = processing_queue;
      processing_queue = processing_queue->next;
      free(temp);
    }
  }
  return NULL;
}