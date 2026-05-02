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

int PORT = 0;
int BUFF_MAX = 2048;
char IP_str[2048] = {0};

char log_path[2048] = {0};
char disk_pubkey[2048] = {0};
char disk_prikey[2048] = {0};
unsigned char shared_secret[2048] = {0};

pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

RSA_Keypair keypair; // global variable to store the generated key pair for this client, to be used in the send handler and waiting queue handler

int main(int argc, char *argv[]) { // ./client <IP> <PORT> <Hoster_Boolean> <GroupID> <Pubkey_Path> <Prikey_Path> <log_path> 
  // -- Using Producer-Consumer pattern for client, i.e two threads for sending and receiving
  if (argc != 8) {
    error_handle("CLI argument client");
  }
  strcpy(IP_str, argv[1]);
  PORT = atoi(argv[2]);

  int is_hoster = atoi(argv[3]);

  uint32_t group_id = (uint32_t)atoi(argv[4]);

  char pubkey_path[2048] = {0};
  strcpy(pubkey_path, argv[5]);

  char prikey_path[2048] = {0};
  strcpy(prikey_path, argv[6]);

  strcpy(log_path, argv[7]); // to save decrypted messages some where on client's disk

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

  struct Client_MetaData client_info;
  memset(&client_info, 0, sizeof(client_info));

  //TODO: setting up producer part - send to server
  size_t disk_pubkey_len = read_all_bytes(pubkey_path, disk_pubkey, sizeof(disk_pubkey));
  size_t disk_prikey_len = read_all_bytes(prikey_path, disk_prikey, sizeof(disk_prikey));

  client_info.sfd = sfd;
  client_info.my_client_id = -1; // will later be given by server
  client_info.group_id = group_id;
  client_info.is_hoster = is_hoster;
  client_info.state = STATE_JUST_CONNECTED; // will later be given by server
  memcpy(client_info.pubkey, disk_pubkey, disk_pubkey_len);
  client_info.waiting_queue_head = NULL;

  generate_rsa_keypair(&keypair);

  // hoster making the mutual secret key
  if (client_info.is_hoster) {
    // building the group chat's secret key
    if (generate_symmetric_key(shared_secret) == -1) {
      error_handle("generate symmetric key in client");
    }
  }
  
  pthread_t send_tid;
  if (pthread_create(&send_tid, NULL, send_handler, &client_info) == -1) {
    error_handle("thread in client");
  }
  
  // consumer part - receive from server
  int log_fd = open(log_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ssize_t num_read = 0;
  uint8_t recv_buf[2048];
  int leftover_bytes = 0;
  // receive ... (working on)


  
  return 0;
}