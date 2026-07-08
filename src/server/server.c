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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>

int PORT = 0;
int BUFF_MAX = 2048;
int MAX_CLIENTS = 100000; // = #members in a room * #room: to be set in argument 
int LISTEN_BACKLOG = 0; // to be set in argument
short CLIENTS_CNT = 0;
int READ_QUOTA = 8192; // to avoid starvation of clients with large messages, we will only read 8192 bytes from the socket each time, and if there's still leftover bytes then we will read in the next round after processing the current message

struct GroupChat_Metadata glob_groupchats[100]; // server keeps track of all rooms
pthread_t pthread_id[64];
short GLOB_GROUPCHAT_CNT = 0;
pthread_mutex_t glob_groupchats_mutex = PTHREAD_MUTEX_INITIALIZER;

atomic_int concurrent_clients = 0;
atomic_int peak_concurrent_clients = 0;

sem_t task_sem;
struct Client_Metadata *task_circular_queue[100000]; // for worker threads to get the waiting client to process, CS hence protected by a mutex
int queue_front = 0;
int queue_rear = 0;
int queue_size = 0;
pthread_mutex_t task_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
int epoll_fd = -1;

int main(int argc, char *argv[]) // ./server <port> <MAX_CLIENTS> 
{
  int NUM_THREADS = sysconf(_SC_NPROCESSORS_ONLN);
  // --- setting up TCP pipeline for server with IPv6 communication
  if (argc != 3) {
    error_handle("CLI argument for server issue");
  }
  PORT = atoi(argv[1]);
  MAX_CLIENTS = atoi(argv[2]);

  struct sockaddr_in6 s_addr;
  socklen_t addr_len = sizeof(s_addr);
  memset(&s_addr, 0, sizeof(struct sockaddr_in6));
  s_addr.sin6_family = AF_INET6;
  s_addr.sin6_port = htons(PORT);
  s_addr.sin6_addr = in6addr_any;

  int s_fd;
  s_fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (s_fd == -1) {
    error_handle("server socket issue");
  }

  // set SO_REUSEADDR to avoid "Address already in use" error when restarting server
  int opt = 1;
  if (setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    error_handle("setsockopt SO_REUSEADDR issue");
  }

  if (bind(s_fd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in6)) == -1) {
    error_handle("server bind issue");
  }

  LISTEN_BACKLOG = MAX_CLIENTS;
  if (listen(s_fd, LISTEN_BACKLOG) == -1) {
    error_handle("listen issue");
  }

  // --- setting up epoll
  int nfds = 0;
  struct epoll_event ev, events[MAX_CLIENTS];

  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    error_handle("epoll_create1 issue");
  }
  ev.events = EPOLLIN;
  ev.data.fd = s_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s_fd, &ev) == -1) {
    error_handle("epoll_ctl: listen_sock issue");
  }

  // --- setting up threadpool
  sem_init(&task_sem, 0, 0);
  for (int i = 0; i < NUM_THREADS; i++) {
    if (pthread_create(&pthread_id[i], NULL, (void *)message_handler, NULL) != 0) {
      error_handle("pthread_create issue");
    }
  }

  for (;;) {
    nfds = epoll_wait(epoll_fd, events, MAX_CLIENTS, -1);
    if (nfds == -1) {
      error_handle("epoll_wait issue");
    }
    for (int i = 0; i < nfds; i++)
    {
      if (events[i].data.fd == s_fd) {
        // --- dealing with newcomers
        struct Client_Metadata *newclient = malloc(sizeof(struct Client_Metadata));
        memset(&newclient->addr, 0, sizeof(struct sockaddr_in6));
        newclient->fd = accept(s_fd, (struct sockaddr *)&newclient->addr, &addr_len);
        if (newclient->fd == -1) {
          free(newclient);
          error_handle("accept issue");
        }
        // set O_NONBLOCK & add newcomer's fd into epoll
        int flags = fcntl(newclient->fd, F_GETFL, 0);
        flags |= O_NONBLOCK;
        if (fcntl(newclient->fd, F_SETFL, flags) == -1) {
          free(newclient);
          error_handle("accept issue");
        }
        ev.events = EPOLLIN | EPOLLONESHOT; // use EPOLLONESHOT to avoid multiple threads handling the same client concurrently, we will reset it after processing the client's message in the worker thread
        ev.data.ptr = newclient;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, newclient->fd, &ev) == -1) {
          perror("epoll_cntl: conn_sock");
          free(newclient);
          exit(EXIT_FAILURE);
        }

        // initate newcomer's other attributes, NO KEY SHARING YET, only when send the first message
        newclient->groupchat_id = -1;  // -1 means "Not in a room yet", will be replaced when client send first type 0 message to server for key distro
        newclient->room = NULL;
        newclient->state = STATE_JUST_CONNECTED;
        newclient->client_id = CLIENTS_CNT++;
        pthread_mutex_init(&newclient->client_mutex, NULL);
        atomic_init(&newclient->ref_count, 1); // 1 reference owned by the epoll/main track
        memset(newclient->recv_buf, 0, sizeof(char) * BUFF_MAX);
        newclient->leftover_bytes = 0;
      } else {
        // --- extract and handling message
        struct Client_Metadata *client = (struct Client_Metadata *)events[i].data.ptr;
        // ... add the client into task queue and wake up worker thread to process the message, the worker thread will take care of the state transition and response message construction/sending
        pthread_mutex_lock(&task_queue_mutex);
        if (queue_size == 100000) {
          pthread_mutex_unlock(&task_queue_mutex);
          error_handle("Task queue overflow, too many clients to handle");
        }
        task_circular_queue[queue_rear] = client;
        queue_rear = (queue_rear + 1) % 100000;
        queue_size++;
        pthread_mutex_unlock(&task_queue_mutex);
        sem_post(&task_sem);
        // same as: message_handler((struct Client_Metadata *)client); like v1.0
      }
    }
  }
  //..clean up
  close(s_fd);
  return 0;
}