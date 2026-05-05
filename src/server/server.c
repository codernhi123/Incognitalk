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

int PORT = 0;
int BUFF_MAX = 2048;
int MAX_CLIENTS = 10000;

int LISTEN_BACKLOG = 0; // to be set in argument
short CLIENTS_CNT = 0;

struct GroupChat_Metadata glob_groupchats[10000]; // server keeps track of all rooms
short GLOB_GROUPCHAT_CNT = 0;

int main(int argc, char *argv[]) // ./server <port> <MAX_CLIENTS> 
{
  // setting up TCP pipeline for server with IPv6 communication
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

  if (bind(s_fd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in6)) == -1) {
    error_handle("server bind issue");
  }

  LISTEN_BACKLOG = MAX_CLIENTS;
  if (listen(s_fd, LISTEN_BACKLOG) == -1) {
    error_handle("listen issue");
  }

  int epoll_fd;
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

  for (;;) {
    nfds = epoll_wait(epoll_fd, events, MAX_CLIENTS, -1);
    if (nfds == -1) {
      error_handle("epoll_wait issue");
    }
    for (int i = 0; i < nfds; i++)
    {
      if (events[i].data.fd == s_fd) {
        // 1 --- dealing with newcomers
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
        ev.events = EPOLLIN;
        ev.data.ptr = newclient;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, newclient->fd, &ev) == -1) {
          perror("epoll_cntl: conn_sock");
          free(newclient);
          exit(EXIT_FAILURE);
        }

        // initate newcomer's state, NO KEY SHARING YET, only when send the first message
        newclient->groupchat_id = -1;  // -1 means "Not in a room yet", will be replaced when client send first type 0 message to server for key distro
        newclient->room = NULL;
        memset(newclient->pubkey, 0, 256);
        newclient->state = STATE_JUST_CONNECTED;
        newclient->client_id = CLIENTS_CNT++;
        memset(newclient->recv_buf, 0, sizeof(char) * BUFF_MAX);
      } else {
        // 2 --- extract and handling message
        struct Client_Metadata *client = (struct Client_Metadata *)events[i].data.ptr;
        message_handler((struct Client_Metadata *)client);
      }
    }
  }
  //..clean up
  return 0;
}