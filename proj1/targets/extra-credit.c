#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

int freadline(int fd, char *buf) {
  int i = 0;
  char next;
  for (;;) {
    int c = read(fd, &next, 1);
    if (c <= 0) {
      break;
    }

    if (next == '\n') {
      return i;
    }

    buf[i] = next;

    i++;
  }
  return -1;
}

int respond_once(int clientfd) {
  char buf[2048];

  int line_len = freadline(clientfd, buf);
  if (line_len <= 0) {
    write(clientfd, "done\r\n", 6);
    close(clientfd);
    return -1;
  }

  write(clientfd, buf, line_len);
  write(clientfd, "\r\n", 2);
  return line_len;
}

void echo_server(int clientfd) {

  while (respond_once(clientfd) >= 0) {
    ;;
  }
}

/* socket-bind-listen idiom */
static int start_server(const char *portstr)
{
    struct addrinfo hints = {0}, *res;
    int sockfd;
    int e, opt = 1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((e = getaddrinfo(NULL, portstr, &hints, &res)))
        errx(1, "getaddrinfo: %s", gai_strerror(e));
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        err(1, "socket");
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        err(1, "setsockopt");
    if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
        err(1, "fcntl");
    if (bind(sockfd, res->ai_addr, res->ai_addrlen))
        err(1, "bind");
    if (listen(sockfd, 5))
        err(1, "listen");
    freeaddrinfo(res);

    return sockfd;
}

int main() {
  char *portstr = "5555";
  int serverfd = start_server(portstr);
  warnx("Listening on port %s", portstr);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  for (;;) {
    int clientfd = accept(serverfd, NULL, NULL);
    int pid;
    switch ((pid = fork()))
    {
    case -1: /* error */
        err(1, "fork");
        close(clientfd);
    case 0:  /* child */
        echo_server(clientfd);
        break;
    default: /* parent */
        close(clientfd);
    }
  }

  return 0;
}

