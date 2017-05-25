#include <arpa/inet.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

const uint16_t port = 1234;
int clientfd;

ssize_t recv_line(char *buf) {
    ssize_t rc;
    size_t nread = 0;
    while (1) {
        rc = recv(clientfd, buf + nread, 1, 0);
        if (rc == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            break;
        }
        nread += rc;
        if (buf[nread - 1] == '\n') {
            break;
        }
    }
    return nread;
}

ssize_t sendlen(const char *buf, size_t n) {
    ssize_t rc;
    size_t nsent = 0;
    while (nsent < n) {
        rc = send(clientfd, buf + nsent, n - nsent, 0);
        if (rc == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            return -1;
        }
        nsent += rc;
    }
    return nsent;
}

ssize_t sendstr(const char *str) {
    return sendlen(str, strlen(str));
}

int handle() {
    char buf[256];
    memset(buf, 0, 256);
    sendstr("Welcome to Remote *ECHO* Service!\n");
    recv_line(buf);
    sendstr(buf);
}

int main(int argc, char **argv) {
    int rc;
    int opt;
    int sockfd;
    pid_t pid;
    struct sockaddr_in saddr = {0};

    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        fputs("Failed to set SIGCHLD handler.", stderr);
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
                   sizeof(opt)) != 0) {
        perror("setsockopt");
        return 1;
    }

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *) &saddr,
             sizeof(saddr)) != 0) {
        perror("bind");
        return 1;
    }

    if (listen(sockfd, 20) != 0) {
        perror("listen");
        return 1;
    }

    while (1) {
        clientfd = accept(sockfd, NULL, NULL);
        if (clientfd == -1) {
            perror("accept");
            continue;
        }

        pid = fork();
        if (pid == -1) {
            perror("fork");
            close(clientfd);
            continue;
        }

        if (pid == 0) {
            alarm(15);

            close(sockfd);

            rc = 0;
            if (rc == 0) {
                if (dup2(clientfd, 0) == -1) {
                    perror("dup2");
                    close(clientfd);
                    continue;
                }
                if (dup2(clientfd, 1) == -1) {
                    perror("dup2");
                    close(clientfd);
                    continue;
                }
                rc = handle();
            }

            close(clientfd);
            _exit(rc);
        }

        close(clientfd);
    }

    return 0;
}
