#include <stdio.h>

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "net.h"



#define MAX 80


void myServer(int *connfd, int *sockfd) {
    struct sockaddr_in servaddr, cli;
    unsigned int len;

    // socket create and verification
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);


    int reuse = 1;
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        printf("setsockopt(SO_REUSEADDR) failed\n");

    // Binding newly created socket to given IP and verification
    if ((bind(*sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(*sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening...\n");
    len = sizeof(cli);

    // Accept the data packet from client and verification
    *connfd = accept(*sockfd, (SA*)&cli, &len);
    if (connfd < 0) {
        printf("server acccept failed...\n");
        exit(0);
    }
    else
        printf("server acccept the client...\n");

}


void serverFunc(int sockfd)
{
    char buff[MAX];
    int n;
    // infinite loop for chat
    for (;;) {
        bzero(buff, MAX);

        // read the message from client and copy it in buffer
        read(sockfd, buff, sizeof(buff));
        // print buffer which contains the client contents
        printf("From client: %s\t To client : ", buff);
        bzero(buff, MAX);
        n = 0;
        // copy server message in the buffer
        while ((buff[n++] = getchar()) != '\n')
            ;

        // and send that buffer to client
        write(sockfd, buff, sizeof(buff));

        // if msg contains "Exit" then server exit and chat ended.
        if (strncmp("exit", buff, 4) == 0) {
            printf("Server Exit...\n");
            break;
        }
    }
}


void clientFunc(int sockfd)
{
    char buff[MAX];
    int n;
    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        write(sockfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
}

void myClient(int *sockfd) {
    struct sockaddr_in servaddr;
    // socket create and varification
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else {
        printf("Socket successfully created..\n");
    }
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(*sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else {
        printf("connected to the server...\n");
    }

}

void sendData(int sockfd, unsigned char *buf, size_t size) {
    unsigned long  t = 0;
    do {
        t = t + write(sockfd, &buf[t], size - t);
    } while (t<size);

}

void erikSend(int sockfd, unsigned char *buf, unsigned long size) {
    unsigned long  t = 0;
    do {
        t = t + write(sockfd, &buf[t], 57*size - t);
    } while (t<57*size);

}

void erikReceive(int sockfd, unsigned char *buff, unsigned long size) {
    size_t t = 0;
    do {
        t = t + read(sockfd, &buff[t], 57*size - t);
    } while (t<57*size);
}

void receiveData(int sockfd, unsigned char *buff, unsigned long size) {
    size_t t = 0;
    do {
        t = t + read(sockfd, &buff[t], size - t);
    } while (t<size);
}
