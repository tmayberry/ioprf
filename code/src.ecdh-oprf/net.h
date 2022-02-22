#define PORT 9876
#define SA struct sockaddr

void receiveData(int sockfd, unsigned char *buff, unsigned long size);
void sendData(int sockfd, unsigned char *buf, size_t size);
void myServer(int *a, int *b);
void serverFunc(int sockfd);
void myClient(int *a);
void clientFunc(int sockfd);
void erikSend(int sockfd, unsigned char *buf, unsigned long size);
void erikReceive(int sockfd, unsigned char *buff, unsigned long size);
