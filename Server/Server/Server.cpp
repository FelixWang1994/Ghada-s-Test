#undef UNICODE
#define WIN32_LEAN_AND_MEAN
#define AES_BITS 128
#define MSG_LEN 512
#define DEFAULT_BUFLEN 512

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

// for decrypting the recieved file
int aes_decrypt(char* in, char* key, char* out)
{
	if (!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE];
	for (int i = 0; i<AES_BLOCK_SIZE; ++i)
		iv[i] = 0;
	AES_KEY aes;
	if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
		return 0;
	}
	int len = strlen(in);
	if (len % 16 != 0){
		len = 16 * (len / 16 + 1);
	}
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}

// for generate the MD5 of a file
char* MD5(FILE *pFile){
	MD5_CTX ctx;
	int len = 0;
	unsigned char buffer[1024] = { 0 };
	unsigned char digest[16] = { 0 };
	if (pFile == NULL)
	{
		printf("open file failed\n");
		return NULL;
	}
	MD5_Init(&ctx);
	while ((len = fread(buffer, 1, 1024, pFile)) > 0)
	{
		MD5_Update(&ctx, buffer, len);
	}
	fclose(pFile);
	MD5_Final(digest, &ctx);
	int i = 0;
	char buf[33] = { 0 };
	char tmp[3] = { 0 };
	for (i = 0; i < 16; i++)
	{
		sprintf(tmp, "%02X", digest[i]);
		strcat(buf, tmp);
	}
	return buf;
}

// for compare the MD5 result
bool verifyMD5(char * c1, char* c2){
	for (int i = 0; i < 32; i++){
		if (c1[i] != c2[i])
			return false;
	}
	return true;
}

int main(int argc, char **argv){
	WSADATA wsaData;
	int iResult;
	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket;
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	//char recvbuf[DEFAULT_BUFLEN];
	//int recvbuflen = DEFAULT_BUFLEN;
	char temp[DEFAULT_BUFLEN], file_name[DEFAULT_BUFLEN];

	// Check the commanline parameter for the port
	if (argc != 3){
		printf("Check the parameters please!\n");
		return 1;
	}

	printf("***********Server begins to work!***********\n");

	// Record the comming file name and create the file if not existed
	printf("Give a name to the comming file!\n");
	scanf("%s", file_name);
	// create file
	FILE *fp = fopen(file_name, "wb");
	if (fp == NULL){
		printf("create file %s failed\n", file_name);
		return -1;
	}

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	// Resolve the local address and port to be used by the server
	iResult = getaddrinfo(argv[1], argv[2], &hints, &result);
	if (iResult != 0){
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}
	// Setup the listenSocket
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET){
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}
	printf("Server is listening............\n");
	// Bind the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR){
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	freeaddrinfo(result);
	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR){
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	// Accept a client socket
	ClientSocket = INVALID_SOCKET;
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	// No longer need server socket
	closesocket(ListenSocket);
	// Receive data from the Client  
	char key[AES_BLOCK_SIZE];
	int num = 0;      // How much data received
	int count = 0;    // Indicate what has been received 
	char recvMD5[32]; // To store the received MD5
	while (count <=2)
	{
		num = recv(ClientSocket, temp, DEFAULT_BUFLEN, 0);
		if (num < 0){
			printf("recv failed: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}
		else if (num > 0){
			switch (count){
			case 0:{     //Firstly receive the key.
				count++;
				for (int i = 0; i < 16; i++)  // Set the key as received key
				{
					key[i] = temp[i];
				}
				printf("Key has been received!\n");
				send(ClientSocket, "Key received!!", 16, 0);
				printf("Server is listening............\n");
				Sleep(1500);
				memset((char*)temp, 0, DEFAULT_BUFLEN);
				break;
			}
			case 1:{
				printf("Correct MD5 has been received: %s\n", temp);
				for (int j = 0; j < 32; j++){
					recvMD5[j] = temp[j];
				}
				count++;
				send(ClientSocket, "MD5 received!", 16, 0);
				printf("Server is listening............\n");
				//Sleep(1500);
				memset((char*)temp, 0, DEFAULT_BUFLEN);
				break;
			}
			default:{
				break;
			}
			}
			
		} else{
			break;
		}
	}
	send(ClientSocket, "File received!!", 16, 0);
	// Decrypt received file
	char sourceStringTemp[MSG_LEN];
	char dstStringTemp[MSG_LEN];
	memset((char*)sourceStringTemp, 0, MSG_LEN);
	memset((char*)dstStringTemp, 0, MSG_LEN);
	strcpy((char*)dstStringTemp, temp);
	int i;
	if (!aes_decrypt(dstStringTemp, key, sourceStringTemp))
	{
		printf("decrypt error\n");
		return -1;
	}
	printf("received file before decrypting:\n");
	for (int i = 0; dstStringTemp[i]; i += 1){
		printf("%x", (unsigned char)dstStringTemp[i]);
	}
	printf("\n");
	printf("received file after decrypting:\n");
	printf("%s\n", sourceStringTemp);
	// Below is to show the binary format of the file
	//printf("dec %d:", strlen((char*)sourceStringTemp));
	//for (i = 0; sourceStringTemp[i]; i += 1){
	//	printf("%x", (unsigned char)sourceStringTemp[i]);
	//}
	fwrite(sourceStringTemp, 1, (int)strlen(sourceStringTemp), fp);
	printf("transmission done\n");

	// shutdown the send half of the connection cause no more data will be sent
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR){
		printf("shutdown failed: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		return 1;
	}

	// cleanup and Verify the MD5
	fclose(fp);
	// have to create a new pointer to the file with the property of "rb" for the md5 function
	FILE * pFile = fopen(file_name, "rb"); // binary mode for read  
	if (pFile == NULL)
	{
		printf("open file %s failed\n", file_name);
		return -1;
	}
	char *MD = MD5(pFile);
	printf("The MD5 of created file is:");
	for (int a = 0; a < 32; a++)
		printf("%c", MD[a]);
	printf("\n");
	printf("The received MD5        is:");
	for (int a = 0; a < 32; a++)
		printf("%c", recvMD5[a]);
	printf("\n");
	if (verifyMD5(MD, recvMD5))
		printf("File is correct!\n");
	else
		printf("File is broken!\n");

	closesocket(ClientSocket);
	WSACleanup();

	return 0;
}
