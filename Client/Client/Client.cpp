#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 512
#define AES_BITS 128
#define MSG_LEN 512

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

// for encrypting the file
int aes_encrypt(char* in, char* key, char* out)
{
	if (!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE];
	for (int i = 0; i<AES_BLOCK_SIZE; ++i)
		iv[i] = 0;
	AES_KEY aes;
	if (AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
		return 0;
	}
	int len = strlen(in);
	if (len % 16 != 0){
		len = 16 * (len / 16 + 1);
	}
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
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


int main(int argc, char **argv){
	WSADATA wsaData;
	int iResult;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	SOCKET ConnectSocket = INVALID_SOCKET;
	char recvbuf[DEFAULT_BUFLEN];
	int count = 0;    // to indicate what to send

	//Validate the parameters
	if (argc != 3){
		printf("Check the parameters please!\n");
		return 1;
	}

	//initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0){
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	// Resolve the server address and port
	iResult = getaddrinfo(argv[1], argv[2], &hints, &result);
	if (iResult != 0){
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}
	// Attemp to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next){
		//Create a SOCKET for connecting the server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET){
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}
		//Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR){
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}
	freeaddrinfo(result);
	if (ConnectSocket == INVALID_SOCKET){
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	printf("Connect successfully!\n");

	// File operation
	char temp[DEFAULT_BUFLEN];
	printf("Input the file you want to transfer\n");
	scanf("%s", temp);
	// open file   
	FILE * fp = fopen(temp, "rb"); // binary mode for read  
	if (fp == NULL)
	{
		printf("open file %s failed\n", temp);
		return -1;
	}

	// Calculate the MD5 of the file
	char *MD = MD5(fp);
	char MDTemp[32];
	for (int i = 0; i < 32; i++)
		MDTemp[i] = MD[i];

	// Have to reopen the file because it has been closed in MD5 function
	fp = fopen(temp, "rb");
	if (fp == NULL)
	{
		printf("open file %s failed\n", temp);
		return -1;
	}

	// Set up the key arbitrarily what will be sent to the server later
	char key[AES_BLOCK_SIZE];
	int i;
	for (i = 0; i < 16; i++)
	{
		key[i] = 35 + i;
	}

	// Encrpty the file
	char sourceStringTemp[MSG_LEN];
	char dstStringTemp[MSG_LEN];
	memset((char*)sourceStringTemp, 0, MSG_LEN);
	memset((char*)dstStringTemp, 0, MSG_LEN);
	int num = 0;
	while (!feof(fp))
	{
		num = fread(sourceStringTemp, 1, DEFAULT_BUFLEN, fp);
	}
	printf("\n");
	printf("File before encrypting: \n");
	printf("%s\n", sourceStringTemp);
	if (!aes_encrypt(sourceStringTemp, key, dstStringTemp))
	{
		printf("encrypt error\n");
		return -1;
	}
	printf("File after  encrypting: \n");
	for (int i = 0; dstStringTemp[i]; i += 1){
		printf("%x", (unsigned char)dstStringTemp[i]);
	}
	printf("\n");

	// Transmission process
	int iDataNum = 0;
	while (count<=2){
		switch (count){
		case 0:{
			printf("Send the key first!\n");
			//transmit the key
			iResult = send(ConnectSocket, key, AES_BLOCK_SIZE, 0);
			if (iResult == SOCKET_ERROR){
				printf("send failed with error: %d\n", WSAGetLastError());
				WSACleanup();
				return 1;
			}
			/*do{
				iDataNum = recv(ConnectSocket, recvbuf, 200, 0);
			} while (iDataNum == 0);*/
			iDataNum = recv(ConnectSocket, recvbuf, 200, 0);
			recvbuf[iDataNum] = '\0';
			printf("Server says: %s\n", recvbuf);
			count++;
			break;
		}
		case 1:{
			//transmit the MD5 of the file
			printf("Send the correct MD5 now!\n");
			iResult = send(ConnectSocket, MDTemp, 32, 0);
			if (iResult == SOCKET_ERROR){
				printf("send failed with error: %d\n", WSAGetLastError());
				WSACleanup();
				return 1;
			}
			/*do{
				iDataNum = recv(ConnectSocket, recvbuf, 200, 0);
			} while (iDataNum == 0);*/
			iDataNum = recv(ConnectSocket, recvbuf, 200, 0);
			recvbuf[iDataNum] = '\0';
			printf("Server says: %s\n", recvbuf);
			count++;
			break;
		}
		case 2:{
			//transmit the encrypted file
			printf("Send the encrypted file now!\n");
			iResult = send(ConnectSocket, dstStringTemp, (int)strlen(dstStringTemp), 0);
			if (iResult == SOCKET_ERROR){
				printf("send failed with error: %d\n", WSAGetLastError());
				WSACleanup();
				return 1;
			}
			fclose(fp);
			count++;
			break;
		}
		default:{
			break;
		}
		}
	}

	// shutdown the connection for sending since no more data will be sent
	// the client can still use the ConnectSocket for receiving data
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR){
		printf("shutdown failed: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	iDataNum = recv(ConnectSocket, recvbuf, 200, 0);
	recvbuf[iDataNum] = '\0';
	printf("Server says: %s\n", recvbuf);
	printf("File transfer completed!\n");

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}