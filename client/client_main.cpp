#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")

#include <iostream>
#include <string>
#include <WinSock2.h>

#define BUFFER_SIZE 1024*16

int main(int argc, char** argv) {
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	WSAStartup(versionWanted, &wsaData);

	int sock;
	sockaddr_in server_addr, client_addr;
	int port = 12314;
	char buffer[BUFFER_SIZE];
	int retv;

	memset(&server_addr, NULL, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	while (true) {
		std::cin >> buffer;
		retv = sendto(sock, buffer, sizeof(buffer), 0, (sockaddr*)&server_addr, sizeof(server_addr));
		std::cout << retv << " Bytes sent" << std::endl;

		int addr_len = sizeof(client_addr);
		retv = recvfrom(sock, buffer, BUFFER_SIZE, 0, (sockaddr*)&client_addr, (int*)&addr_len);
		buffer[retv + 1] = NULL;
		std::cout << "[UDP/" << inet_ntoa(client_addr.sin_addr) << ":"
			<< ntohs(client_addr.sin_port) << "] " << buffer << std::endl;
	}

	closesocket(sock);

	return 0;
}