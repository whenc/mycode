#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define BUFFER_SIZE 65535
//#define IO_RCVALL_WSAIOW(IOC_VENDOR,1)

typedef struct _IP_HEADER{
	union{
		char version;
		char hdrLen;
	}first;	
	char serviceType;
	short totalLen;
	short id;
	union{
		char flags;
		short fragOff;
	}second;
	char timeToLive;
	char protocol;
	short hdrChksum;
	int sourceAddr;
	int destAddr;
	int option;
}IP_HEADER; 

// analyze packet
void getVersion(char c, char &version){
	version = c>>4; 
}

void getHdrLen(char c, char &result){
	result = (c&0x0f)*4;
}

const char *parseServiceType_getProcedence(char c){
	switch(c >> 5){
		case 7:
			return "Network Control";	
			break;
		case 6:
			return "Intrnetwork Control";	
			break;
		case 5:
			return "CRIYIC/ECP";	
			break;
		case 4:
			return "Flash Override";
			break;
		case 3:
			return "Flash";
			break;
		case 2:
			return "Immediate";
			break;
		case 1:
			return "Priority";
			break;
		case 0:
			return "Routine";
			break;
		default:
			return "Unknown";
			break;
	}
} 

const char *parseServiceType_getTOS(char b){
	b = (b>>1)&0x0f;
	switch(b){
		case 0:
			return "Normal service";
			break;
		case 1:
			return "Minimize monetary cost";
			break;
		case 2:
			return "Maximize reliability";
			break;
		case 4:
			return "Maximize throughout";
			break;
		case 8:
			return "Minimize delay";
			break;
		case 15:
			return "Maximize security";
			break;
		default:
			return "Unknown";
			break; 
	}
	
}

void getFlags(int w, char &DF, char &MF){
	DF = (w>>14)&0x01;
	MF = (w>>13)&0x01;
}

void getFragOff(int w, int &fragOff){
	fragOff = w&0x1fff;
}

const char *getProtocol(char c){
	switch(c){
		case 1:
			return "ICMP";
			break;
		case 2:
			return "IGMP";
			break;
		case 4: 
			return "IP in IP";
			break;
		case 6:
			return "TCP";
			break;
		case 8:
			return "EGP";
			break;
		case 17:
			return "UDP";
			break;
		case 41:
			return "IPV6";
			break;
		case 46:
			return "RSVP";
			break;
		case 89: 
			return "OSPF";
			break;
		default:
			return "Unknown";
			break;
	}
}


void ipparse(FILE *file, char *buffer){
	IP_HEADER ip = *(IP_HEADER*)buffer; // ?
	fseek(file, 0, SEEK_END); //?
	
	// analyze version
	char version;
	getVersion(ip.first.version, version);
	fprintf(file, "版本 = %d\r\n", version);
	
	// analyze header length
	char hdrLen;
	getHdrLen(ip.first.hdrLen, hdrLen);
	fprintf(file, "首部长度 = %d(byte)\r\n", hdrLen);
	
	// analyze serviceType
	fprintf(file, "服务类型 = %s,%s\r\n",parseServiceType_getProcedence(ip.serviceType),
		parseServiceType_getTOS(ip.serviceType));
	
	// analyze the length of datagram
	fprintf(file, "总长度 = %d(byte)\r\n", ip.totalLen);
	
	// analyze datagram id
	fprintf(file, "标识 = %d\r\n", ip.id); 
	
	// analyze the flags
	char DF;
	char MF;
	getFlags(ip.second.flags, DF ,MF);
	fprintf(file, "标志：DF = %d，MF = %d\r\n", DF, MF);
	
	// analyze fragment offset
	fprintf(file, "片位移 = %d\r\n", ip.second.fragOff);
	
	//analyse time to live
	fprintf(file, "生存周期 = %d\r\n", ip.timeToLive);
	
	//analyse protocol 
		
	fprintf(file, "协议 = %s\r\n", getProtocol(ip.protocol));
	 
	// analyze cheksum
	fprintf(file, "头部检验和 = 0x%0d\r\n", ip.hdrChksum);
	
	fprintf(file, "源IP地址 = %s\r\n", inet_ntoa(*(in_addr*)&ip.sourceAddr));
	
	fprintf(file, "目的IP地址 = %s\r\n\n\n",inet_ntoa(*(in_addr*)&ip.destAddr));
}

int main(int argc, char *argv[]){
	if(argc != 2){
		printf("usage error!\n");
		return -1;
	} 
	
	FILE *file;
	if((file = fopen(argv[1], "w+")) == NULL){
		printf("failed to open file %s!", argv[1]);
		return -1;
	}
	
	// initial WSA
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		printf("WSAStartup failed with error:%d\n", WSAGetLastError());
		return -1;
	}
	
	// create raw socket
	SOCKET sock;
	if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == 
	INVALID_SOCKET){
		printf("create sock failed with error:%d\n", WSAGetLastError());
		WSACleanup();
		return -1;		
	}
	
//	bool flag=true; 
//	//设置IP头操作，其中flag设置为ture，用户可以亲自对头进行处理
//	if(setsockopt(sock, IPPROTO_IP,IP_HDRINCL,(char*)&flag,sizeof(flag)) == SOCKET_ERROR){
//		printf("setsocketopt failed with error:%d\n", WSAGetLastError());
//		closesocket(sock);
//		WSACleanup();
//		return -1;
//	} 
	
	// 获取主机名
	char hostName[128];
	if(gethostname(hostName,100) == SOCKET_ERROR){
		printf("gethostname failed with error:%d!\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();		
		return -1;
	}
	
	//获取本地IP地址
	hostent *pHostIP;
	if((pHostIP = gethostbyname(hostName)) == NULL){
		printf("gethostbyname failed with error:%d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();		
		return -1; 
	} 
	
	// sockaddr_in
	sockaddr_in addr_in;
	addr_in.sin_addr = *(in_addr*)pHostIP->h_addr_list[0];
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(6000);
	
	// bind the raw socket
	if(bind(sock, (PSOCKADDR)&addr_in, sizeof(addr_in)) == SOCKET_ERROR){
		printf("bind the socket failed with error:%d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup(); 
		return -1;
	}
	
	DWORD dwBufferLen[10];
	DWORD Optval = 1;
	DWORD dwBytesReturned = 0;
	int iResult;
	if((iResult = WSAIoctl(sock, SIO_RCVALL, &Optval, sizeof(Optval), &dwBufferLen,
		sizeof(dwBufferLen), &dwBytesReturned, NULL, NULL)) == SOCKET_ERROR){
		printf("WSAIoctl failed with error:%d", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return -1;	
	}
	
	
	char buffer[BUFFER_SIZE];
	
	// all settings has been done
	// it is time to begin
	printf("begin receive datagram and analyze it...\n");
	while(true){
		printf("receive datagram...\n");
		int size = recv(sock, buffer, BUFFER_SIZE, 0);
		printf("analyze it...\n");
		if(size > 0){
			ipparse(stdout, buffer);
			ipparse(file, buffer);
		}
	}
	
	fclose(file);
	return 0;
}




