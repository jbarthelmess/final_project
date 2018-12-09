#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/select.h>
#include<arpa/inet.h>
#include<cstdlib>
#include<cstdio>
#include "User.h"
#include "Crypto.h"

int recv_handshake(User& user, int comm_sock) {
	int check;
    char buf[4095];
    char msg[1024];
    uint64_t N2, e2, d2;
    RSA_key_maker(N2, e2, d2);
    uint32_t N, e, d, g, other;
    N = N2;
    e = e2;
    d = d2;
    memcpy(buf, &N, 4);
    memcpy(&buf[4], &e, 4);
    user.set_rsa_recv(N2, d2);
    user.set_sem_recv(N2, d2);
    check = send(comm_sock, buf, 8, 0);
    check = recv(comm_sock, buf, 20, 0);
    memcpy(&N, buf, 4);
    memcpy(&e, &buf[4], 4);
    N2 = N;
    e2 = e;
    user.set_rsa_send(N2, e2);
    user.set_sem_send(N2, e2);
    memcpy(&N, &buf[8], 4);
    memcpy(&e, &buf[12], 4);
    memcpy(&g, &buf[16], 4);
    N2 = N;
    e2 = e;
    d = rand()%N;
    other = exp_mod(e, d, N);
    user.set_des(other);
    other = exp_mod(g, d, N);
    memcpy(buf, &other, 4);
    check = send(comm_sock, buf, 4, 0);
    if(check == -1) {
        perror("send");
    }
    return 1;
}

int send_handshake(User& user, int comm_sock) {
    char buf[4096];
    char msg[1024];
    int err_check;
    bool suc_check;
    uint64_t e2, d2, N2;
    uint32_t e, d, N, g;
    
    // exchange crypto info
    // first recieve servers public RSA info
    err_check = recv(comm_sock, buf, 8, 0);
    if(err_check != 8) {
        perror("recv");
        std::cerr << "Server Error "<< err_check << std::endl;
        close(comm_sock);
        exit(1);
    }
    memcpy(&N, buf, 4);
    memcpy(&e, &buf[4], 4);
    user.set_rsa_send(N, e);
    user.set_sem_send(N, e);
    RSA_key_maker(N2, e2, d2);
    N = N2;
    e = e2;
    d = d2;
    user.set_rsa_recv(N2, d2);
    user.set_sem_recv(N2, d2);
    memcpy(buf, &N, 4);
    memcpy(&buf[4], &e, 4);
    g = DH_generator(N2, e2, d2);
    N = N2;
    e = e2;
    d = d2;
    memcpy(&buf[8], &N, 4);
    memcpy(&buf[12], &e, 4);
    memcpy(&buf[16], &g, 4);
    err_check = send(comm_sock, buf, 20, 0);
    err_check = recv(comm_sock, buf, 4, 0);
    if(err_check == -1) {
        perror("recv");
    }
    memcpy(&e, buf, 4);
    e = exp_mod(e, d, N);
    user.set_des(e);
    user.get_rsa_send(N2, e2);
    user.get_rsa_recv(N2, d2);
    return 1;
}

int main() {
	srand(8675309*time(NULL));
	struct sockaddr_in lis;
	struct sockaddr_in con;
	int sock;
	int check;
	int num_bytes;
	char rec[4096];
	char msg[4096];
	socklen_t len;
	fd_set reading;
	char* token;
	bool setup = false;
	User me;
	
	while(1) {
		if(!setup) {
			memset(&lis, 0, sizeof(struct sockaddr_in));
			memset(&con, 0, sizeof(struct sockaddr_in));
			lis.sin_family = AF_INET;
			lis.sin_port = htons(0);
			lis.sin_addr.s_addr = htonl(INADDR_ANY);
			len = sizeof(struct sockaddr_in);
			
			sock = socket(AF_INET, SOCK_STREAM, 0);
			if(sock < 0) {
				perror("socket");
				return 1;
			}
			if(bind(sock, (struct sockaddr*) &lis, len) == -1) {
				perror("bind");
				return 1;
			}
			if(getsockname(sock, (struct sockaddr*) &lis, &len) == -1) {
				perror("getsockname");
				return 1;
			}
			std::cout << "Listening on port " << ntohs(lis.sin_port) << std::endl;
			if(listen(sock, 1)) {
				perror("listen");
				return 1;
			}
			setup = true;
		}
		FD_ZERO(&reading);
		FD_SET(sock, &reading);
		FD_SET(0, &reading);
		check = select(sock+1, &reading, NULL, NULL, NULL);
		if(FD_ISSET(sock, &reading)) { // someone is trying to connect
			check = accept(sock, (struct sockaddr*) &lis, &len);
			close(sock);
			sock = check;
			check = 1;
			srand(8675309*time(NULL));
		}
		else if(FD_ISSET(0, &reading)) { // either a connect request or invalid input
			num_bytes = read(0, rec, 1024);
			token = strtok(rec, " ");
			if(!strcmp(token, "CONNECT")) {
				token = strtok(NULL, " ");
				if((check = inet_pton(AF_INET, token, &con.sin_addr)) != 1) {
					if(!check) {
						std::cerr << "Invalid address format given. Please input only IPv4 addresses" << std::endl;
					}
					else {
						perror("inet_pton");
					}
					continue;
				}
				token = strtok(NULL, " ");
				con.sin_port = htons(atoi(token));
				con.sin_family = AF_INET;
				check = socket(AF_INET, SOCK_STREAM, 0);
				if(check == -1) {
					perror("socket");
					std::cerr << "Something went wrong setting up your socket. Local resources may be limited please try again later" << std::endl;
					continue;
				}
				if(connect(check, (struct sockaddr*) &con, len) == -1) {
					perror("connect");
					std::cerr << "Something went wrong connecting to the remote user. Make sure you entered the information correctly and try again" << std::endl;
					std::cerr << "If you try again and still fail, they may be connected to another user, and unable to connect at this time" << std::endl;
					continue;
				}
				close(sock);
				sock = check;
				check = 0;
			}
			else {
				std::cout << "Invalid command. You must be connected to someone before you can message them, or do anything else." << std::endl;
				std::cout << "CONNECT command format: CONNECT <IP_ADDRESS> <PORT>" << std::endl;
				continue;
			}
		}
		setup = false;
		std::cout << "You have connected to another user! Setting up secure comms..." << std::endl;
		if(check) { // we are server, they connected
			check = recv_handshake(me, sock);
		}
		else {
			check = send_handshake(me, sock);
		}
		uint64_t key;
		uint64_t N, d, e;
		me.get_des(key);
		me.get_rsa_recv(N, d);
		std::cout << "Connection successfully established! Here is our info:" << std::endl;
		std::cout << "Symmetric DES key: " << key << std::endl;
		std::cout << "Recieving RSA Public key info: N = " << N << ", d = " << d << std::endl;
		me.get_rsa_send(N, e);
		std::cout << "Sending RSA Public key info: N = " << N << ", e = " << e << std::endl;
		
		std::cout << "You may now begin sending messages.\n" << std::endl;
		me.set_preference("RSA");
		me.set_preference("SEM");
		me.set_preference("DES");
		while(1) {
			std::cout << "> ";
			fflush(stdout);
			FD_ZERO(&reading);
			FD_SET(sock, &reading);
			FD_SET(0, &reading);
			check = select(sock+1, &reading, NULL, NULL, NULL);
			if(FD_ISSET(sock, &reading)) {
				num_bytes = recv(sock, rec, 2048, 0);
				if(!num_bytes) {
					std::cout << "Partner has ended the connection, returning to front" << std::endl;
					close(sock);
					break;
				}
				check = d_and_check(rec, num_bytes, msg, me.get_preference(), me);
				if(check == -1) {
					std::cerr << "Decryption failed due to inaccurate mac. Closing connection..." << std::endl;
					close(sock);
					break;
				}
				msg[check] = '\0';
				if(msg[check-1] == '\n') {
					msg[check-1] = '\0';
					check -=1;
				}
				
				if(!strncmp(msg, "SET", 3)) {
					token = strtok(msg, " ");
					token = strtok(NULL, " ");
					check = me.set_preference(std::string(token));
					if(check == -1) {
						std::cout << "Partner sent invalid encryption switch "<< token << ", we will continue to use "<< me.get_preference()<<"." << std::endl;
					}
					else {
						std::cout << "Partner switched encryption to " << token << ", we will use that for communications now." << std::endl;
					}
				}
				else {
					std::cout << msg << std::endl;
				}
			}
			if(FD_ISSET(0, &reading)) {
				num_bytes = read(0, rec, 2048);
				if(num_bytes == 2048) {
					std::cout << "Sorry, messages of that length are not supported. Please keep messages under 2048 characters" << std::endl;
					fflush(stdin);
					continue;
				}
				rec[num_bytes] = '\0';
				if(rec[num_bytes-1] == '\n') {
					rec[num_bytes-1] = '\0';
					num_bytes -=1;
				}
				if(!strncmp(rec, "DISCONNECT", 10)) {
					std::cout << "Disconnecting from partner..." << std::endl;
					close(sock);
					break;
				}
				if(!strncmp(rec, "SET", 3)) {
					token = strtok(rec, " ");
					token = strtok(NULL, " ");
					if(!strcmp(token, "RSA") || !strcmp(token, "SEM") || !strcmp(token, "DES")) {
						std::cout << "Sending change command to Partner." << std::endl;
						check = sprintf(msg, "SET %s", token);
						e_and_send(msg, check, me.get_preference(), me, sock, NULL);
						me.set_preference(token);
						std::cout << "Will now use " << me.get_preference() << " for communications now" << std::endl;
					}
					else {
						std::cout << "Invalid encryption type. Please use the codes as follows:" << std::endl;
						std::cout << "RSA - Rivest-Shamir-Adleman Public Key Encryption" << std::endl;
						std::cout << "SEM - A semantically secure reworking of RSA" << std::endl;
						std::cout << "DES - The Data Encryption Standard, a symmetric key exchange" << std::endl;
					}
				}
				else {
					num_bytes = e_and_send(rec, num_bytes, me.get_preference(), me, sock, NULL);
				}
			}
		}
	}
	return 0;
}
