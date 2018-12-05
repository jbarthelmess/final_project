#include<arpa/inet.h> // inet_pton
#include<cstdint> // int32_t uint64_t
#include<unordered_map>
#include<iostream> // std::cout
#include<string> // std::string,
#include<cstring> // strrchr, other functions to deal with char arrays
#include<cstdio> // sprintf, 
#include<unistd.h> // read, readlink
#include<sys/socket.h> // socket, bind, connect
#include<sys/select.h> // select
#include<sys/time.h> // time, time struct
#include<sys/types.h> // size_t, 
#include<fcntl.h> 
#include<termios.h> 
#include<netdb.h>
#include<ifaddrs.h>
#include "Crypto.h"
#include "User.h"

void get_address(struct sockaddr_in* finder ) {
	struct ifaddrs *ifmain, *ifa;
	getifaddrs(&ifmain);
	struct sockaddr_in* temp;
	for(ifa = ifmain; ifa != NULL; ifa = ifa->ifa_next) {
		if(ifa->ifa_addr == NULL) continue;
		if(ifa->ifa_addr->sa_family != AF_INET) continue;
		if(strcmp(ifa->ifa_name, "lo")) {
			temp = (struct sockaddr_in *) &(ifa->ifa_addr);
			*finder = *temp;
			break;
		}
	}
	freeifaddrs(ifmain);
}

int handshake(User& user) {
    char buf[4096];
    char msg[1024];
    int err_check;
    bool suc_check;
    uint64_t e2, d2, N2;
    uint32_t e, d, N, g;
    int comm_sock, msg_sock, thread_write;
    user.get_contact_info(comm_sock, msg_sock, thread_write);
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

void clean_in(char* buf, int* len) {
    if(*len < 0) {
        perror("read");
    }
    else if(*len > 0 && buf[(*len) -1] == '\n') {
        buf[(*len)-1] = '\0';
        (*len)--;
    }
    else
        buf[*len] = '\0';
}

void print_user_check_error(int code) {
    if(code == -1) {
        std::cout << "Input was too short, please try again.";
    }
    else if(code == -2) {
        std::cout << "Input was too long, please try again.";
    }
    else {
        std::cout << "Input contained an illegal character. Please try again without using control characters, or the characters (\"), ('), (|), (/), (\\), (`), (}), ({), (~).";
    }
}

int user_check(char* username) {
    int i;
    int len = strlen(username);
    if(len < 8) {
        return -1;
    }
    else if(len > 32) {
        return -2;
    }
    for(i = 0; i < len; i++) {
        if(!isgraph(username[i])) // eliminate control characters
            return -3;
        if(username[i] == 34 || username[i] == 39 || username[i] == 47 || username[i] == 92 || username[i] == 96 || username[i] > 122) { // eliminate ("), ('), (|), (/), (\), (`), (}), ({), (~) 
            return -3;
        }
    }
    return 0;
}

void create_new_user_data(std::string& username, std::string& password) {
    char buf[256];
    int len = 0;
    int check;
    while(len == 0) {
        std::cout << "Create a username. It should be between 8 and 32 characters long, and contain only printable ascii characters." << std::endl;
        std::cout << "Username: ";
        fflush(stdout);
        len = read(0, buf, 256);
        fflush(stdin);
        clean_in(buf, &len);
        check = user_check(buf);
        if(check < 0) {
            std::cout << std::endl;
            print_user_check_error(check);
            std::cout << std::endl;
            len = 0;
        }
    }
    username = std::string(buf);
    len = 0;
    struct termios oldt, newt;
    tcgetattr(0, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(0, TCSANOW, &newt);
    while(len == 0) {
        std::cout << "Create a password. It should be between 8 and 32 characters long, and contain only printable ascii characters." << std::endl;
        std::cout << "Password: ";
        fflush(stdout);
        len = read(0, buf, 256);
        fflush(stdin);
        clean_in(buf, &len);
        check = user_check(buf);
        if(check < 0) {
            std::cout << std::endl;
            print_user_check_error(check);
            std::cout << std::endl;
            len = 0;
            continue;
        }
        password = std::string(buf);
        std::cout << std::endl;
        std::cout << "Please reenter your password to confirm it is correct." << std::endl;
        std::cout << "Reenter Password: ";
        fflush(stdout);
        len = read(0, buf, 256);
        fflush(stdin);
        clean_in(buf, &len);
        check = password.compare(buf);
        std::cout << std::endl;
        if(check != 0) {
            std::cout << "Passwords did not match, please reenter a password." << std::endl;
            len =0;
        }
    }
    tcsetattr(0, TCSANOW, &oldt);
}

int getusername(char* buf, int b_size, std::string& user) {
    int len = 0;
    int code;
    while(len == 0) { // get username
        std::cout << "Enter your username(just hit enter if you are a first time user):";
        fflush(stdout);
        len = read(0, buf, b_size);
        fflush(stdin);
        if(len == 0) {
            exit(1);
        }
        clean_in(buf, &len);
        if(len == 0) { // new user, need to shift to separate protocol
            return 0;
        }
        else { 
            code = user_check(buf);
            if(code < 0) {
                std::cout << std::endl;
                print_user_check_error(code);
                std::cout << std::endl;
                len = 0;
            }
        }
    }
    user = std::string(buf);
    return 1;
}

void getpassword(char* place, int p_size, std::string& pass) {
    int len = 0;
    int code;
    struct termios oldt, newt;
    tcgetattr(0, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(0, TCSANOW, &newt);
    while(len ==0 || len == p_size) {
        std::cout << "Enter password:";
        fflush(stdout);
        len = read(0, place, p_size);
        fflush(stdin);
        if(len >= 0) {
            clean_in(place, &len);
            code = user_check(place);
            if(code < 0) {
                std::cout << std::endl;
                print_user_check_error(code);
                std::cout << std::endl;
                len = 0;
            } 
            else {
                place[len] = '\0';
            }
        }
    }
    tcsetattr(0, TCSANOW, &oldt);
    pass = std::string(place);
    std::cout << std::endl;
}

int who(int sock, User& user) {
    char buf[4096];
    char decrypt[4096];
    char left[4096];
    char* token;
    char* next;
    int byte_count, num_users;
    
    byte_count = recv(sock, buf, 4095, 0);
    byte_count = d_and_check(buf, byte_count, decrypt, user.get_preference(), user);
    decrypt[byte_count] = '\0';
    if(byte_count < 0) {
        return -1;
    }
    memcpy(&num_users, buf, 4);
    std::cout << "There are currently " << num_users << " users online." << std::endl;
    token = strtok(&buf[4], " ");
    next = strtok(NULL, " ");
    people_print:
    while(next != NULL) {
        std::cout << "* " << token << std::endl;
        token = next;
        next = strtok(NULL, " ");
    }
    return 0;
}

int main(int argc, char** argv) {
    if(argc != 3) {
        std::cout << "USAGE: ./client.exe <SERV_IP_ADDRESS> <SERV_PORT>" << std::endl;
        return 1;
    }
    srand(525600*time(NULL));
    int err_check;
    char buf[4096];
    char msg[4096];
    char encrypt[4096];
    User user;
    int msg_sock;
    int comm_sock;
    int thread_pipe;
    // connect to server
    socklen_t conn_len, msg_conn_len, holder_len;
    unsigned short port = atoi(argv[2]);
    struct sockaddr_in conn;
    struct sockaddr_in msg_conn;
    struct sockaddr_in holder;
    memset(&conn, 0, sizeof(struct sockaddr_in));
    memset(&msg_conn, 0, sizeof(struct sockaddr_in));
    memset(&holder, 0, sizeof(struct sockaddr_in));
    conn_len = sizeof(conn);
    msg_conn_len = sizeof(msg_conn);
    holder_len = sizeof(holder);
    conn.sin_port = htons(port);
    conn.sin_family = AF_INET;
    err_check = inet_pton(AF_INET, argv[1], &conn.sin_addr);
    if(err_check <= 0) {
        if(err_check == 0)
            std::cerr << "Not a valid IPv4 address." << std::endl;
        else
            perror("inet_pton");
        return 1;
    }
    comm_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(comm_sock < 0) {
        perror("socket");
        return 1;
    }
    if(connect(comm_sock, (struct sockaddr*) &conn, conn_len) < 0) {
        perror("connect");
        return 1;
    }
    user.set_comm(comm_sock);
    std::string username;
    std::string password;
    std::unordered_map<std::string, User> connected;
    err_check = handshake(user);
    if(!err_check) {
        std::cerr << "Something went wrong in the handshake. Shutting down..." << std::endl;
        return 1;
    }
    bool logged_in = false;
    bool new_user = false;
    uint32_t MAC[5];
    while(!logged_in) {
        err_check = getusername(buf, 2048, username);
        if(!err_check) { // new user
            create_new_user_data(username, password);
            new_user = true;
        }
        else {
            getpassword(buf, 2048, password);
        }
        strcpy(buf, username.c_str());
        strcat(buf, password.c_str());
        SHA_1(buf,username.length() + password.length(), MAC);
        strcpy(msg, "LOGIN ");
        strcat(msg, username.c_str());
        memcpy(&msg[username.length() + 7], MAC, 20);
        e_and_send(msg, 27+username.length(), "DES", user, comm_sock, NULL);
        err_check = recv(comm_sock, buf, 64, 0);
        err_check = d_and_check(buf, err_check, msg, "DES", user);
        if(err_check == -1) {
        	std::cout << "something went wrong" << std::endl;
        }
        msg[err_check] = '\0';
        if(!strcmp(msg, "SUC")) {
        	std::cout<< "LOGIN successful, setting up with server" <<std::endl;
        	int listener = socket(AF_INET, SOCK_STREAM, 0);
        	get_address(&holder);
        	msg_conn.sin_family = AF_INET;
        	msg_conn.sin_port = htons(0);
        	msg_conn.sin_addr.s_addr = htonl(INADDR_ANY);
        	if(bind(listener, (struct sockaddr* ) &msg_conn, msg_conn_len) == -1) {
        		perror("bind");
        		exit(1);
        	}
        	if(getsockname(listener, (struct sockaddr*) &msg_conn, &msg_conn_len) == -1) {
        		perror("getsockname");
        		exit(1);
        	}
        	if(listen(listener, 1) == -1) {
        		perror("listen");
        		exit(1);
        	}
        	memcpy(buf, &msg_conn.sin_port, 2);
        	e_and_send(buf, 2, "DES", user, comm_sock, NULL);
        	msg_sock = accept(listener, (struct sockaddr*) &msg_conn, &msg_conn_len);
        	close(listener);
        	user.set_msg(msg_sock);
        	logged_in = true;
        }
        else {
        //WE DON'T GET HERE. SERVER MUST NEVER RESPOND IF IT'S INCORRECT PASSWORD. AND POSSIBLY 
        //EVEN IF CORRECT PASSWORD
        	std::cout << "Login failed, username may be taken, or incorrect password provided." << std::endl;
        }
    }
    User other;
    /*LOGIN procedure*/
    std::cout << "You are now logged in!" << std::endl;
    /*Create message socket*/
    fd_set reading;
    int max;
    if(msg_sock > comm_sock)
        max = msg_sock;
    else 
        max = comm_sock;
    max = max+1;
    char* token;
    while(1) {
        FD_ZERO(&reading);
        FD_SET(comm_sock, &reading);
        FD_SET(msg_sock, &reading);
        FD_SET(0, &reading);
        
        int check = select(max, &reading, NULL, NULL, NULL);
        if(FD_ISSET(msg_sock, &reading)) {
            check = recv(msg_sock, buf, 1024,0);
            err_check = d_and_check(buf, check, msg, user.get_preference(), user);
            token = strtok(msg, " ");
            if(!strcmp(token, "MSG")) {
            	token = strtok(NULL, " ");
            	other = connected[std::string(token)];
		        err_check = d_and_check(&msg[4+strlen(token)], check - 4 - strlen(token), buf, other.get_preference(), other);
		        if(err_check != -1) {
				    std::cout << other.get_username() << ": ";
				    write(1, buf, err_check);
				    std::cout << std::endl;
		        }
            }
        }
        if(FD_ISSET(comm_sock, &reading)) {
            check = recv(comm_sock, buf, 1024, 0);
            check = d_and_check(buf, check, msg, user.get_preference(), user);
            token = strtok(msg, " ");
            if(!strcmp(token, "CONNECT")) {
                token = strtok(NULL, " ");
                other.set_username(std::string(token));
                token = strtok(NULL, " ");
                other.set_preference(std::string(token));
                uint64_t key;
                uint32_t N, e, d;
                if(!strcmp(token, "DES")) {
                	memcpy(&key, &msg[check-8], 8);
                	other.set_des(key);
                }
                else {
                	memcpy(&N, &msg[check-16], 4);
                	memcpy(&d, &msg[check-4], 4);
                	other.set_rsa_recv(N, d);
                	other.set_sem_recv(N, d);
                	memcpy(&d, &msg[check-8], 4);
                	memcpy(&N, &msg[check-12], 4);
                	other.set_rsa_send(N, e);
                	other.set_sem_send(N, e);
                }
                connected[username] = other;
            }
            else if(!strcmp(token, "DISCONNECT")) {
                token = strtok(NULL, " ");
                if(connected.count(std::string(token))) {
                    connected.erase(std::string(token));
                    std::cout << std::string(token) << " disconnected." << std::endl;
                }
            }
        }
        if(FD_ISSET(0, &reading)) {
            check = read(0, buf, 2047);
            clean_in(buf, &check);
            token = strtok(buf, " ");
            if(strcmp(token, "MSG")==0) {
            	if(check > 1000) {
            		std::cout << "MSG is too long, please use a maximum of 1000 characters" << std::endl;
            		continue;
            	}
                token = strtok(NULL, " ");
                if(connected.count(std::string(token))) {
                    other = connected[std::string(token)];
                    int dummy, dummy2, dummy3;
                    other.get_contact_info(dummy, dummy2, dummy3);
                    err_check = e_and_send(&buf[5+strlen(token)], check - (5+strlen(token)), other.get_preference(), other, dummy2, encrypt);
                    strcpy(msg, "MSG ");
                    strcat(msg, token);
                    memcpy(&msg[5+strlen(token)], encrypt, check - (5+strlen(token)));
                    e_and_send(msg, 5+strlen(token) + err_check, user.get_preference(), user, dummy2, NULL);
                }
                else {
                	std::cout << "You are not connected to " << token << ", please connect before attempting to send messages." << std::endl;
                }
            }
            else if(strcmp(token, "CONNECT") == 0) {
            	
            }
            
            else if(strcmp(token, "DISCONNECT") == 0) {
                token = strtok(NULL, " ");
                if(connected.count(std::string(token))) {
                    connected.erase(std::string(token));
                    err_check = sprintf(msg, "DISCONNECT %s", token);
                    e_and_send(msg, err_check, user.get_preference(), user, comm_sock, NULL);
                }
            }
            else if(strcmp(token, "LOGOFF") == 0) {
                /* Encrypt buffer and send */
                e_and_send(token, strlen(token), user.get_preference(), user, comm_sock, NULL);
                //heck = send(comm_sock, buf, 6, 0);
                close(msg_sock);
                close(comm_sock);
                //close(thread_pipe);
                return 0;
            }
            else if(strcmp(token, "DISABLE") == 0) {
                token = strtok(NULL, " ");
                err_check = user.remove_comm_opt(std::string(token));
                if(err_check) {
                    auto it = connected.begin();
                    while( it != connected.end()) {
                        if((it->second).get_preference().compare(token)) {
                            it = connected.erase(it);
                        }
                        else
                            it++;
                    }
                }
                err_check = sprintf(buf, "DISABLE %s", token);
                e_and_send(buf, err_check, user.get_preference(), user, comm_sock, NULL);
            }
            else if(strcmp(token, "WHO") == 0) {
                e_and_send(token, 3, user.get_preference(), user, comm_sock, NULL);
                who(comm_sock, user);
            }
            else if(strcmp(token, "SET") == 0) {
                token = strtok(NULL, " ");
                std::string old_pref = user.get_preference();
                err_check = user.set_preference(std::string(token));
                if(!err_check) {
                	std::string new_pref=user.get_preference();
                    err_check = sprintf(msg, "SET %s", new_pref.c_str());
                    //std::cout<<"THE MESSAGE IS: "<<msg<<std::endl;
                    //std::cout<<"OLD_PREF IS: "<<old_pref.c_str()<<std::endl;
                    //std::cout<<"NEW_PREF IS: "<<new_pref.c_str()<<std::endl;
                    e_and_send(msg, err_check, old_pref, user, comm_sock, NULL);
                }
            }
            else if(strcmp(token, "HELP") == 0) {
                std::cout << "COMMAND LIST:" << std::endl;
                std::cout << "MSG[username,msg]: sends a message securely to another user via the server. " << std::endl;
                std::cout << "\tMessage contents will be unreadable by server. Messages can be no longer than 800"<<std::endl;
                std::cout << "CONNECT [username]: connect to another user" << std::endl;
                std::cout << "DISCONNECT [username]: disconnect from another user" << std::endl;
                std::cout << "DISABLE [encrypt option]: Disable and encrytion option from being used" << std::endl;
                std::cout << "WHO: See what other users are online" << std::endl;
                std::cout << "SET [encrypt option]: set an encryption option to be used for communication with server" << std::endl;
                std::cout << "LOGOFF: End session with server" << std::endl;
                std::cout << "HELP: get this menu" << std::endl;
                std::cout << "\nENCRYPTION OPTIONS:" << std::endl;
                std::cout << "DES: Data Encryption Standard (Default)" << std::endl;
                std::cout << "RSA: Rivest-Shamir-Adleman" << std::endl;
                std::cout << "SEM: a semantically secure RSA\n" << std::endl;
            }
            else {
                std::cout << "Invalid command." << std::endl;
            }
        }
    }
    return 0;
}

