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
#include "Crypto.h"
#include "User.h"

bool e_and_send(char* buf, int num_bytes, std::string code, User& user, int comm_sock) {
    uint32_t N, e;
    uint32_t des;
    char* encrypt;
    int bytes_written;
    uint32_t MAC[5];
    char mac[20];
    SHA_1(std::string(buf), MAC);
    memcpy(mac, MAC, 20);
    
    if(!code.compare("RSA")) {
        user.get_rsa_send(N, e);
        encrypt= new char[num_bytes+20];
        bytes_written = do_RSA_encrypt_decrypt(buf, num_bytes, encrypt, N, e);
        des = do_RSA_encrypt_decrypt(mac, 20, &encrypt[bytes_written], N, e);
        std::cout << "Sending " << bytes_written + des << " bytes of encrypted data." << std::endl;
        bytes_written = send(comm_sock, encrypt, bytes_written+des, 0);
        delete [] encrypt;
        if(bytes_written != -1) {
            return true;
        }
        else 
            return false;
    }
    else if(!code.compare("SEM")) {
        user.get_sem_send(N, e);
        encrypt = new char[3*num_bytes];
        bytes_written = do_SEM_encrypt(buf, num_bytes, encrypt, N, e);
        des = do_SEM_encrypt(mac, 20, &encrypt[bytes_written], N, e);
        bytes_written = send(comm_sock, encrypt, bytes_written+des, 0);
        if(bytes_written != -1) {
            return true;
        }
        else
            return false;
    }
    else if(!code.compare("DES")) {
        user.get_des(des);
        encrypt = new char[num_bytes + 20];
        bytes_written = do_des_encrypt(buf, num_bytes, encrypt, des);
        N = do_des_encrypt(mac, 20, &encrypt[bytes_written], des);
        bytes_written = send(comm_sock, encrypt, bytes_written + N, 0);
        if(bytes_written != -1) {
            return true;
        }
        else 
            return false;
    }
    else
        return false;
}

bool d_and_check(char* buf, int num_bytes, char* msg, std::string code, User& user) {
    uint32_t N, d;
    uint32_t des;
    int bytes_written;
    uint32_t MAC[5];
    char mac[24];
    char* msg_mac;
    memset(mac, 0, 24);
    if(!code.compare("RSA")) {
        user.get_rsa_recv(N, d);
        bytes_written = do_RSA_encrypt_decrypt(buf, num_bytes, msg, N, d);
        msg_mac = &msg[bytes_written - 24];
        SHA_1(std::string(msg, bytes_written-24), MAC);
        memcpy(mac, MAC, 20);
        if(strncmp(mac, msg_mac, 20)) {
            std::cerr << "Something went wrong, shutting down..." << std::endl;
            //close(comm_sock);
            //exit(1);
            return false;
        }
        else
            return true;
    }
    else if(!code.compare("SEM")) {
        user.get_sem_recv(N, d);
        bytes_written = do_SEM_decrypt(buf, num_bytes, msg, N, d);
        msg_mac = &msg[bytes_written-24];
        SHA_1(std::string(msg, bytes_written-24), MAC);
        memcpy(mac, MAC, 20);
        if(strncmp(mac, msg_mac, 20)) {
            std::cerr << "Something went wrong, shutting down..." << std::endl;
            //close(comm_sock);
            //exit(1);
            return false;
        }
        else
            return true;
    }
    else if(!code.compare("DES")) {
        user.get_des(des);
        bytes_written = do_des_decrypt(buf, num_bytes, msg, des);
        msg_mac = &msg[bytes_written-24];
        SHA_1(std::string(msg, bytes_written-24), MAC);
        memcpy(mac, MAC, 20);
        if(strncmp(mac, msg_mac, 20)) {
            std::cerr << "Something went wrong, shutting down..." << std::endl;
            //close(comm_sock);
            //exit(1);
            return false;
        }
        else
            return true;
    }
    return false;
}



int handshake(User& user) {
    char buf[4096];
    char msg[1024];
    int err_check;
    bool suc_check;
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
    RSA_key_maker(N, e, d);
    user.set_rsa_recv(N, d);
    user.set_sem_recv(N, d);
    memcpy(buf, &N, 4);
    memcpy(&buf[4], &e, 4);
    g = DH_generator(N, e, d);
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
    user.get_rsa_send(N, e);
    user.get_rsa_recv(N, d);
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

int getusername(char* buf, int b_size, std::string user) {
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

void getpassword(char* place, int p_size, std::string pass) {
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

int who(int sock) {
    char buf[1024];
    char left[1024];
    char* token;
    char* next;
    int byte_count, num_users;
    /*strcpy(buf, "WHO");
    byte_count = send(sock, buf, 3, 0);
    if(byte_count < 0) {
        return -1;
    }*/
    byte_count = recv(sock, buf, 1023, 0);
    buf[byte_count] = '\0';
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
    if(byte_count == 1023) {
        strcpy(left, next);
        byte_count = recv(sock, buf, 1023,0);
        buf[byte_count] = '\0';
        next = strtok(buf, " ");
        strcat(left, next);
        token = left;
        next = strtok(NULL, " ");
        goto people_print;
    }
    std::cout << "* " << token << std::endl;
    return 0;
}

int main(int argc, char** argv) {
    if(argc != 3) {
        std::cout << "USAGE: ./client.exe <SERV_IP_ADDRESS> <SERV_PORT>" << std::endl;
        return 1;
    }
    srand(525600);
    int err_check;
    char buf[2048];
    char msg[2048];
    User user;
    int msg_sock;
    int comm_sock;
    int thread_pipe;
    // connect to server
    socklen_t conn_len;
    unsigned short port = atoi(argv[2]);
    struct sockaddr_in conn;
    memset(&conn, 0, sizeof(struct sockaddr_in));
    conn_len = sizeof(conn);
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
        if(new_user) {
            strcpy(msg, "LOGIN ");
            strcat(msg, username.c_str());
            e_and_send(msg, 6+username.length(), "DES", user, comm_sock);
        }
        else {
            strcpy(buf, username.c_str());
            strcat(buf, password.c_str());
            SHA_1(std::string(buf), MAC);
            strcpy(msg, "LOGIN ");
            strcat(msg, username.c_str());
            memcpy(&msg[username.length() + 6], MAC, 20);
            e_and_send(msg, 26+username.length(), "DES", user, comm_sock);
        }
        
    }
    User other;
    /*LOGIN procedure*/
    
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
            /* Decrypt and check */
            other = connected[std::string(buf)];
            /* Decrypt message*/
            std::cout << other.get_username() << ": ";
            std::cout << msg <<std::endl;
        }
        if(FD_ISSET(comm_sock, &reading)) {
            check = recv(comm_sock, buf, 1024, 0);
            /* Decrypt and check */
            token = strtok(msg, " ");
            if(!strcmp(token, "CONNECT")) {
                
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
            buf[check] = '\0';
            token = strtok(buf, " ");
            if(!strcmp(token, "MSG")) {
                token = strtok(NULL, " ");
                if(connected.count(std::string(token))) {
                    other = connected[std::string(token)];
                    /* Encrypt buffer */
                    strcpy(msg, "MSG ");
                    strcat(msg, token);
                    memcpy(&msg[5+strlen(token)], &buf[5+strlen(token)], check-strlen(token)-5);
                    /* Encrypt and send*/
                }
            }
            else if(!strcmp(token, "CONNECT")) {
            
            }
            else if(!strcmp(token, "DISCONNECT")) {
                token = strtok(NULL, " ");
                if(connected.count(std::string(token))) {
                    connected.erase(std::string(token));
                    err_check = sprintf(msg, "DISCONNECT %s", token);
                    /* Encrypt and send*/
                }
            }
            else if(!strcmp(token, "LOGOFF")) {
                /* Encrypt buffer and send */
                //heck = send(comm_sock, buf, 6, 0);
                close(msg_sock);
                close(comm_sock);
                close(thread_pipe);
                return 0;
            }
            else if(!strcmp(token, "DISABLE")) {
                /* Encrypt buffer */
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
                /* Encrypt and send */
            }
            else if(!strcmp(token, "WHO")) {
                /* Encrypt and send buffer as is*/
                who(comm_sock);
            }
            else if(!strcmp(token, "SET")) {
                token = strtok(NULL, " ");
                err_check = user.set_preference(std::string(token));
                if(!err_check) {
                    err_check = sprintf(msg, "SET %s", token);
                    /* Encrypt and send*/
                }
            }
            else if(!strcmp(token, "HELP")) {
                std::cout << "COMMAND LIST:" << std::endl;
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



