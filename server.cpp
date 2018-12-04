#include<iostream> // std::cout
#include<string> // std::string,
#include<cstring> // strrchr, other functions to deal with char arrays
#include<cstdio> // sprintf, 
#include<unistd.h> // read, readlink
#include<sys/socket.h> // socket, bind, connect
#include<sys/select.h> // select
#include<sys/time.h> // time, time struct
#include<sys/types.h> // size_t, 
#include<fcntl.h> // open, close
//#include<termios.h> // termios struct, tcgetattr, tcsetattr
#include<sys/stat.h>
#include<arpa/inet.h> // inet_pton
#include<unordered_map> // unordered map
#include<pthread.h> // pthread_library
#include "User.h" // User class
#include "Crypto.h"
#include<cstdint>


// globals to be shared by threads. Mutexed to avoid data corruption
std::unordered_map<std::string, User> created;
pthread_mutex_t mutex;

bool e_and_send(char* buf, int num_bytes, std::string code, User& user) {
    uint32_t N, e;
    uint32_t des;
    int comm_sock, msg_sock, thread_pipe;
    user.get_contact_info(comm_sock, msg_sock, thread_pipe);
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
        bytes_written = send(comm_sock, encrypt, bytes_written+des, 0);
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
    int comm_sock, msg_sock, thread_sock;
    user.get_contact_info(comm_sock, msg_sock, thread_sock);
    uint32_t MAC[5];
    char mac[24];
    char* msg_mac;
    memset(mac, 0, 24);
    if(!code.compare("RSA")) {
        user.get_rsa_recv(N, d);
        bytes_written = do_RSA_encrypt_decrypt(buf, num_bytes, msg, N, d);
        for(int i = 0; i < bytes_written; i++) {
            printf("%d ", msg[i]);
        }
        msg_mac = &msg[bytes_written - 24];
        SHA_1(std::string(msg, bytes_written-24), MAC);
        memcpy(mac, MAC, 20);
        if(strncmp(mac, msg_mac, 20)) {
            std::cerr << "Something went wrong, shutting down..." << std::endl;
            close(comm_sock);
            exit(1);
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
            close(comm_sock);
            exit(1);
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
            close(comm_sock);
            exit(1);
        }
        else
            return true;
    }
    return false;
}

int handshake(User& user) {
    int comm_sock, msg_sock, thread_w, check;
    char buf[4095];
    char msg[1024];
    user.get_contact_info(comm_sock, msg_sock, thread_w);
    uint32_t N, e, d, g, other;
    RSA_key_maker(N, e, d);
    memcpy(buf, &N, 4);
    memcpy(&buf[4], &e, 4);
    user.set_rsa_recv(N, d);
    user.set_sem_recv(N, d);
    check = send(comm_sock, buf, 8, 0);
    check = recv(comm_sock, buf, 20, 0);
    memcpy(&N, buf, 4);
    memcpy(&e, &buf[4], 4);
    user.set_rsa_send(N, e);
    user.set_sem_send(N, e);
    memcpy(&N, &buf[8], 4);
    memcpy(&e, &buf[12], 4);
    memcpy(&g, &buf[16], 4);
    d = rand()%N;
    other = exp_mod(e, d, N);
    user.set_des(other);
    other = exp_mod(g, d, N);
    memcpy(buf, &other, 4);
    check = send(comm_sock, buf, 4, 0);
    if(check == -1) {
        perror("send");
    }
    user.get_rsa_send(N, e);
    user.get_rsa_recv(N, d);
    return 1;
}

int fillcode(std::string code, char* msg, int start) {
    if(!code.compare("DES")) {
        uint64_t item = rand();
        memcpy(&msg[start], &item, 8);
        return start+8;
    }
    else {
        uint32_t N, e, d;
        RSA_key_maker(N, e, d);
        memcpy(&msg[start], &N, 4);
        memcpy(&msg[start+4], &e, 4);
        memcpy(&msg[start+8], &d, 4);
        return start+12; 
    }
}
/* user access options
0 - remove comm opt
1 - set new top option
2 - get user data
3 - get names
4 - logoff
5 - create new user
6 - login
*/

int user_access(std::string username, int code, char* buf, User* other, std::vector<std::string>& names) {
    if(code > 6 || code < 0) {
        return;
    }
    User holder;
    pthread_mutex_lock(mutex);
    int ret_code = 0;
    if(code == 0) {
        created[username].remove_comm_opt(buf);
    }
    if(code == 1) {
        created[username].set_preference(std::string(buf));
    }
    if(code == 2) {
        holder = created[username];
        (*other)(holder);
    }
    if(code == 3) {
        for(auto it = created.begin(); it != created.end(); it++) {
            names.push_back((it->second).get_username());
        }
    }
    if(code == 4) {
        created[username].logout();
    }
    if(code == 5) {
        if(!created.count(username)) {
            created[username] = *other;
        }
        else {
            retcode = -1;
        }
    }
    if(code == 6) {
        if(!created.count(username)) {
            retcode = -1;
        }
        else {
            std::string hash = created[username].get_password();
            if(hash.compare(buf)) {
                retcode = -1;
            }
        }
    }
    pthread_mutex_unlock(mutex);
    return retcode;
}

void* handle_client(void* arg) {
    User user = *(static_cast<User*>(arg));
    int check = handshake(user);
    int max;
    char buf[4096];
    char msg[4096];
    int comm_sock, msg_sock, thread_pipe_write, thread_pipe_read;
    char* token;
    int err;
    User other;
    user.get_contact_info(comm_sock, msg_sock, thread_pipe_write);
    user.get_thread_read(thread_pipe_read);
    if(comm_sock > thread_pipe_read) max = comm_sock;
    else max = thread_pipe_read;
    
    max = max+1;
    std::unordered_map<std::string, User> conn;
    std::vector<std::string> names;
    fd_set reading;
    while(1) {
        FD_ZERO(&reading);
        FD_SET(comm_sock, &reading);
        //FD_SET(msg_sock, &reading);
        FD_SET(thread_pipe_read, &reading);
        
        check = select(max, &reading, NULL, NULL, NULL);
        if(FD_ISSET(thread_pipe_read, &reading)) {
            err = recv(thread_pipe_read, buf, 1024, 0);
            buf[err] = '\0';
            token = strtok(buf, " ");
            if(!strcmp(token, "CONNECT")) {
                token = strtok(NULL, " ");
                other.set_username(std::string(token));
                user_access(other.get_username(), 2, NULL, &other, names);
                int other_comm, other_msg, other_thr;
                other.get_contact_info(other_comm, other_msg, other_thr);
                token = strtok(NULL, " ");
                if(!strcmp(token, "DES")) {
                    uint64_t key;
                    memcpy(&key, &buf[err-8], 8);
                    other.set_des(key);
                    other.set_preference("DES");
                    conn[other.get_username()] = other;
                    write(other_thr, "ACK", 3);
                }
                else {
                    uint32_t N, e, d;
                    RSA_key_maker(N, e, d);
                    other.set_rsa_recv(N, d);
                    other.set_sem_recv(N, d);
                    int saving = sprintf(msg, "CONNECT %s", token);
                    memcpy(&msg[saving], &N, 4);
                    memcpy(&msg[saving+4], &e, 4);
                    write(other_thr, msg, saving+8);
                    memcpy(&N, &buf[err-8], 4);
                    memcpy(&e, &buf[err-4], 4);
                    other.set_rsa_send(N, e);
                    other.set_sem_send(N, e);
                    other.set_preference(std::string(token));
                }
                conn[other.get_username()] = other;
            }
            else {
                token = strtok(NULL, " ");
                conn.erase(token);
            }
        }
        if(!FD_ISSET(comm_sock, &reading)) continue;
        check = recv(comm_sock, buf, 4095, 0);
        /*
            Decryption
        */
        token = strtok(buf, " ");
        if(!strcmp(token, "LOGIN")) {
            
        }
        else if(!(user.get_username().compare(""))) {
            close(comm_sock);
            close(msg_sock);
            close(thread_pipe_read);
            close(thread_pipe_write);
            return NULL;
        }
        if(!strcmp(token, "CONNECT")) {
            token = strtok(NULL, " ");
            if(conn.count(std::string(token))) {
                continue;
            }
            user_access(std::string(token), 2, NULL, &other, names);
            int other_comm, other_msg, other_pipe;
            other.get_contact_info(other_comm, other_msg, other_pipe);
            err = sprintf(msg, "CONNECT %s", user.get_username().c_str());
            msg[err] = '\0';
            std::string o_top = other.get_preference();
            std::string me_top = user.get_preference();
            std::string third; 
            if(!o_top.compare("DES")) {
                if(me_top.compare("RSA"))
                    third = "RSA";
                else
                    third = "SEM";
                    
            }
            else if(!o_top.compare("RSA")) {
                if(me_top.compare("DES"))
                    third = "DES";
                else
                    third = "SEM";
            }
            else {
                if(me_top.compare("DES"))
                    third = "DES";
                else
                    third = "RSA";
            }
            
            std::string code;
            if(user.has_preference(o_top)) {
                code = o_top;
                err = fillcode(o_top, msg, err);
            }
            else if(other.has_preference(me_top)) {
                code = me_top;
                err = fillcode(me_top, msg, err);
            }
            else if(other.has_preference(third) && user.has_preference(third)) {
                code = third;
                err = fillcode(third, msg, err);
            }
            else {
                send(comm_sock, "FAIL", 4, 0);
                continue;
            }
            
            if(code.compare("DES")) {
                uint32_t d, N;
                memcpy(&msg[err-4], &d, 4);
                err-=4;
                buf[err] = '\0';
                memcpy(&msg[err-8], &N, 4);
                if(!code.compare("RSA")) {
                    other.set_rsa_recv(N, d);
                    other.set_preference("RSA");
                }
                else {
                    other.set_sem_recv(N, d);
                    other.set_preference("SEM");
                }
            }
            else {
                uint64_t key;
                memcpy(&msg[err-8], &key, 8);
                other.set_des(key);
                other.set_preference("DES");
            }
            
            /* Encrypt and send on thread pipe*/
            err = read(thread_pipe_read, buf, 1024);
            if(!code.compare("DES")) {
                continue;
            }
            else {
                buf[err] = '\0';
                uint32_t N, e;
                memcpy(&N, &buf[err-8], 4);
                memcpy(&e, &buf[err-4], 4);
                if(!code.compare("RSA")) {
                    other.set_rsa_send(N, e);
                }
                else {
                    other.set_sem_send(N, e);
                }
            }
            conn[other.get_username()] = other;
        }
        else if(!strcmp(token, "DISCONNECT")) {
            token = strtok(NULL, " ");
            conn.erase(token);
            user_access(token, 2, NULL, &other, names);
            err = sprintf(msg, "DISCONNECT %s", user.get_username().c_str());
            /* Encrypt and send */
        }
        else if(!strcmp(token, "DISABLE")) {
            token = strtok(NULL, " ");
            err =user.remove_comm_opt(token);
            if(err) {
                user_access(user.get_username(), 0, token, NULL, names);
            }
            err = sprintf(msg, "DISCONNECT %s", user.get_username().c_str());
            auto it = conn.begin();
            while( it != conn.end()) {
                if(!((it->second).get_preference()).compare(token)) {
                    /* Encrypt and send */
                    it = conn.erase(it);
                }
                else 
                    it++;
            }
        }
        else if(!strcmp(token, "SET")) {
            token = strtok(NULL, " ");
            err = user.set_preference(token);
            if(!err) {
                user_access(user.get_username(), 1, token, NULL, names);
            }
        }
        else if(!strcmp(token, "MSG")) {
            token =strtok(NULL, " ");
            other = conn[std::string(token)];
            err = sprintf(msg, "MSG %s", user.get_username().c_str());
            memcpy(&msg[err], &buf[strlen(token)+5], check - strlen(token) +5);
            /* Encrypt and send*/
        }
        else if(!strcmp(token, "LOGOFF")) {
            err = sprintf(msg, "DISCONNECT %s", user.get_username().c_str());
            for(auto it = conn.begin(); it != conn.end(); it++) {
                /*Encrypt and send */
            }
            user_access(user.get_username(), 4, NULL, NULL, names);
            close(comm_sock);
            close(msg_sock);
            close(thread_pipe_read);
            close(thread_pipe_write);
            return NULL;
        }
        else if(!strcmp(token, "WHO")) {
            user_access(user.get_username(), 3, NULL, NULL, names);
            int total = 0;
            for(int i = 0; i < names.size(); i++) {
                total += names[i].length() + 1;
            }
            char * message = new char[total];
            int used = 0;
            message[0] = '\0';
            for(int i = 0; i < names.size(); i++) {
                strcat(&message[used], names[i].c_str());
                used+= names.size();
                strcat(&message[used], " ");
                used+=1;
            }
            message[used-1] = '\0';
            /*Encrypt and send*/
        }
    }
    return NULL;
    
}

int main(int argc, char** argv) {
    // get local folder for writing file
    srand(8675309);
    pthread_mutex_init(mutex);
    int listener;
    struct sockaddr_in new_conn;
    socklen_t new_conn_len = sizeof(sockaddr_in);
    unsigned short port;
    if(argc >= 2)
        port = atoi(argv[1]);
    else
        port = 3000;
    memset(&new_conn, 0, new_conn_len);
    new_conn.sin_port = htons(port);
    new_conn.sin_family = AF_INET;
    new_conn.sin_addr.s_addr = htonl(INADDR_ANY);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if(listener < 0) {
        perror("socket");
        return 1;
    }
    if(bind(listener, (struct sockaddr*) &new_conn, new_conn_len) == -1) {
        perror("bind");
        return 1;
    }
    if(getsockname(listener, (struct sockaddr*) &new_conn, &new_conn_len) == -1) {
        perror("getsockname");
        return 1;
    }
    port = ntohs(new_conn.sin_port);
    std::cout << port << std::endl;
    if(listen(listener, 5) < 0) {
        perror("listen");
        return 1;
    }
    int new_sock;
    int dummy = 0;
    pthread_t tid;
    while(1) { // loop listening for connections
        User* user = new User();
        new_sock = accept(listener, (struct sockaddr*) &new_conn, &new_conn_len);
        user->bring_online(new_sock, dummy, new_conn);
        pthread_create(&tid, NULL, handle_client, (void*) user);
        pthread_detach(tid);
    }
    
    return 0;
}
