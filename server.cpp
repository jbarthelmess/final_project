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

int handshake(User& user) {
    int comm_sock, msg_sock, thread_w, check;
    char buf[4095];
    char msg[1024];
    user.get_contact_info(comm_sock, msg_sock, thread_w);
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

int fillcode(std::string code, char* msg, int start) {
    if(!code.compare("DES")) {
        uint64_t item = rand();
        strcpy(&msg[start], "DES");
        memcpy(&msg[start+3], &item, 8);
        return start+11;
    }
    else {
        uint64_t N2, e2, d2;
        RSA_key_maker(N2, e2, d2);
        uint32_t N, e, d;
        N = N2;
        e = e2;
        d = d2;
        strcpy(&msg[start], code.c_str());
        memcpy(&msg[start+3], &N, 4);
        memcpy(&msg[start+7], &e, 4);
        memcpy(&msg[start+11], &d, 4);
        return start+15; 
    }
}
/* user access options
0 - remove comm opt
1 - set new top option
2 - get user data
3 - get names
4 - logoff
5 - create new user/ login
*/

int user_access(std::string username, int code, char* buf, User* other, std::vector<std::string>& names) {
    if(code > 5 || code < 0) {
        return -1;
    }
    User holder;
    pthread_mutex_lock(&mutex);
    int ret_code = 0;
    if(code == 0) {
        created[username].remove_comm_opt(buf);
    }
    if(code == 1) {
        created[username].set_preference(std::string(buf));
    }
    if(code == 2) {
        holder = created[username];
        *other = holder;
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
    	other->set_password(buf, 20);
    	other->set_username(username);
        if(!created.count(username)) {
            created[username] = *other;
        }
        else {
        	char pass[21];
        	int len;
        	created[username].get_password(pass, len);
            if(memcmp(pass, buf, 20)) {
                ret_code = -1;
            }
        }
    }
    pthread_mutex_unlock(&mutex);
    return ret_code;
}

void* handle_client(void* arg) {
    User user = *(static_cast<User*>(arg));
    int check = handshake(user);
    int max;
    char buf[4096];
    char msg[4096];
    int comm_sock, msg_sock, thread_pipe_write, thread_pipe_read;
    char* token;
    struct sockaddr_in msg_sock_info;
    int err;
    unsigned short msg_port;
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
                    write(other_thr, "ACK", 3);
                    err = sprintf(msg, "CONNECT %s %s", other.get_username().c_str(), token);
                    memcpy(&msg[err+1], &key, 8);
                    e_and_send(msg, err+9, user.get_preference(), user, comm_sock, NULL);
                }
                else {
                    uint64_t N2, e2, d2;
                    RSA_key_maker(N2, e2, d2);
                    uint32_t N, e, d;
                    N = N2;
                    e = e2;
                    d = d2;
                    other.set_rsa_recv(N, d);
                    other.set_sem_recv(N, d);
                    int saving = sprintf(msg, "CONNECT %s %s",other.get_username().c_str(), token);
                    memcpy(&msg[saving+1], &N, 4);
                    memcpy(&msg[saving+5], &e, 4);
                    write(other_thr, msg, saving+9);
                    memcpy(&N, &buf[err-8], 4);
                    memcpy(&e, &buf[err-4], 4);
                    other.set_rsa_send(N, e);
                    other.set_sem_send(N, e);
                    other.set_preference(std::string(token));
                    memcpy(&msg[saving+9], &N, 4);
                    memcpy(&msg[saving+13], &d, 4);
                    e_and_send(msg, saving+17, user.get_preference(), user, comm_sock, NULL);
                }
                conn[other.get_username()] = other;
            }
            else {
                token = strtok(NULL, " ");
                conn.erase(std::string(token));
            }
        }
        if(!FD_ISSET(comm_sock, &reading)) continue;
        check = recv(comm_sock, buf, 4095, 0);
        d_and_check(buf, check, msg, user.get_preference(), user);
        token = strtok(msg, " ");
        if(!strcmp(token, "LOGIN")) {
            token = strtok(NULL, " ");
            std::string id(token);
            char hash[20];
            memcpy(hash, &buf[id.length() + 7], 20);
            check = user_access(id, 5, hash, &user, names);
            if(check == 0) {
            	std::cout << "USER SUCCESSFULLY LOGGED IN" << std::endl;
                user.set_username(id);
                user.set_password(hash, 20);
                err = sprintf(buf, "SUC");
                e_and_send(buf, 3, "DES", user, comm_sock, NULL);
                user.get_connect_info(&msg_sock_info);
                err = recv(comm_sock, buf, 4095, 0);
                d_and_check(buf, err, msg, user.get_preference(), user);
                memcpy(&msg_sock_info.sin_port, msg, 2);
                msg_sock = socket(AF_INET, SOCK_STREAM, 0);
                if(connect(msg_sock, (struct sockaddr*) &msg_sock_info, sizeof(struct sockaddr_in))) {
                	sprintf(buf, "ERROR");
                	e_and_send(buf, 5, user.get_preference(), user, comm_sock, NULL);
                	perror("connect");
                	close(comm_sock);
                	close(thread_pipe_read);
                	close(thread_pipe_write);
                	return NULL;
                }
                
            }
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
            	strcpy(buf, "FAIL");
                e_and_send(buf, 4, user.get_preference(), user, comm_sock, NULL);
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
            	strcpy(buf, "FAIL");
                e_and_send(buf, 4, user.get_preference(), user, comm_sock, NULL);
                continue;
            }
            
            if(code.compare("DES")) {
                uint32_t d, N;
                memcpy(&d, &msg[err-4], 4);
                err-=4;
                buf[err] = '\0';
                memcpy(&N, &msg[err-8], 4);
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
                memcpy(&key, &msg[err-8], 8);
                other.set_des(key);
                other.set_preference("DES");
            }
            
            err = send(other_pipe, msg, err, 0);
            err = read(thread_pipe_read, buf, 1024);
            if(!code.compare("DES")) {
            	err = sprintf(msg, "SUC");
            	e_and_send(msg, err, user.get_preference(), user, comm_sock, NULL);
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
                err = sprintf(msg, "SUC");
                memcpy(&msg[3], &N, 4);
                memcpy(&msg[7], &e, 4);
                e_and_send(msg, 11, user.get_preference(), user, comm_sock, NULL);
            }
            conn[other.get_username()] = other;
        }
        else if(!strcmp(token, "DISCONNECT")) {
            token = strtok(NULL, " ");
            err = sprintf(msg, "DISCONNECT %s", user.get_username().c_str());
            int dummy1, dummy2, dummy3;
            other = conn[std::string(token)];
            other.get_contact_info(dummy1, dummy2, dummy3);
            send(dummy3, msg, err, 0);
            conn.erase(token);
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
                	int dummy, dummy2, dummy3;
                	(it->second).get_contact_info(dummy, dummy2, dummy3);
                    send(dummy3, msg, err, 0);
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
            int dummy, dummy2, dummy3;
            other.get_contact_info(dummy, dummy2, dummy3);
            err = sprintf(msg, "MSG %s", user.get_username().c_str());
            memcpy(&msg[err+1], &buf[strlen(token)+5], check - strlen(token) +5);
            e_and_send(msg, check, other.get_preference(), other, dummy2, NULL);
        }
        else if(!strcmp(token, "LOGOFF")) {
            err = sprintf(msg, "DISCONNECT %s", user.get_username().c_str());
            for(auto it = conn.begin(); it != conn.end(); it++) {
            	int sock1, dummy, dummy2;
            	(it->second).get_contact_info(sock1, dummy, dummy2);
            	send(dummy2, msg, err, 0);
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
            uint32_t size = names.size();
            memcpy(message, &size, 4);
            message[4] = '\0';
            for(int i = 0; i < names.size(); i++) {
                strcat(&message[used+4], names[i].c_str());
                used+= names[i].size();
                strcat(&message[used+4], " ");
                used+=1;
            }
            message[used-1] = '\0';
            e_and_send(message, used, user.get_preference(), user, comm_sock, NULL);
            delete [] message;
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    // get local folder for writing file
    srand(8675309*time(NULL));
    pthread_mutex_init(&mutex, NULL);
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
