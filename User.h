#ifndef _USER_H_
#define _USER_H_

#include<list>
#include<string>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#include<cstdint>
#include<ctime>
#include<vector>
#include<cstring>

class User {
    public:
    User();
    User(std::string name);
    User(const User& old);
    
    bool is_secure() { return secure;}
    bool is_online() { return online;}
    bool set_secure() {if(time(NULL) - last_online < 604800) secure = true; return secure;}
    bool make_secure(std::vector<uint64_t>& sec);
    int set_preference(std::string top);
    int remove_comm_opt(std::string ban);
    void reset_comm_preferences();
    void bring_online(int comm, int msg, struct sockaddr_in info);
    void set_username(std::string name) {username = name;}
    void set_password(char* pass, int len);
    void set_rsa_recv(uint64_t new_n, uint64_t new_d) { rsa_recv_n = new_n; rsa_d = new_d;}
    void set_rsa_send(uint64_t new_n, uint64_t new_e) { rsa_send_n = new_n; rsa_e = new_e;}
    void set_des(uint64_t new_des) { des = new_des;}
    void set_sem_recv(uint64_t new_n, uint64_t new_d) { sem_recv_n = new_n; sem_d = new_d;}
    void set_sem_send(uint64_t new_n, uint64_t new_e) { sem_send_n = new_n; sem_e = new_e;}
    void set_time(time_t now) {last_online = now;}
    time_t get_last_online() {return last_online;}
    void set_pipe(int p_w, int p_r) {thread_pipe_w = p_w; thread_pipe_r = p_r;}
    void set_comm(int comm) {comm_sock = comm;}
    void set_msg(int msg) {msg_sock = msg;}
    void logout();
    void get_contact_info(int& comm, int& msg, int& pipe) {comm = comm_sock; msg = msg_sock; pipe = thread_pipe_w;}
    void get_rsa_send(uint64_t& N, uint64_t& e) {N = rsa_send_n; e = rsa_e;}
    void get_sem_send(uint64_t& N, uint64_t& e) {N = sem_send_n; e = sem_e;}
    void get_rsa_recv(uint64_t& N, uint64_t& d) {N = rsa_recv_n; d = rsa_d;}
    void get_sem_recv(uint64_t& N, uint64_t& d) {N = sem_recv_n; d = sem_d;}
    std::string get_preference() {return *(comm_priority.begin());}
    bool has_preference(std::string pref);
    void get_des(uint64_t& DES) {DES = des;}
    std::string get_username() { return std::string(username);}
    void get_password(char* pass, int& size) { memcpy(pass, password, pass_len); size = pass_len;}
    void get_thread_read(int& pipe) {pipe = thread_pipe_r;}
    void get_connect_info(struct sockaddr_in* conn) {conn->sin_family = comm_info.sin_family; conn->sin_addr.s_addr = comm_info.sin_addr.s_addr; }
    
    private:
    std::string username;
    char password[33];
    std::list<std::string> comm_priority;
    uint64_t rsa_recv_n;
    uint64_t rsa_send_n;
    uint64_t rsa_e;
    uint64_t rsa_d;
    uint64_t des;
    uint64_t sem_recv_n;
    uint64_t sem_send_n;
    uint64_t sem_e;
    uint64_t sem_d;
    bool secure;
    bool online;
    int comm_sock;
    int msg_sock;
    int thread_pipe_w;
    int thread_pipe_r;
    struct sockaddr_in comm_info;
    time_t last_online;
    int pass_len;
};

#endif
