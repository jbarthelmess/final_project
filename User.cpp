#include "User.h"

User::User() {
    username = "";
    password = "";
    rsa_send_n = rsa_recv_n = rsa_e = rsa_d = des = sem_send_n = sem_recv_n = sem_e = sem_d = 0;
    secure = false;
    online = false;
    comm_sock = -1;
    msg_sock = -1;
    comm_priority.push_back(std::string("DES"));
    comm_priority.push_back(std::string("SEM"));
    comm_priority.push_back(std::string("RSA"));
    last_online = 0;
}

User::User(std::string name, std::string pass) {
    username = name;
    password = pass;
    rsa_send_n = rsa_recv_n = rsa_e = rsa_d = des = sem_send_n = sem_recv_n = sem_e = sem_d = 0;
    comm_priority.push_back(std::string("DES"));
    comm_priority.push_back(std::string("SEM"));
    comm_priority.push_back(std::string("RSA"));
    secure = false;
    online = false;
    comm_sock = -1;
    last_online = 0;
}

User::User(User old) {
    username = old.username;
    password = old.password;
    rsa_send_n = old.rsa_send_n;
    rsa_recv_n = old.rsa_recv_n;
    rsa_e = old.rsa_e;
    rsa_d = old.rsa_d;
    des = old.des;
    sem_send_n = old.sem_send_n;
    sem_recv_n = old.sem_recv_n;
    sem_d = old.sem_d;
    sem_e = old.sem_e;
    secure = old.secure;
    online = old.online;
    comm_sock = old.comm_sock;
    msg_sock = old.msg_sock;
    last_online = old.last_online;
    thread_pipe_w = old.thread_pipe_w;
    thread_pipe_r = old.thread_pipe_r;
    comm_priority.clear();
    for(auto it = old.comm_priority.begin(); it != old.comm_priority.end(); it++) {
        comm_priority.push_back(*it);
    }
    comm_info = old.comm_info
}

bool User::make_secure(std::vector<uint32_t>& sec) {
    if(sec.size() != 9) {
        return -1;
    }
    rsa_recv_n = sec[0];
    rsa_send_n = sec[1];
    rsa_e = sec[2];
    rsa_d = sec[3];
    des = sec[4];
    sem_recv_n = sec[5];
    sem_send_n = sec[6];
    sem_e = sec[7];
    sem_d = sec[8];
    if(time(NULL) - last_online < 604800) {
        return 0;
    }
    return 1;
}

int User::set_preference(std::string top) {
    if(top.compare("RSA") || top.compare("DES") || top.compare("SEM")) {
        comm_priority.remove(top);
        comm_priority.push_front(top);
        return 0;
    }
    else
        return -1;
}

int User::remove_comm_opt(std::string ban) {
    if(ban.compare("RSA") || ban.compare("DES") || ban.compare("SEM")) {
        comm_priority.remove(ban);
        return 1;
    }
    else
        return 0;
}

void User::reset_comm_preferences() {
    comm_priority.clear();
    comm_priority.push_back(std::string("DES"));
    comm_priority.push_back(std::string("SEM"));
    comm_priority.push_back(std::string("RSA"));
}

void User::bring_online(int comm, int msg, struct sockaddr_in info) {
    comm_sock = comm;
    msg_sock = msg;
    comm_info.sin_port = info.sin_port;
    comm_info.sin_family = info.sin_family;
    comm_info.sin_addr = info.sin_addr;
    online = true;
    last_online = time(NULL);
}

void User::logout() {
    comm_sock = -1;
    msg_sock = -1;
    rsa_send_n = rsa_recv_n = rsa_e = rsa_d = des = sem_send_n = sem_recv_n = sem_e = sem_d = 0;
    secure = false;
    online = false;
    reset_comm_preferences();
}

bool User::has_preference(std::string pref) {
    for(auto it = comm_priority.begin(); it != comm_priority.end(); it++) {
        if(!(*it).compare(pref)) return true;
    }
    return false;
}
