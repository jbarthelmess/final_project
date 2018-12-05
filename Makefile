all: client.exe server.exe
client.exe: temp.cpp User.cpp User.h Crypto.h
	g++ temp.cpp User.cpp -o client.exe -lpthread -std=c++11

server.exe: server.cpp User.cpp User.h Crypto.h
	g++ server.cpp User.cpp -o server.exe -lpthread -std=c++11

