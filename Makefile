

CC=g++
CFLAGS=-Wall -pedantic -g

webinfo: radauth.cpp
	$(CC) $(CFLAGS) radauth.cpp -o radauth -lcrypto
