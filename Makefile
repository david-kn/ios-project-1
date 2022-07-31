#
# Projekt: ISA
# Autor:   xkonar07
#

NAME=all

CC=g++
CFLAGS=-Wall -pedantic -g -pthread -fpermissive

radauth: radauth.cpp
	$(CC) $(CFLAGS) radauth.cpp -o radauth -lssl -lcrypto




