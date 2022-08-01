/*
    Project:	ISA
    Author:		xkonar07
*/

#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <openssl/md5.h>
#include <string>
#include <vector>
#include <string.h>
#include <algorithm>
#include <sys/types.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/ioctl.h>

#define MAX_MSG 4096
#define MAXINTERFACES 100

using namespace std;

enum errors {
    E_OK,           // everything is OK
    E_HELP,         // show help message
    E_ARG,          // wrong params
    E_CONF,         // wrong config gile
    E_WRONG_CON,     // connection problem
    E_PACKET,        // wrong incoming packet
    E_REQ,          // not a access-request
    E_FUSR,         // wrong user:password file
    E_USR,           // no such user
    E_SOCK,         // problem creatin socket
    E_BIND,          // problem to bind socket
    E_SHORT,     // packet is too short
    E_INT,		   	// we could find all interfaces defined in config file
    E_NONBLOCK,		// could set flag to NONBLOCKING
    E_IOCTL			// problem
};

const char *EMSG[] = {
    "VSE JE OK",                                       // E_OK
    "Pomoc"  ,                                         // E_help
    "Spatne zadane parametry",                         // E_ARG
    "Spatny konfiguracni soubor",                      // E_CONF
    "Problem pri pripojeni",                           // E_WRONG_CON
    "Prijaty packet je nevalidni",                    // E_PACKET
    "Prijaty packet neni typu 'access-request'",        // E_REQ
    "Spatny soubor s hesly",                           // E_FUSR
    "Uzivatelsko jmeno nebylo nalezeno",                // E_USR
    "Nelze otevrit socket",                             // E_SOCK
    "Chyba bindovani",                                  // E_BIND;
    "Packet is too short",                              // E_SHORT
    "Rozhrani zadane v konfiguracnim souboru neexistuje",  // E_INT
    "Nepodarilo se nastavit priznak na neblokujici",	// E_NONBLOCK
    "Problem pri ioctl()",					// E_IOCTL
};

typedef struct {
    int port;       // port for communication
    string path;    // path to config file
    string secret;    // shared secret
    string userdb;  // path to 'pass:user' file
    vector<string> interface;   //vector of strings of interfaces to listen on
    int numInterfaces;      // number of interfaces in the config file
    char* response;
    // pole/vector rozhrani

} tSettings, *ptrSettings;

typedef struct {
    unsigned char auth[15];  // auth string
    int length;         // 3rd & 4th packet - cotains length of packet
    unsigned int passLength;
    int identifier;     // 2nd byte of packet - identifier
    string name;        // 1: user-name string (from attribute)
    unsigned char pass[128];        // 2: user-password string (from attribute)
    string NASid;       // 32: NAS-Identifier string (from attribute)

} tPacket, *ptrPacket;

