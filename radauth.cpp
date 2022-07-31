/*
    Projekt: ISA
    Autor:   xkonar07

    TODO:   zpracovani signalu - delete mysocket
            valgrind test
            case-insensitive ? nazev souboru ? heslo ? iface ?
            add/ delete printf & comments


*/

#include "radauth.h"

int processIncome(char *buffer, tSettings *settings, bool &verified, bool &discard, tPacket *myPacket);
void showHelp(void);
void showError(int error);
int processArg(int argc, char **argv, tSettings *settings);

bool allocated = false;
int *mysocket = NULL;

void showHelp()
{
    printf("Help message for project ISA\n");
    printf("Author: David Konar (xkonar07@stud.fit.vutbr.cz\n\n");
    printf("Usage: ./radauth -c <konfiguracni soubor>\n");
    printf("Parametres:\t-c <config filename>\tobligatory parametr\n");
}

void showError(int error)
{
    fprintf(stderr, "%s\n", EMSG[error]);
}

int processArg(int argc, char **argv, tSettings *settings)
{

    // we need 2 input arguments precisely
    if (argc < 2 || argc > 3)
    {
        return E_ARG;
    }
    else if (argc == 2)
    {
        if ((strcmp(argv[1], "-h")) == 0)
        {
            return E_HELP; // OK, we will show help msg
        }
        else
        {
            return E_ARG;
        }
    }
    else
    {
        // 2nds argument has to be like this
        if ((strcmp(argv[1], "-c")) == 0)
        {
            // 3rd argument is path to config file - save it!
            settings->path = argv[2];
            return E_OK;
        }
        else
        {
            return E_ARG;
        }
    }
    return E_OK;
}

int parseConfigFile(ptrSettings settings)
{

    ifstream infile;
    infile.exceptions(ifstream::failbit | ifstream::badbit);
    string whitespaces(" \t\f\v\n\r");
    string thisLine;
    string name;
    string value;
    string tmp;
    size_t pos;
    size_t current;
    size_t next = -1;
    vector<string>::iterator it;

    //is the file readable ?
    try
    {
        infile.open(settings->path.c_str(), ifstream::in);

        while (!infile.eof())
        {
            getline(infile, thisLine);
            pos = thisLine.find_first_not_of(whitespaces);
            if (pos != string::npos)
            {
                thisLine = thisLine.substr(pos);
            }
            thisLine.erase(thisLine.find_last_not_of(whitespaces) + 1);
            if (thisLine.empty())
            { // empty lines
                continue;
            }

            // parse the file
            current = next + 1;
            next = thisLine.find_first_of("=", current);
            name = thisLine.substr(current, next - current);

            current = next + 1;
            next = thisLine.find_first_of("=", current);
            value = thisLine.substr(current, next - current);

            current = next + 1;
            next = thisLine.find_first_of("=", current);
            name.erase(name.find_last_not_of(whitespaces) + 1);
            if (next == string::npos) // wrong file structure
                return E_CONF;

            if (strcasecmp(name.c_str(), "iface") == 0)
            {
                next = -1;
                int q = 1;
                do
                {
                    current = next + 1;
                    next = value.find_first_of(",", current);
                    tmp = value.substr(current, next - current);

                    pos = tmp.find_first_not_of(whitespaces);
                    if (pos != string::npos)
                    {
                        tmp = tmp.substr(pos);
                    }
                    tmp.erase(tmp.find_last_not_of(whitespaces) + 1);

                    // save it to the structure
                    settings->interface.insert(settings->interface.begin() + q - 1, tmp);
                    q++;
                    settings->numInterfaces++;
                } while (next != string::npos);
            }
            else if (strcasecmp(name.c_str(), "port") == 0)
            {
                pos = value.find_first_not_of(whitespaces);
                if (pos != string::npos)
                {
                    value = value.substr(pos);
                }
                value.erase(value.find_last_not_of(whitespaces) + 1);

                settings->port = atoi(value.c_str());

                if (settings->port == 0)
                    return E_CONF;
            }
            else if (strcasecmp(name.c_str(), "secret") == 0)
            {
                settings->secret = value;
            }
            else if (strcasecmp(name.c_str(), "userdb") == 0)
            {
                pos = value.find_first_not_of(whitespaces);
                if (pos != string::npos)
                {
                    value = value.substr(pos);
                }
                value.erase(value.find_last_not_of(whitespaces) + 1);
                settings->userdb = value;
            }
            else
            {
                return E_CONF;
            }
            next = -1;

            if (infile.eof())
                break;
        }
    }
    catch (ifstream::failure e)
    {
        //infile.close();
        return E_CONF;
    }

    infile.close();
    return E_OK;
}

// padd/fill the string with 0x0 (zeros) in 16-byte (octet) blocks
void padPassword(string &password)
{

    int mod = 0;
    int bytes = 16;
    int len = password.length();

    if ((mod = len % 16) != 0)
    {
        bytes -= mod;
        password.append<int>(bytes, 0x0);
    }
}

// find user in file with username:password
bool findUser(string userdb, string username, string &password)
{

    ifstream infile;
    string name;
    string value;
    infile.exceptions(ifstream::failbit | ifstream::badbit);
    string thisLine;
    vector<string>::iterator it;
    bool found = false;

    size_t current;
    size_t next = -1;

    //is the file readable ?
    try
    {
        infile.open(userdb.c_str(), ifstream::in);

        while (!infile.eof())
        {
            getline(infile, thisLine);

            thisLine.erase(thisLine.find_last_not_of(" \n\r\t") + 1);
            if (thisLine.empty())
            { // empty lines
                continue;
            }

            current = next + 1;
            next = thisLine.find_first_of(":", current);
            name = thisLine.substr(current, next - current);

            current = next + 1;
            next = thisLine.find_first_of(":", current);
            value = thisLine.substr(current, next - current);

            current = next + 1;
            next = thisLine.find_first_of(":", current);
            if (next == string::npos) // wrong file structure
                return E_FUSR;

            if ((username.compare(name)) == 0)
            {
                // names match !!
                found = true;
                password.assign(value);
            }

            next = -1;

            if (infile.eof())
                break;
        }
    }
    catch (ifstream::failure e)
    {
        return E_FUSR;
    }

    infile.close();
    if (found)
        return true;

    return false;
}

bool parseAttributes(char *msg, tPacket *myPacket)
{
    int i = 0;
    int q = 0;
    int attrLen = 0;
    bool globalCondition = true;
    bool name = false;
    bool password = false;
    bool NASid = false;
    int type = 0;
    int cnt = 0;
    // parse attributes -> 20th byte and folowwing...
    // this loop parse each attribute separately
    for (i = 20; i < myPacket->length;)
    {
        type = 0;
        q = i;

        if ((unsigned char)msg[i] == 1)
        { // User-Name
            type = 1;
            name = true;
        }
        else if ((unsigned char)msg[i] == 2)
        { // User-Password
            type = 2;
            password = true;
        }
        else if ((unsigned char)msg[i] == 32)
        { // NAS-Identifier
            type = 32;
            NASid = true;
        }
        else
        { // ignore
            ;
        }

        i++;
        // length of the following attribut (in bytes)
        attrLen = (unsigned char)msg[i] + i - 1;
        if (type == 2)
        {
            myPacket->passLength = (unsigned char)msg[i] - 2;
        }
        if (type == 1)
        {
            if ((unsigned char)msg[i] - 2 < 3) // to short user-name (minimum is 3 chars)
                globalCondition = false;
        }

        i++;
        cnt = 0;
        for (q = i; q < attrLen; q++)
        {
            if (type == 1)
            {
                myPacket->name += msg[q];
            }
            if (type == 2)
            {
                myPacket->pass[cnt] = msg[q];
                cnt++;
                //myPacket->pass += msg[q];
            }
            if (type == 32)
            {
                myPacket->NASid[cnt] = msg[q];
                cnt++;
                //myPacket->pass += msg[q];
            }
        }
        i = q;
    }
    if (name == true && password == true && NASid == true && globalCondition == true)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int createResponse(bool accept, char *msg, unsigned char *&response, tSettings *settings, tPacket *myPacket)
{

    int code;
    unsigned int i = 0;
    unsigned int len;
    string txt;
    int finallength = 20;  // minimum length
    int acceptLength = 19; //strlen("Access granted for ")
    int rejectLength = 18; //strlen("Access denied for  ")
    unsigned char hashed[MD5_DIGEST_LENGTH];
    unsigned char *received;

    // set code and reply-message according the verified process
    if (accept == true)
    {
        code = 2;
        finallength = finallength + acceptLength /*+ myPacket->name.length() + replyMsgLength*/;
        txt.append("Access granted for ");
        txt.append(myPacket->name);
    }
    else
    {
        code = 3;
        finallength = finallength + rejectLength /* + myPacket->name.length() + replyMsgLength*/;
        txt.append("Access denied for ");
        txt.append(myPacket->name);
    }
    len = 22 + txt.length();

    received = new unsigned char[22 + txt.length() + settings->secret.length()];
    response = new unsigned char[22 + txt.length()];
    memset(response, 0, 22 + txt.length());
    memset(received, 0, 22 + txt.length() + settings->secret.length());

    for (i = 0; i < 20; i++)
        received[i] = msg[i];

    received[0] = code;
    received[3] = len; //

    received[20] = 18;               // attribute type: Reply-Message
    received[21] = txt.length() + 2; // atrribute length (text itself + 1 byte [type] + 1 byte [length])
    for (i = 22; i < 22 + txt.length(); i++)
    {
        received[i] = txt.at(i - 22);
    }

    for (i = (22 + txt.length()); i < ((22 + txt.length()) + settings->secret.length()); i++)
        received[i] = settings->secret.at(i - (22 + txt.length()));

    MD5(received, 22 + txt.length() + settings->secret.length(), hashed);

    // set response code response atc.
    response[0] = code;
    response[1] = msg[1];
    response[2] = 0;
    response[3] = len;
    for (i = 4; i < 20; i++)
    {
        response[i] = hashed[i - 4];
    }

    response[20] = 18;
    response[21] = 2 + txt.length();
    for (i = 22; i < 22 + txt.length(); i++)
    {
        response[i] = txt.at(i - 22);
    }

    delete[] received;

    return len;
}

int processIncome(char *buffer, tSettings *settings, bool &verified, bool &discard, tPacket *myPacket)
{

    unsigned int cnt = 0;
    verified = true;
    int toHashLength = 0;
    string password;
    string toHash;
    unsigned char MD5result[MD5_DIGEST_LENGTH];
    unsigned char finalValue[128];

    myPacket->name.clear();
    myPacket->NASid.clear();

    toHash.clear();
    password.clear();
    memset(myPacket->pass, 0, 128);
    memset(myPacket->auth, 0, 16);
    memset(finalValue, 0, 128);

    /*************************/
    /*****GET PLAIN INFO******/
    /*************************/

    // CODE
    // has to be '1' - we accept only "access-request" packets. Otherwise discard it
    if ((unsigned char)buffer[0] != 1)
    {
        discard = true;
        return E_OK;
    }

    // IDENTIFIER
    // (unsigned char)buffer[1]
    // save this value - is used to match "request-response"
    myPacket->identifier = (unsigned char)buffer[1];

    // LENGTH
    // (unsigned char)buffer[2];
    // (unsigned char)buffer[3];
    myPacket->length = (unsigned char)buffer[2] * 256 + (unsigned char)buffer[3];
    if (myPacket->length < 20 || myPacket->length > 4096)
    {
        discard = true;
        return E_OK;
    }

    for (cnt = 0; cnt < 16; cnt++)
    {
        myPacket->auth[cnt] = buffer[(4 + cnt)];
    }

    if ((verified = parseAttributes(buffer, myPacket)) == false)
    {
        // one of the important attributes is missing (either password, name or NAS-identifier)
        verified = false;
        return E_OK;
    }

    /**********************************/
    /*******VERIFY USER & PASS*********/
    /**********************************/
    // check if the user-name exists and get its password from userDB file
    if ((findUser(settings->userdb, myPacket->name, password)) == false)
    {
        verified = false;
        //return E_USR;
        return E_OK;
    }
    if (verified == true)
    { // user-name not found, skip it!

        // pad the password (according the RADIUS rfc2865 standards)
        padPassword(password);

        //if the password lenghts differ => they are different for sure so no hashing...
        if (password.length() != myPacket->passLength)
        {
            verified = false;
        }
        else
        { // password have the same length

            // new string containig shared secret + authenticator (from packet)
            toHash += settings->secret;
            for (cnt = 0; cnt < 16; cnt++)
            {
                toHash += (myPacket->auth[cnt]);
            }

            toHashLength = toHash.length();
            // hash the whole string  => output is in result
            MD5((unsigned char *)toHash.c_str(), toHashLength, MD5result);

            cnt = 0;
            for (; cnt < 16; cnt++)
            { // "cnt" is set to "0" for the first time
                finalValue[cnt] = MD5result[cnt] ^ (password.at(cnt));
            }

            int octet = 1;
            int zero = 0;
            unsigned int limit;
            unsigned int backward;
            int numOfOctets = myPacket->passLength / 16;
            for (octet = 1; octet < numOfOctets; octet++)
            {
                toHash.clear();

                zero = 0;
                backward = cnt - 16;
                toHash += settings->secret;
                limit = backward + 16;

                for (; backward < limit; backward++)
                {
                    toHash += (finalValue[backward]);
                }
                toHashLength = toHash.length();
                // hash the whole string  => output is in result
                MD5((unsigned char *)toHash.c_str(), toHashLength, MD5result);

                zero = 0;
                for (; cnt < backward + 16; cnt++)
                { // "cnt" is set to "0" for the first time
                    finalValue[cnt] = MD5result[zero] ^ (password.at(cnt));
                    zero++;
                }
            }

            /**********************************/
            /************VERIFY HASH***********/
            /**********************************/
            for (cnt = 0; cnt < myPacket->passLength; cnt++)
            {
                if (finalValue[cnt] != myPacket->pass[cnt])
                {
                    verified = false;
                    break;
                }
            }
            if (cnt == myPacket->passLength)
            {
                verified = true;
            }
        }
    }
    return E_OK;
}

int connect(tSettings *settings)
{

    tPacket myPacket;

    string ho = "ho";
    unsigned char *ansver2;
    bool verified = true;
    bool discard = false;
    int plen;
    int e;

    int sd, rc, n;
    int flags;
    socklen_t cliLen;
    struct sockaddr_in cliAddr, servAddr;
    char msg[MAX_MSG];
    mysocket = new int[settings->numInterfaces];
    allocated = true;

    /* socket creation */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0)
    {
        return E_SOCK;
    }

    /**********************************/
    struct ifconf ifconf;
    struct ifreq ifreq[MAXINTERFACES];
    int interfaces;
    int i = 0;
    // Point ifconf's ifc_buf to our array of interface ifreqs.
    ifconf.ifc_buf = (char *)ifreq;

    // Set ifconf's ifc_len to the length of our array of interface ifreqs.
    ifconf.ifc_len = sizeof ifreq;

    //  Populate ifconf.ifc_buf (ifreq) with a list of interface names and addresses.
    if (ioctl(sd, SIOCGIFCONF, &ifconf) == -1)
    {
        //printf("ioctl");
        // problem couldnt get the list of iterfaces
    }

    // Divide the length of the interface list by the size of each entry.
    // This gives us the number of interfaces on the system.
    interfaces = ifconf.ifc_len / sizeof(ifreq[0]);

    // Print a heading that includes the total # of interfaces.

    int val = 1;
    std::vector<string>::iterator it;
    char ip[INET_ADDRSTRLEN];
    val = 0;

    // Loop through the array of interfaces, printing each one's name and IP.
    for (i = 0; i < interfaces; i++)
    {

        struct sockaddr_in *address = (struct sockaddr_in *)&ifreq[i].ifr_addr;

        // Convert the binary IP address into a readable string.
        if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
        {
        }

        for (it = (settings->interface).begin(); it != (settings->interface).end(); ++it)
        {
            if (it->compare(ifreq[i].ifr_name) == 0)
            {
                val++;

                mysocket[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if (mysocket[i] < 0)
                {
                    return E_SOCK;
                }
                servAddr.sin_family = AF_INET;
                //servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                servAddr.sin_port = htons(settings->port);
                servAddr.sin_addr.s_addr = inet_addr(ip);
                //printf(":%d %d\n", i, mysocket[i]);
                rc = bind(mysocket[i], (struct sockaddr *)&servAddr, sizeof(servAddr));
                if (rc < 0)
                {
                    return E_BIND;
                }

                if ((flags = fcntl(mysocket[i], F_GETFL, 0)) < 0)
                { // check out current flags of the socket
                    // problem, couldn't get the flag
                    ;
                }
                // error
                flags |= O_NONBLOCK; // add option to make it NON-BLOCK
                if ((fcntl(mysocket[i], F_SETFL, flags)) < 0)
                {
                    // problem; couldnt set it NONBLOCk
                }
            }
        }
    }
    // there is no such a interface !!
    if (val != settings->numInterfaces)
    {
        //printf("ADS: %d\n", E_INT);
        return E_INT;
    }

    // LETS GO TO INFINITY LOOP
    /* init buffer */
    memset(msg, 0, MAX_MSG);

    //select(maxfd+1, &readset, NULL, NULL, NULL);

    fd_set readset;

    while (true)
    {
        int maxfd = -1;
        FD_ZERO(&readset);

        /* Add all of the interesting fds to readset */
        for (i = 0; i <= settings->numInterfaces; ++i)
        {
            if (mysocket[i] > maxfd)
                maxfd = mysocket[i];
            FD_SET(mysocket[i], &readset);
        }

        // wait till some socket is ready to be read from
        select(maxfd + 1, &readset, NULL, NULL, NULL);

        for (i = 0; i <= settings->numInterfaces; ++i)
        {

            if (FD_ISSET(mysocket[i], &readset))
            {
                // if this socket has some data to read
                discard = false;
                verified = true;
                cliLen = sizeof(cliAddr);

                // receive data
                if ((n = recvfrom(mysocket[i], msg, MAX_MSG, 0, (struct sockaddr *)&cliAddr, &cliLen)) >= 0)
                {

                    if (n < 0)
                    {
                        continue;
                    }
                    // process received data - verify
                    if ((e = processIncome(msg, settings, verified, discard, &myPacket)) != E_OK)
                    {
                        return e;
                    }
                    if (n == myPacket.length)
                    { // length is same - OK
                        if (discard == false)
                        { // if the packet is valid then send response (accept or reject) (otherwise retain silent)
                            plen = createResponse(verified, msg, ansver2, settings, &myPacket);
                            sendto(mysocket[i], ansver2, plen, flags, (struct sockaddr *)&cliAddr, cliLen);
                        }
                    }
                    else
                    { // length is different! do nothing...
                        ;
                    }
                }
            }
        }
    }

    return E_OK;
}

void clean_all(int sig)
{
    if (allocated == true)
    {
        delete[] mysocket;
    }
    printf("%d\n", sig);
    exit(sig);
}

int main(int argc, char **argv)
{

    (void)signal(SIGINT, clean_all);
    (void)signal(SIGTERM, clean_all);
    (void)signal(SIGQUIT, clean_all);

    tSettings settings = {};
    int e = E_OK;
    vector<string>::iterator it;

    if (((e = processArg(argc, argv, &settings)) == E_HELP))
    { // show help
        showHelp();
        return EXIT_SUCCESS;
    }
    else if (((e = processArg(argc, argv, &settings)) != E_OK))
    { // bad arguments
        showError(e);
        return EXIT_FAILURE;
    }
    else
    { // everything is fine... continue
        ;
    }

    // verify config file
    if (((e = parseConfigFile(&settings)) != E_OK))
    {
        showError(e);
        return EXIT_FAILURE;
    }

    // start server...
    if (((e = connect(&settings)) != E_OK))
    {
        showError(e);
        return EXIT_FAILURE;
    }

    // it will never get here
    return 0;
}
