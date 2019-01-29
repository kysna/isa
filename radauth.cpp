#include <iostream>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <cstring>
#include <string>
#include <algorithm>
#include <vector>

#include <openssl/md5.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAX_BUF 4096
#define ACCESS_REQUEST 1
#define ACCESS_ACCEPT 2
#define ACCESS_REJECT 3
#define USER_NAME 1
#define USER_PASSWORD 2
#define NAS_IDENTIFIER 32
#define DISCARD -1
#define RESPONSE_LENGTH 20

using namespace std;

enum{
  MISS_SECRET,
  MISS_USERDB,
  ERR_ARG,
  INC_DATA,
  MULT_DATA,
  ERR_OPEN_F,
  ERR_GET_IP,
  DB_LINE_FORMAT,
  ERR_MYSOCKET,
  ERR_BIND,
  MISS_IFACE, 
  MISS_PORT
};

typedef struct db{
  vector<string> user_name;
  vector<string> user_pass;
  unsigned char response[MAX_BUF];
  unsigned int response_l;
} Tdb;

typedef struct conff{
  vector<string> iface;
  int port;
  string secret;
  string userdb;
} Tconff;



////////////
//print help
void printhelp(){
  cout << "Radauth." << endl << "Use Arguments ./radauth -c <path_to_conf_file>" << endl;
  cout << "Example of a correct conf file syntax:" << endl;
  cout << "iface=eth0,eth1" << endl;
  cout << "port=11812" << endl;
  cout << "secret=password" << endl;
  cout << "userdb=/home/isa/users.txt" << endl;
  exit(0);
}

////////////////
//Handle signals
void signal_handle(int signum){

  exit(0);
}


////////////////////////////
//handle errors and warnings
void err_handle(int err){

  if(err == MISS_IFACE){
    cerr << "Error: Item \"iface\" missing in the conf file. See -h." << endl;
    exit(MISS_IFACE);
  }
  else if(err == MISS_PORT){
    cerr << "Error: Item \"port\" missing in the conf file. See -h." << endl;
    exit(MISS_PORT);
  }
  else if(err == MISS_SECRET){
    cerr << "Warning: Item \"secret\" missing in the conf file. See -h." << endl;
  }
  else if(err == MISS_USERDB){
    cerr << "Warning: Item \"userdb\" missing in the conf file. See -h." << endl;
  }
  else if(err == ERR_ARG){
    cerr << "Error: Wrong Arguments, see --help or -h." << endl;
    exit(ERR_ARG);
  }
  else if(err == INC_DATA){
    cerr << "Warning: Redundant or incorrect data in the conf file." << endl;
  }
  else if(err == MULT_DATA){
    cerr << "Warning: Multiple occurrence of one of the items in the conf file. Program might not work properly. See -h." << endl;
  }
  else if(err == ERR_OPEN_F){
    cerr << "Error: Cannot open file." << endl;
    exit(ERR_OPEN_F);
  }
  else if(err == ERR_GET_IP){
    cerr << "Warning: The proccess of getting IPv4 of interface didn't succeed." << endl;
  }
  else if(err == DB_LINE_FORMAT){
    cerr << "Warning: One of the lines in the database of users has a wrong format." << endl;
  }
  else if(err == ERR_MYSOCKET){
    cerr << "Error: There was an error while creating one of the sockets." << endl;
    exit(ERR_MYSOCKET);
  }
  else if(err == ERR_BIND){
    cerr << "Error: Server couldn't bind to one of the sockets." << endl;
    exit(ERR_BIND);
  }

  return;
}

//////////////////////////////////////////////////
//Check arguments, possibilities: -help, -c <path>
char *getparam(int argc, char **argv){
  
  char *path;
  if ((argc == 2) and ((strcmp(argv[1], "--help") == 0) or (strcmp(argv[1], "-h") == 0)))
    printhelp();
  else if((argc != 3) or (strcmp(argv[1], "-c") != 0)){
    err_handle(ERR_ARG);
  }
  else
    path = argv[2];

  return path;
}

///////////////////////////////////////////
//Parse the conf file and the user database
int parsefile(char *path, Tconff &cf, Tdb &dblist){

  fstream confstream;
  fstream dbstream;
  string h;
  string ifaces;
  int m1=0,m2=0,m3=0,m4=0;
  int find_sep;


  confstream.open(path);
  if(!confstream.is_open()){
    err_handle(ERR_OPEN_F);
  }

  //fill the structure with info from conf file
  while(!confstream.eof()){
    getline(confstream, h);
    h.erase(remove_if(h.begin(), h.end(), ::isspace), h.end());   //erase whitespaces
    if(h.substr(0,6) == "iface="){  //if it is the line with interfaces
      ifaces = h.substr(6,256);     //store its values
      if(ifaces == "")
        err_handle(MISS_IFACE);
      m1++;   //increment variable to check whether there are multiple lines with interfaces
    }
    else if(h.substr(0,5) == "port="){
      h = h.substr(5,256);
      if(h == "")
        err_handle(MISS_PORT);
      istringstream sstr(h);
      sstr >> cf.port;
      m2++; 
    }
    else if(h.substr(0,7) == "secret="){
      cf.secret = h.substr(7,256);
      m3++;
    } 
    else if(h.substr(0,7) == "userdb="){
      cf.userdb = h.substr(7,256);
      m4++; 
    }
    else if(h != "")
      err_handle(INC_DATA);
      
  }
  confstream.close();
  
  //divide interfaces and store them into vector
  while(ifaces.compare("") != 0){
    find_sep = ifaces.find(",");
    if(find_sep != -1){		//store interface and update string if coma was found
      cf.iface.push_back(ifaces.substr(0,find_sep));
      ifaces = ifaces.substr(find_sep+1, 256);
    }
    else{				//store last interface if there are no comas left
      cf.iface.push_back(ifaces.substr(0,256));
      ifaces = "";
    }
  }



  //handle mistakes in conf file and warn user
  if(m1 == 0)
    err_handle(MISS_IFACE);
  if(m2 == 0)
    err_handle(MISS_PORT);
  if(m3 == 0)
    err_handle(MISS_SECRET);
  if(m4 == 0)
    err_handle(MISS_USERDB);
  if(m1 > 1 or m2 > 1 or m3 > 1 or m4 > 1)
    err_handle(MULT_DATA);


  dbstream.open(cf.userdb.c_str());
  if(!dbstream.is_open()){
    err_handle(ERR_OPEN_F);
  }

  //fill the vectors of strings with usernames and passwords from userdb
  while(!dbstream.eof()){
    getline(dbstream, h);

    if(h == "")
      continue;

    find_sep = h.find(":");
    if(find_sep != -1){		//store user_name and password
      dblist.user_name.push_back(h.substr(0,find_sep));
      dblist.user_pass.push_back(h.substr(find_sep+1, 256));
    }
    else				//warn user if theres no ":"
      err_handle(DB_LINE_FORMAT);    

  }
  dbstream.close();


  return 0;
}

/////////////////
//Create response
void build_response(int status, int found, unsigned int l, unsigned char buf[MAX_BUF], Tconff &cf, Tdb &dblist){

  unsigned char tmp_hash[MD5_DIGEST_LENGTH];
  memset(tmp_hash, 0, MD5_DIGEST_LENGTH);
  unsigned char replymsg_a[] = "Access granted for ";   //19 bytes
  unsigned char replymsg_r[] = "Access denied for ";   //18 bytes

  unsigned char replymsg[20];  //reply msg will never be longer than 20 bytes
  memset(replymsg, 0, 20);

  int name_l = 0;
  unsigned char *name;

  if(status == ACCESS_ACCEPT)
    memcpy(replymsg, replymsg_a, 19);
  else  
    memcpy(replymsg, replymsg_r, 18);

  //get length of user_name
  if(found >= 0)
    name_l = dblist.user_name.at(found).length();
  else{
    memcpy(&name_l, &buf[l+1], 1);
    name_l -= 2;
  }

  //get user_name
  name = (unsigned char *)malloc(sizeof(unsigned char)*(name_l));
  if(found >= 0)
    memcpy(name, (unsigned char *)dblist.user_name.at(found).c_str(), name_l);
  else{
    memcpy(name, &buf[l+2], name_l);
  }
  
  
  unsigned int reply_l = strlen((const char *)replymsg); 
  unsigned char *r;
  r = (unsigned char *)malloc(sizeof(unsigned char)*(RESPONSE_LENGTH+2+reply_l+name_l+cf.secret.length()));
  
  //Make Response that will be hashed using MD5
  memset(r,0,RESPONSE_LENGTH+reply_l+name_l+2+cf.secret.length());
  memset(&r[0], status, 1);   //1st byte is code - ACCEPT or REJECT
  memcpy(&r[1], &buf[1], 1);  // ID from Access-Request Packet
  memset(&r[3], RESPONSE_LENGTH+2+reply_l+name_l, 1);  // Length of Response
  memcpy(&r[4], &buf[4], 16);  // Request Authenticator
  memset(&r[20], 18, 1);   // code 18 stands for Attribute Reply-Message
  memset(&r[21], 2+reply_l+name_l, 1);  // length of Reply-Message - code+length+strlen(msg)+strlen(user_name)
  memcpy(&r[22], replymsg, reply_l);  // Reply message without user_name
  memcpy(&r[22+reply_l], name, name_l); // User name
  memcpy(&r[22+reply_l+name_l], (unsigned char *)cf.secret.c_str(), cf.secret.length()); // shared secret 


  MD5(r, RESPONSE_LENGTH+2+reply_l+name_l+cf.secret.length(), tmp_hash);

  //Creation of Access-Accept/Reject packet using the result of MD5 function instead of Request Authenticator
  memcpy(&r[4], tmp_hash, MD5_DIGEST_LENGTH);
  memset(dblist.response, 0, MAX_BUF);
  memcpy(dblist.response, r, RESPONSE_LENGTH+reply_l+name_l+2);

  dblist.response_l = RESPONSE_LENGTH+reply_l+name_l+2; // store length of packet


  free(r);
  free(name);

  return;
}


/////////////////////////////////////////////////////////////////////////
//Check whether the User-Password equals the user's Password from database
int control_password(unsigned char buf[MAX_BUF], Tconff &cf, Tdb &dblist, unsigned int l, int found){

  unsigned char att_code;
  unsigned char att_length;
  unsigned char *hash_pass;
  unsigned char user_password[MD5_DIGEST_LENGTH];
  unsigned char p[MD5_DIGEST_LENGTH];

  unsigned int d = dblist.user_pass.at(found).length();;
  unsigned char auth[MD5_DIGEST_LENGTH];
  memcpy(auth, &buf[4], MD5_DIGEST_LENGTH);

  unsigned char tmp_hash[MD5_DIGEST_LENGTH];
  memset(tmp_hash, 0, MD5_DIGEST_LENGTH);

  memcpy(&att_code, &buf[l], 1);
  memcpy(&att_length, &buf[l+1], 1);
  hash_pass = (unsigned char *)malloc(sizeof(unsigned char)*(cf.secret.length() + MD5_DIGEST_LENGTH)); 

  /*
  Each cycle is for 16B of a password ==> (attribute_length-2 / 16) cycles.
  E.g. if user_pasword in Access Request packet is 32 bytes long, the attribute_length is 34,
  so there will be (34-2) / 16, which is 2 cycles.
  Alghorithm is as follows: C1 = P1 XOR (secret + RA), C2 = P2 XOR (secret + C1),C3 = P3 XOR (secret + C2), ...
  where CX - user_password from Access Request packet, PX - password from database, secret - shared secret
  RA - request authenticator      
  */
  for(unsigned i=0; i<((unsigned int)att_length-2)/MD5_DIGEST_LENGTH; i++){
    memset(hash_pass, 0, cf.secret.length() + MD5_DIGEST_LENGTH);

    //fill variable wchiw will be entering hash
    memcpy(hash_pass, cf.secret.c_str(), cf.secret.length()); 
    memcpy(&hash_pass[cf.secret.length()], auth, MD5_DIGEST_LENGTH);  

    //md5
    memset(tmp_hash, 0, MD5_DIGEST_LENGTH);
    MD5(hash_pass, cf.secret.length()+MD5_DIGEST_LENGTH, tmp_hash);

    //prepare variable PX for XOR - fill it with 16B of password from database
    memset(user_password, 0, MD5_DIGEST_LENGTH);
    memset(p, 0, MD5_DIGEST_LENGTH);

    if( d > 16 ){
      memcpy(p, &dblist.user_pass.at(found).c_str()[i*MD5_DIGEST_LENGTH], MD5_DIGEST_LENGTH);
      d -= 16;
    }
    else
      memcpy(p, &dblist.user_pass.at(found).c_str()[i*MD5_DIGEST_LENGTH], d);

    //PX xor (result of md5) and then compare with the bytes from request packet
    for(int j=0; j<MD5_DIGEST_LENGTH; j++){
      user_password[j] = p[j] ^ tmp_hash[j];

      if(user_password[j] != buf[l+j+2+i*MD5_DIGEST_LENGTH]){
        free(hash_pass);
        return ACCESS_REJECT;
      }
    }

    //keep CX for further use
    for(int k=0; k<MD5_DIGEST_LENGTH; k++){
      auth[k] = user_password[k];
    }
  }
 
  hash_pass = NULL;
  free(hash_pass);

  return ACCESS_ACCEPT;

}


//////////////////////////////////////////////
//Control packet and decide the type of answer
int parse_packet(unsigned char buf[MAX_BUF], Tconff &cf, Tdb &dblist){

  unsigned char identifier;
  memcpy(&identifier, &buf[1], 1);

  unsigned int length;
  length &= 0;
  length = buf[2] << 8;
  length |= buf[3];

  if(length < 20 or length > 4096)  //The minimum length is 20 and maximum length is 4096.
    return DISCARD;  

  unsigned int buf_l;
  buf_l = strlen((const char*)buf);  //If the packet is shorter than it's Length indicates, it MUST discarded
  if(length < buf_l)
    return DISCARD;

  //ATTRIBUTES CHECK
  unsigned char att_code;
  unsigned char att_length;
  unsigned char *user_name;
  unsigned int l = 20; //code of the first attribute is at 21st byte (buf[20])
  int found = -1;
  int check_name=0, check_pass=0, check_nas_id=0;
  int count_bytes = 0;
  int p_before_n = 0;
  unsigned int store_l;
 
  while(l < (length)){
    memcpy(&att_code, &buf[l], 1);
    memcpy(&att_length, &buf[l+1], 1);


    //USER-NAME
    if((unsigned int) att_code == USER_NAME){
      found = -2;
      user_name = (unsigned char *)malloc(sizeof(unsigned char)*(att_length - 2));
      memset(user_name, 0, att_length-2);
      memcpy(&user_name[0], &buf[l+2], att_length-2); //get user-name from Access-Request Packet

      for(unsigned int i=0; i<dblist.user_name.size(); i++){
        if((att_length - 2) != dblist.user_name.at(i).length())
          continue;

        for(unsigned int j=0; j<dblist.user_name.at(i).length(); j++){
          if(user_name[j] == dblist.user_name.at(i).c_str()[j] ){ //compare with db
            count_bytes++;
            if((count_bytes == (att_length -2)) and ((att_length -2) == dblist.user_name.at(i).length()))
	      found = i; //username found at position i - password must be at the same position
          }          
          else
            count_bytes = 0;
        }
      }



      if(found == -2) {
        free(user_name);
        build_response(ACCESS_REJECT, found, l, buf,cf,dblist);  
        if(p_before_n != 0)    
          return ACCESS_REJECT; //username was not found in the database, send access_reject packet
      }

      user_name = NULL;
      free(user_name);
      check_name = 1;

      //If attribute user_password was before user_name
      if(p_before_n == 1){
        if(control_password(buf,cf,dblist,store_l,found) == ACCESS_REJECT){
          build_response(ACCESS_REJECT, found, store_l, buf,cf,dblist);
          return ACCESS_REJECT;
        }
        check_pass = 1;
        memcpy(&att_length, &buf[l+1], 1);
      }
    }
   
    //USER-PASSWORD
    else if(((unsigned int) att_code == USER_PASSWORD) and (found >= 0) ){
      if(control_password(buf,cf,dblist,l,found) == ACCESS_REJECT){
        build_response(ACCESS_REJECT, found, l, buf,cf,dblist); 
        return ACCESS_REJECT;
      }
      check_pass = 1;   
    }

    //If attribute user_password was before user_name and user_name was wrong
    else if(((unsigned int) att_code == USER_PASSWORD) and (found == -2) ){
      return ACCESS_REJECT; 
    }

    //If attribute user_password was before user_name
    else if(((unsigned int) att_code == USER_PASSWORD) and (found == -1) ){
      p_before_n = 1;
      store_l = l;  
    }

    //NAS-IDENTIFIER
    else if((unsigned int) att_code == NAS_IDENTIFIER){
      check_nas_id = 1;
    }

    l = l + (unsigned int)att_length; //Move in the Access-Request packet
  }
 
  if((check_name == 0) or (check_pass == 0) or (check_nas_id == 0)){ 
    return DISCARD;
  }

  build_response(ACCESS_ACCEPT, found, l, buf,cf,dblist);
  return ACCESS_ACCEPT;
}

////////////////////////////////////////////////
//Create a connection, receive and send messages
void my_srv(Tconff &cf, Tdb &dblist){

  
  int *mysocket;
  struct sockaddr_in *ip_address; 
  struct ifreq ifr;
  unsigned int addrlen;
  fd_set rdfds;

  mysocket = (int *)malloc(sizeof(int)*(cf.iface.size())); 
  ip_address = ( sockaddr_in *)malloc(sizeof(sockaddr_in)*(cf.iface.size())); 


  for(unsigned n=0; n<cf.iface.size(); n++){
    if((mysocket[n] = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      err_handle(ERR_MYSOCKET);

    memset(&ip_address[n], 0, sizeof(struct sockaddr));
    memset(&ifr, 0, sizeof(struct ifreq));


    ip_address[n].sin_family = AF_INET;
    ip_address[n].sin_port = htons(cf.port);
    ip_address[n].sin_addr.s_addr = INADDR_ANY;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, (cf.iface.at(n)).c_str()  , IFNAMSIZ-1);

    if (ioctl(mysocket[n], SIOCGIFADDR, &ifr) < 0) {
      err_handle(ERR_GET_IP);
      close(mysocket[n]);
      }

    ip_address[n].sin_addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    if((bind(mysocket[n], (struct sockaddr*)&ip_address[n], sizeof(ip_address[n]))) < 0)
      err_handle(ERR_BIND);

  }
  

  unsigned char buf[MAX_BUF];
  unsigned char code;
  addrlen = sizeof(ip_address[0]);
  int max = mysocket[0];
  int pid;

  while(1){

    FD_ZERO(&rdfds);
    for(unsigned int i=0; i<cf.iface.size(); i++){
      FD_SET(mysocket[i], &rdfds);
      if(mysocket[i] > max)
        max = mysocket[i];
    }
     




    if(select(max+1, &rdfds, NULL, NULL, NULL) == -1){
      free(mysocket);
      free(ip_address);
      return;
    }

    for (unsigned int i = 0; i< cf.iface.size(); i++){
      if (FD_ISSET(mysocket[i], &rdfds)){

	if((pid = fork()) < 0){
	  kill(0, SIGTERM);
        }
        else if(pid == 0){
          recvfrom(mysocket[i], buf, MAX_BUF, 0, (struct sockaddr*)&ip_address[i], &addrlen);
          memcpy(&code, &buf[0], 1);

          if((unsigned int) code == ACCESS_REQUEST){
            code = parse_packet(buf,cf, dblist);
            if((unsigned int) code == ACCESS_ACCEPT or (unsigned int) code == ACCESS_REJECT){
              sendto(mysocket[i], dblist.response, dblist.response_l, 0, (struct sockaddr*)&ip_address[i], sizeof(ip_address[i]));
            }
          }
        }  
      }
    }
  }
}


//////
//main
int main(int argc, char **argv){



  char *path;
  Tconff cf;  
  Tdb dblist;
  
  signal(SIGINT, signal_handle);
  signal(SIGTERM, signal_handle);
  signal(SIGQUIT, signal_handle);


  path = getparam(argc, argv); //Harvest command-line parameters
  parsefile(path, cf, dblist); //Parse the conf file and the user database
  my_srv(cf, dblist);

  return 0;
  

}
