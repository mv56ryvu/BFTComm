#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <string>
#include <thread>

#include <vector>
#include <deque>

#include "ucxclient/ucxclient.h"
#include "authenticator.pb.h"
#include "peer.pb.h"
#include "crypto/crypto.h"

using namespace std;

#define MAX_MSG_SIZE 1024
#define MAX_NUM_MSGS 10
const int BUFF_SIZE = 4000000;

#define ROLE_CLIENT 0
#define ROLE_PEER_FOLLOWER 1
#define ROLE_PEER_LEADER 2
#define ROLE_COORDINATOR 3

ucx_client ucxClient;

int nodeCount, nodeId, basePort;
vector<string> addresses;
vector<int> roles;
vector<int> basePorts;

bool coordPresent = false;
int coordId;

vector<int> sockets;

bool outgoing_do_hash = false;
bool outgoing_do_sign = false;
bool incoming_do_hash = false;
bool incoming_verify_sign = false;
string hash_alg;
string sign_alg;

RSA* rsa;

// Thread function that receives messages to be multicasted
ucs_status_t receiveData(void *arg, const void *header, size_t header_length,
                         void *data, size_t length, const ucp_am_recv_param_t *param) {
    int pointer = 0;
    while(pointer < length) {
        uint32_t pbSize = 0;
        pbSize += (uint32_t) ((unsigned char*) data)[pointer]; 
        pbSize += (uint32_t) (((unsigned char*) data)[pointer + 1] << 8); 
        pbSize += (uint32_t) (((unsigned char*) data)[pointer + 2] << 16); 
        pbSize += (uint32_t) (((unsigned char*) data)[pointer + 3] << 24);

        bftmessages::SendMessage send_message;
        char* startOfMessage = &(((char*) data)[pointer + 4]);
        if(!send_message.ParseFromArray(startOfMessage, pbSize)) {
            printf("Error parsing multicast message\n");
            return UCS_OK;
        }
        // cout << send_message.DebugString() << endl;

        bftmessages::PeerMessage message = send_message.message();
        bftmessages::Authenticator authenticators[send_message.nodeid_size() * 2];

        if(outgoing_do_hash) {
            // TODO
        }
        if(outgoing_do_sign) {
            string hash = send_message.hash();
            

            for(int i = 0; i < send_message.nodeid_size(); i++) {
                unsigned char signature[60];
                int signature_len = mac_sign(send_message.nodeid(i), (unsigned char*) hash.c_str(), hash.size(), signature);
                
                bftmessages::Authenticator newAuthenticator;
                newAuthenticator.set_fromnodeid(0);
                newAuthenticator.set_tonodeid(send_message.nodeid(i));
                newAuthenticator.set_sig(signature, signature_len);
                newAuthenticator.set_sigtype(bftmessages::SigType::MAC);
                authenticators[i * 2] = newAuthenticator;

                bftmessages::Authenticator coordAuthenticator;
                authenticators[i * 2 + 1] = coordAuthenticator;
            }
        }
        for(int i = 0; i < send_message.nodeid_size(); i++) {
            message.clear_auth();
            if(outgoing_do_sign) {
                message.add_auth()->CopyFrom(authenticators[i * 2]);
                message.add_auth()->CopyFrom(authenticators[i * 2 + 1]);
            } else {
                message.add_auth()->CopyFrom(send_message.signs(i * 2));
                message.add_auth()->CopyFrom(send_message.signs(i * 2 + 1));
            }

            string send_buffer;
            if(!message.AppendToString(&send_buffer)) {
                cout << "Failed to serialize outgoing message" << endl;
            } else {
                uint32_t size = (uint32_t) send_buffer.size();

                const char byte0 = static_cast<unsigned char>(size & 0x000000FF); 
                const char byte1 = static_cast<unsigned char>((size & 0x0000FF00) >> 8); 
                const char byte2 = static_cast<unsigned char>((size & 0x00FF0000) >> 16); 
                const char byte3 = static_cast<unsigned char>((size & 0xFF000000) >> 24);

                const char bytes[] = { byte0, byte1, byte2, byte3 };
                string s(bytes, 4);

                string sendBuf;
                sendBuf.append(bytes, 4);
                sendBuf.append(send_buffer);

                ssize_t n = write(sockets[send_message.nodeid(i)], sendBuf.c_str(), sendBuf.size());
                if(n == 0) {
                    cout << "Failed to send outgoing message" << endl;
                }
            }
        }
        pointer += 4 + pbSize;
    }

    return UCS_OK;
}

int connect_socket(struct sockaddr_in addr) {
	int sock = 0, client_fd;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    if ((client_fd = connect(sock, (struct sockaddr*) &addr, sizeof(addr))) < 0) {
        printf("Connection Failed: %s %d\n", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
        return -1;
    }
    printf("Connected to peer at %s:%d\n", inet_ntoa(addr.sin_addr), htons(addr.sin_port));

    return sock;
}

int connect_to_peers() {
    printf("Connecting to peers\n");
    for(int i = 0; i < nodeCount; i++) {

        if(roles[i] == ROLE_CLIENT) {
            continue;
        }

        struct sockaddr_in peer_addr;
        unsigned char buf[sizeof(struct in6_addr)];
        int targetPort;

        if(roles[i] == ROLE_CLIENT) {
            continue;
        } else if(roles[i] == ROLE_PEER_FOLLOWER || roles[i] == ROLE_PEER_LEADER) {
            targetPort = basePorts[i] + 1;
        } else if(roles[i] == ROLE_COORDINATOR) {
            targetPort = basePorts[i] + 2;
        } else {
            printf("\nInvalid role: %d \n", roles[i]);
            return -1;
        }

        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(targetPort);
    
        int s = inet_pton(AF_INET, addresses[i].c_str(), buf);
        if (s <= 0) {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }
        memcpy(&peer_addr.sin_addr, buf, sizeof(struct in_addr));

        sockets[i] = connect_socket(peer_addr);
    }

    ucxClient.register_callback(receiveData, 2);

    return 0;
}

void process_messages(int socket, int channel) {
    int ret;
    unsigned char buffer[BUFF_SIZE] = { 0 };
    vector<unsigned char> leftover;

    bftmessages::PeerMessage peer_Message;

    while((ret = read(socket, buffer, BUFF_SIZE)) > 0) {
        vector<char> receivedData(buffer, buffer + ret);
        leftover.insert(leftover.end(), receivedData.begin(), receivedData.end());
        vector<unsigned char> sendBuffer;
        
        uint32_t pbSize;
        do {
            pbSize = 0;
            pbSize += (uint32_t) ((unsigned char) leftover[0]) << 0; 
            pbSize += (uint32_t) (((unsigned char) leftover[1]) << 8); 
            pbSize += (uint32_t) (((unsigned char) leftover[2]) << 16); 
            pbSize += (uint32_t) (((unsigned char) leftover[3]) << 24);

            if(4 + pbSize <= leftover.size()) {
                sendBuffer.insert(sendBuffer.end(), leftover.begin(), leftover.begin() + 4 + pbSize);
                leftover.erase(leftover.begin(), leftover.begin() + 4 + pbSize);
            }

            if(leftover.size() >= 4) {
                pbSize = 0;
                pbSize += (uint32_t) ((unsigned char) leftover[0]) << 0; 
                pbSize += (uint32_t) (((unsigned char) leftover[1]) << 8); 
                pbSize += (uint32_t) (((unsigned char) leftover[2]) << 16); 
                pbSize += (uint32_t) (((unsigned char) leftover[3]) << 24);
            }
        } while(leftover.size() >= 4 && leftover.size() >= 4 + pbSize);

        if(sendBuffer.size() > 0) {
            ucxClient.send(&sendBuffer[0], sendBuffer.size(), channel);
        }
    }

	close(socket);
}

void listen_socket(int port) {
	int server_fd, new_socket, valread;

	struct sockaddr_in address;
	address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

	int addrlen = sizeof(address);

	// Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket failed\n");
        exit(-1);
    }
    if (bind(server_fd, (struct sockaddr*)&address, addrlen) < 0) {
        printf("bind failed\n");
        exit(-1);
    }
    if (listen(server_fd, 3) < 0) {
        printf("listen failed\n");
        exit(-1);
    }

    printf("Listening on port %d\n", port);
    while ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*) &addrlen)) >= 0) {

        sockaddr_in peeraddr;
        socklen_t size = sizeof(peeraddr);
        
        getpeername(new_socket, (struct sockaddr *)&peeraddr, &size);
        string address = inet_ntoa(peeraddr.sin_addr);

        if(port == basePort) {
            // Add client socket to correct location in sockets
            for(int i = 0; i < nodeCount; i++) {
                auto res = std::mismatch(addresses[i].begin(), addresses[i].end(), address.begin());
                if (res.first == addresses[i].end() && roles[i] == ROLE_CLIENT)
                {
                    sockets[i] = new_socket;
                }
            }
        }

        printf("Accepted connection on port %d\n", port);

        std::thread(process_messages, new_socket, port - basePort).detach();
    }

	exit(0);
}

int listen_for_connections() {
    for(int i = 0; i < 3; i++) {
        int port = basePort + i;
        thread (listen_socket, port).detach();
    }

    return 0;
}

// Thread function that receives connection targets
ucs_status_t receiveConn(void *arg, const void *header, size_t header_length,
                         void *data, size_t length, const ucp_am_recv_param_t *param) {
    connect_to_peers();

    return UCS_OK;
}

// Thread function that receives init parameters
ucs_status_t receiveInit(void *arg, const void *header, size_t header_length,
                         void *data, size_t length, const ucp_am_recv_param_t *param) {
    bftmessages::ConfigMessage config_message;

    if(config_message.ParseFromArray(header, header_length)) {
        cout << "Parsed config message." << endl;
        // cout << config_message.DebugString() << endl;

        basePort = config_message.baseport();
        nodeCount = config_message.nodecount();

        sockets = vector<int>(nodeCount, 0);

        for(int i = 0; i < nodeCount; i++) {
            roles.push_back(config_message.roles(i));
            addresses.push_back(config_message.addresses(i));
            basePorts.push_back(config_message.baseports(i));
        }

        if(config_message.outgoingdosign()) {
            outgoing_do_sign = true;

            // rsa = createPrivateRSA();
            createMACKeysNonces(nodeCount);
        }

        listen_for_connections();
    } else {
        cout << "Error parsing config message" << endl;
    }

    ucxClient.register_callback(receiveConn, 1);

    return UCS_OK;
}

int main(int argc, char *argv[]) {
    // Verify that the version of the library that we linked against is
    // compatible with the version of the headers we compiled against.
    GOOGLE_PROTOBUF_VERIFY_VERSION;

	if(argc < 2) {
		printf("Insufficient arguments, need [HOST_PORT]\n");
		return -1;
	}

    ucx_client client;
    ucxClient = client;

	ucxClient.init_conn(atoi(argv[1]));
    ucxClient.register_callback(receiveInit, 0);
	
	ucxClient.progress_worker();
}