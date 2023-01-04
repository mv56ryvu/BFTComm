#ifndef UCX_CRYPTO_H
#define UCX_CRYPTO_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>

using std::string;
using std::stringstream;
using std::vector;
using std::hex;
using std::setw;
using std::setfill;

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

RSA* createPrivateRSA();
void createMACKeysNonces(int nodeCount);
int mac_sign(int targetNode, unsigned char *hash, int hash_len, unsigned char *ciphertext);
unsigned int RSASign(RSA* rsa, unsigned char* digest, unsigned int digest_len, unsigned char** sigret);

#endif