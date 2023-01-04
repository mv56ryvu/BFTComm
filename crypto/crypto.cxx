#include "crypto.h"

string privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF"
"NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F"
"UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB"
"AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA"
"QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK"
"kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg"
"f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u"
"412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc"
"mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7"
"kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA"
"gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW"
"G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI"
"7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==\n"
"-----END RSA PRIVATE KEY-----";

vector<unsigned char*> MACKeys;
vector<unsigned char*> MACNonces;

RSA* createPrivateRSA() {
    RSA *rsa = NULL;
    const char* c_string = privateKey.c_str();
    BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio==NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    
    return rsa;
}

// TODO: Generalize for other nodes than 0
void createMACKeysNonces(int nodeCount) {
    string basePhrase = "passphrasewhichneedstobe32bytes!";

    for(int i = 0; i < nodeCount; i++) {
        unsigned char* charArray = (unsigned char*) malloc(basePhrase.size());
        memcpy(charArray, basePhrase.data(), basePhrase.size());
        charArray[0] = i; // + myId
        MACKeys.push_back(charArray);
    }

    for(int i = 0; i < nodeCount; i++) {
        unsigned char* charArray = (unsigned char*) malloc(12);
        for(int j = 0; j < 12; j++) {
            charArray[j] = i; // + myId
        }
        MACNonces.push_back(charArray);
    }
}

int mac_sign(int targetNode, unsigned char *hash, int hash_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char tag[16];

    memcpy(ciphertext, MACNonces[targetNode], 12);
    ciphertext_len = 12;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error initializing context\n");
        return -1;
    }

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("Error initializing encryption\n");
        return -1;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, MACKeys[targetNode], MACNonces[targetNode])) {
        printf("Error initializing\n");
        return -1;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext + 12, &len, hash, hash_len)) {
        printf("Error providing message\n");
        return -1;
    }
    ciphertext_len += len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) {
        printf("Error finalizing encryption\n");
        return -1;
    }
        
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &tag)) {
        printf("Error getting tag\n");
        return -1;
    }

    memcpy(ciphertext + ciphertext_len, tag, 16);
    ciphertext_len += 16;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

unsigned int RSASign(RSA* rsa, unsigned char* digest, unsigned int digest_len, unsigned char** sigret) {
    unsigned int sig_len;

    RSA_sign(NID_sha256, digest, digest_len, *sigret, &sig_len, rsa);

    return sig_len;
}

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}