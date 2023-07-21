#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/des.h>

#define PORT 8080
#define SERVER_IP "127.0.0.1"
#define RSA_KEY_LENGTH 2048
#define AES_KEY_LENGTH 8

void generateRSAKeyPair(RSA **rsaPublicKey, RSA **rsaPrivateKey);
void encryptRSAKey(const char *key, RSA *rsaPublicKey, unsigned char *encryptedKey, int *encryptedKeyLength);
void decryptRSAKey(const unsigned char *encryptedKey, int encryptedKeyLength, RSA *rsaPrivateKey, char *decryptedKey);
void encryptDES(const char *message, const char *key, unsigned char *encryptedMessage);
void decryptDES(const unsigned char *encryptedMessage, const char *key, char *decryptedMessage);

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char symmetricKey[AES_KEY_LENGTH + 1];
    char message[256];
    unsigned char encryptedMessage[256 + 8];
    int encryptedKeyLength;

    // Criação do socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Erro ao criar o socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, '\0', sizeof(server_addr));

    // Configuração do endereço do servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Conexão com o servidor
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erro na conexão");
        exit(EXIT_FAILURE);
    }

    // Carregar a chave pública RSA de Bob
    FILE *pubKeyFile = fopen("chave.pub", "rb");
    RSA *rsaPublicKeyBob = PEM_read_RSAPublicKey(pubKeyFile, NULL, NULL, NULL);
    fclose(pubKeyFile);

    // Receber a chave simétrica criptografada de Bob
    recv(sockfd, &encryptedKeyLength, sizeof(int), 0);
    recv(sockfd, message, encryptedKeyLength, 0);

    // Descriptografar a chave simétrica usando a chave privada RSA de Alice
    RSA *rsaPrivateKey;
    generateRSAKeyPair(NULL, &rsaPrivateKey);

    char decryptedKey[AES_KEY_LENGTH + 1];
    decryptRSAKey((unsigned char *)message, encryptedKeyLength, rsaPrivateKey, decryptedKey);

    // Carregar a mensagem a ser enviada para Bob
    printf("Digite a mensagem a ser enviada para Bob: ");
    fgets(message, 256, stdin);

    // Remover a nova linha da entrada
    message[strcspn(message, "\n")] = 0;

    // Criptografar a mensagem usando a chave simétrica
    encryptDES(message, decryptedKey, encryptedMessage);

    // Exibir a mensagem criptografada enviada para Bob
    printf("Mensagem criptografada enviada para Bob: ");
    for (int i = 0; i < strlen((const char *)encryptedMessage); i++) {
        printf("%02x", encryptedMessage[i]);
    }
    printf("\n");

    // Enviar a mensagem criptografada para Bob
    send(sockfd, encryptedMessage, sizeof(encryptedMessage), 0);

    close(sockfd);
    RSA_free(rsaPublicKeyBob);
    RSA_free(rsaPrivateKey);

    return 0;
}

void generateRSAKeyPair(RSA **rsaPublicKey, RSA **rsaPrivateKey) {
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    RSA *rsaKey = RSA_new();
    RSA_generate_key_ex(rsaKey, RSA_KEY_LENGTH, e, NULL);

    if (rsaPublicKey != NULL) {
        *rsaPublicKey = RSAPublicKey_dup(rsaKey);
    }
    if (rsaPrivateKey != NULL) {
        *rsaPrivateKey = RSAPrivateKey_dup(rsaKey);
    }

    BN_free(e);
    RSA_free(rsaKey);
}

void encryptRSAKey(const char *key, RSA *rsaPublicKey, unsigned char *encryptedKey, int *encryptedKeyLength) {
    *encryptedKeyLength = RSA_public_encrypt(AES_KEY_LENGTH, (unsigned char *)key, encryptedKey, rsaPublicKey, RSA_PKCS1_PADDING);
}

void decryptRSAKey(const unsigned char *encryptedKey, int encryptedKeyLength, RSA *rsaPrivateKey, char *decryptedKey) {
    RSA_private_decrypt(encryptedKeyLength, encryptedKey, (unsigned char *)decryptedKey, rsaPrivateKey, RSA_PKCS1_PADDING);
}

void encryptDES(const char *message, const char *key, unsigned char *encryptedMessage) {
    DES_cblock desKey;
    DES_key_schedule keySchedule;
    DES_string_to_key(key, &desKey);
    DES_set_key_unchecked(&desKey, &keySchedule);

    int messageLength = strlen(message);
    DES_ncbc_encrypt((unsigned char *)message, encryptedMessage, messageLength, &keySchedule, &desKey, DES_ENCRYPT);
}

void decryptDES(const unsigned char *encryptedMessage, const char *key, char *decryptedMessage) {
    DES_cblock desKey;
    DES_key_schedule keySchedule;
    DES_string_to_key(key, &desKey);
    DES_set_key_unchecked(&desKey, &keySchedule);

    int messageLength = strlen((const char *)encryptedMessage);
    DES_ncbc_encrypt(encryptedMessage, (unsigned char *)decryptedMessage, messageLength, &keySchedule, &desKey, DES_DECRYPT);
}
