#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define PORT 8080
#define RSA_KEY_LENGTH 2048
#define AES_KEY_LENGTH 8

void generateRSAKeyPair(RSA **rsaPublicKey, RSA **rsaPrivateKey);
void encryptRSAKey(const char *key, RSA *rsaPublicKey, unsigned char *encryptedKey, int *encryptedKeyLength);
void decryptRSAKey(const unsigned char *encryptedKey, int encryptedKeyLength, RSA *rsaPrivateKey, char *decryptedKey);
void encryptDES(const char *message, const char *key, unsigned char *encryptedMessage);
void decryptDES(const unsigned char *encryptedMessage, const char *key, char *decryptedMessage);

int main() {
    int sockfd, new_sock;
    struct sockaddr_in server_addr, new_addr;
    socklen_t addr_size;
    char symmetricKey[AES_KEY_LENGTH + 1];
    char message[256];
    unsigned char encryptedMessage[256 + 8];

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
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Bind do socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erro no binding");
        exit(EXIT_FAILURE);
    }

    printf("Servidor conectado...\n");

    // Ouvir por conexões
    if (listen(sockfd, 10) == 0) {
        printf("Ouvindo...\n");
    } else {
        perror("Erro ao ouvir");
        exit(EXIT_FAILURE);
    }

    // Aceitar conexão
    addr_size = sizeof(new_addr);
    new_sock = accept(sockfd, (struct sockaddr *)&new_addr, &addr_size);

    // Gerar par de chaves RSA
    RSA *rsaPublicKey;
    RSA *rsaPrivateKey;
    generateRSAKeyPair(&rsaPublicKey, &rsaPrivateKey);

    // Enviar chave pública RSA para Alice
    FILE *pubKeyFile = fopen("chave.pub", "wb");
    PEM_write_RSAPublicKey(pubKeyFile, rsaPublicKey);
    fclose(pubKeyFile);

    // Carregar a chave pública RSA de Alice
    FILE *pubKeyFile2 = fopen("chave.pub", "rb");
    RSA *rsaPublicKeyAlice = PEM_read_RSAPublicKey(pubKeyFile2, NULL, NULL, NULL);
    fclose(pubKeyFile2);

    // Criptografar chave simétrica usando a chave pública RSA de Alice
    encryptRSAKey(symmetricKey, rsaPublicKeyAlice, (unsigned char *)message, (int *)&addr_size);

    // Enviar a chave simétrica criptografada para Alice
    send(new_sock, &addr_size, sizeof(int), 0);
    send(new_sock, message, addr_size, 0);

    // Receber a mensagem criptografada de Alice
    recv(new_sock, encryptedMessage, sizeof(encryptedMessage), 0);

    // Descriptografar a mensagem usando a chave simétrica
    char decryptedMessage[256];
    decryptDES(encryptedMessage, symmetricKey, decryptedMessage);

    // Exibir a mensagem descriptografada
    printf("Mensagem descriptografada: %s\n", decryptedMessage);

    close(new_sock);
    close(sockfd);
    RSA_free(rsaPublicKey);
    RSA_free(rsaPrivateKey);

    return 0;
}

void generateRSAKeyPair(RSA **rsaPublicKey, RSA **rsaPrivateKey) {
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    RSA *rsaKey = RSA_new();
    RSA_generate_key_ex(rsaKey, RSA_KEY_LENGTH, e, NULL);

    *rsaPublicKey = RSAPublicKey_dup(rsaKey);
    *rsaPrivateKey = RSAPrivateKey_dup(rsaKey);

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

     printf("Mensagem criptografada recebida de Alice: ");
    for (int i = 0; i < strlen((const char *)encryptedMessage); i++) {
        printf("%02x", encryptedMessage[i]);
    }
    printf("\n");
}
