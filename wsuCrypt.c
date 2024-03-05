/*
Author: Mellanie Martin
Class: CS 427 - Cryptography & Network Security
Date: 2/24/23
*/

# include <stdio.h>
# include <string.h>
# include <fcntl.h>
# include <unistd.h>

# define BUFF_SIZE 1024

int encrypt(char *key, char *pTxt);
int decrypt(char *key, char *cTxt);

int main (int argc, char **argv) {

    if (argc > 8 || argc < 8) {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
    }

    int flag;
    if (strcmp(argv[1], "-e") == 0) {
        encryption(argv[3], argv[5], flag);
    } else if (strcmp(argv[1], "-d") == 0) {
        decryption(argv[3], argv[5], flag);
    } else {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
        return -1;
    }

    return 0;
}

int encrypt(char *key, char *pTxt) {

    char txtBuffer[BUFF_SIZE];
    char keyBuffer[16];
    int input;
    int fd;

    if ((fd = open(pTxt, O_RDONLY)) == -1) return -1; //error
    int i = 0; // read in pTxt
    while (1) {
        input = read(0, &txtBuffer[i], 1);
        if (input <= 0) { // EOF
            txtBuffer[i] = '\0';
            break;
        }
        i++;
    }
    close(fd);

    if ((fd = open(key, O_RDONLY)) == -1) return -1; //error
    int j = 0; // read in key
    while (1) {
        input = read(0, &keyBuffer[i], 1);
        if (input <= 0) { // EOF
            txtBuffer[i] = '\0';
            break;
        }
        j++;
    }
    close(fd);

    int length = strlen(txtBuffer);
    if ((length - 1) % 16 != 0) { // padding necessary
        int paddedLen = length + (16 - (input % 16));
        for (i; i < paddedLen; i++) {
            txtBuffer[i] = '0';
        }
        txtBuffer[i] = '\0';
    }
    int pTxtLen = i;

    int numBlocks = pTxtLen/16;
    for (int k = 0; k < pTxtLen; k += 16) { // main encryption loop, send block to blockSplit, encrypt

    }
}

int decrypt(char *key, char *cTxt) {
    // read in key + generate sub keys, store in reverse to be used in reverse
    // read in cTxt
}

int blockSplit(char *block, char *key) {
    int input;
    char block[8][4]; // first 4 items = words, last 4 = subkeys. 8, 4-char (16 bit) blocks

}

int GFunction() {

}

int *FFunction() {

}

int keyScheduler(int x, int flag) { // flag = 0 for encryption, = 1 for decryption

}

int fTable() {

}