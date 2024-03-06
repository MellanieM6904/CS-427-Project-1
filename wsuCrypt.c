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
char **blockSplit(char *block);
char **keySplit(char *wholeKey);

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
    char keyBuffer[17];
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

    // PADDING INPUT
    int length = strlen(txtBuffer);
    if ((length - 1) % 16 != 0) { // padding necessary
        int paddedLen = length + (16 - (input % 16));
        for (i; i < paddedLen; i++) {
            txtBuffer[i] = '0';
        }
        txtBuffer[i] = '\0';
    }
    int pTxtLen = i;

    // SPLITTING KEYS 
    char keys[4][4] = keySplit(keyBuffer); // array with k0, k1, k2, k3

    // MAIN ENCRYPTION LOOP
    int numBlocks = pTxtLen/16;
    for (i = 0; i < numBlocks; i++) { // for each block
        char block[16];
        for (int k = 0; k < 16; k ++) {
            block[k] = txtBuffer[i*16 + k];
        }
        char words[4][4] = blockSplit(block);
    }

    //TESTING
    printf("WORDS:\nw0: %s\nw1: %s\nw2: %s\nw3: %s", words[0], words[1], words[2], words[3]);
    printf("KEYS:\nk0: %s\nk1: %s\nk2: %s\nk3: %s", keys[0], keys[1], keys[2], keys[3]);
}

int decrypt(char *key, char *cTxt) {
    // read in key + generate sub keys, store in reverse to be used in reverse
    // read in cTxt
}

char **blockSplit(char *block) {
    
    char words[4][4]; // words; 4, 4-char (16 bit) blocks
    int k = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            words[i][j] = block[k];
            k++;
        }
    }

    return words;
}

char **keySplit(char *wholeKey) {

    char keys[4][4] // keys; 4, 4-char (16 bit) keys. 2 Hex values in each key
    int k = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            words[i][j] = wholeKey[k];
            k++;
        }
    }

    return keys;
}

int GFunction() {

}

int *FFunction() {

}

int keyScheduler(int x, int flag) { // flag = 0 for encryption, = 1 for decryption

}

int fTable() {

}