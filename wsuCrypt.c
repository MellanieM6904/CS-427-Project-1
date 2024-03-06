/*
Author: Mellanie Martin
Class: CS 427 - Cryptography & Network Security
Date: 2/24/23
*/

# include <stdio.h>
# include <string.h>
# include <fcntl.h>
# include <unistd.h>
# include <stdlib.h>

# define BUFF_SIZE 1024

int e(char *key, char *pTxt);
int d(char *key, char *cTxt);
char **blockSplit(char *block, char **words);
char **keySplit(char *wholeKey, char **keys);

int main (int argc, char **argv) {

    if (argc > 8 || argc < 8) {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
    }

    int flag;
    if (strcmp(argv[1], "-e") == 0) {
        e(argv[3], argv[5]);
    } else if (strcmp(argv[1], "-d") == 0) {
        d(argv[3], argv[5]);
    } else {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
        return -1;
    }

    return 0;
}

int e(char *key, char *pTxt) {

    char txtBuffer[BUFF_SIZE];
    char keyBuffer[17];
    int input;
    int fd;

    if ((fd = open(pTxt, O_RDONLY)) == -1) return -1; //error
    int i = 0; // read in pTxt
    while (1) {
        input = read(fd, &txtBuffer[i], 1);
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
        input = read(fd, &keyBuffer[j], 1);
        if (input <= 0) { // EOF
            keyBuffer[j] = '\0';
            break;
        }
        j++;
    }
    close(fd);
    printf("KEY: %s\n", keyBuffer);

    // PADDING INPUT
    int length = strlen(txtBuffer);
    if (length % 16 != 0) { // padding necessary
        int paddedLen = length + (16 - (input % 16));
        for (i; i < paddedLen; i++) {
            txtBuffer[i] = '0';
        }
        txtBuffer[i] = '\0';
    }
    int pTxtLen = i;

    printf("BLOCK: %s\n", txtBuffer);
    

    // SPLITTING KEYS 
    char **keys = (char **)malloc(4 * sizeof(char *));
    for (i = 0; i < 4; i++) keys[i] = (char *)malloc(4 * sizeof(char));
    int binaryKeys[4][16];
    int binaryConversion[14][4] = {0000, 0001, 0010, 0011, 0100, 0101, 0110, 0111,
                                1000, 1001, 1010, 1011, 1100, 1101, 1110, 1111};

    keys = keySplit(keyBuffer, keys); // array with k0, k1, k2, k3
    printf("KEYS:\nk0: %s\nk1: %s\nk2: %s\nk3: %s\n", keys[0], keys[1], keys[2], keys[3]);

    for (int i = 0; i < 4; i++) {
        int k = 0;  // Reset k to zero for each row

        for (int j = 0; j < 4; j++) {
            // Convert each hex character to binary and append to binaryWords[i]
            unsigned char hexValue = keys[i][j];
            sprintf(binaryKeys[i] + k, "%04d", hexValue - '0');
            k += 4;
        }

        binaryKeys[i][16] = '\0'; // Null-terminate the binary string
    }

    // MAIN ENCRYPTION LOOP
    int numBlocks = pTxtLen/16;
    for (i = 0; i <= numBlocks; i++) { // for each block

        char **words = (char **)malloc(4 * sizeof(char *));
        for (int k = 0; k < 4; k++) words[k] = (char *)malloc(4 * sizeof(char));

        int block[16];
        for (int k = 0; k < 16; k ++) {
            block[k] = txtBuffer[i*16 + k];
        }
        words = blockSplit(txtBuffer, words);
        char binaryWords[4][16];

        for (int i = 0; i < 4; i++) {
        int k = 0;  // Reset k to zero for each row

        for (int j = 0; j < 4; j++) {
            // Convert each hex character to binary and append to binaryWords[i]
            unsigned char hexValue = words[i][j];
            sprintf(binaryWords[i] + k, "%04d", hexValue - '0');
            k += 4;
        }

        binaryWords[i][16] = '\0'; // Null-terminate the binary string
    }

        //TESTING
        printf("WORDS:\nw0: %s\nw1: %s\nw2: %s\nw3: %s\n", words[0], words[1], words[2], words[3]);

        // WHITENING
        int R0[16], R1[16], R2[16], R3[16];
        for (int k = 0; k < 64; k++) {
            R0[k] = binaryWords[0][k] ^ binaryKeys[0][k];
            R1[k] = binaryWords[1][k] ^ binaryKeys[1][k];
            R2[k] = binaryWords[2][k] ^ binaryKeys[2][k];
            R3[k] = binaryWords[3][k] ^ binaryKeys[3][k];
        }
        printf("AFTER XOR:\n");
        printf("R0: ");
        int i = 0;
        while (i < 16) {
            if (R0[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        }
        printf("\nR1: ");
        i = 0;
        while (i < 16) {
            if (R0[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        }
        printf("\nR2: ");
        i = 0;
        while (i < 16) {
            if (R0[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        }
        printf("\nR3: ");
        i = 0;
        while (i < 16) {
            if (R0[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        }

        //for (int roundNum = 0; roundNum <= 16; roundNum++) {

        //}

        for (int j = 0; j < 4; j++) {
            free(words[j]);
        }
        free(words);
    }

    

    for (int j = 0; j < 4; j++) {
        free(keys[j]);
    }
    free(keys);
}

int d(char *key, char *cTxt) {
    // read in key + generate sub keys, store in reverse to be used in reverse
    // read in cTxt
}

char **blockSplit(char *block, char **words) {
    
    // words; 4, 4-char (16 bit) blocks
    int k = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            words[i][j] = block[k];
            k++;
        }
    }
    return words;
}

char **keySplit(char *wholeKey, char **keys) {

    // keys; 4, 4-char (16 bit) keys. 2 Hex values in each key
    int k = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keys[i][j] = wholeKey[k];
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