/*
Author: Mellanie Martin
Class: CS 427 - Cryptography & Network Security
Date: 2/24/23
*/

# include <stdio.h>
# include <string.h>

int encrypt(char *key, char *pTxt, int flag);
int decrypt(char *key, char *cTxt, int flag);

int main (int argc, char **argv) {

    if (argc > 8 || argc < 8) {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
    }

    int flag;
    if (strcmp(argv[1], "-e") == 0) {
        flag = 0;
        encryption(argv[3], argv[5], flag);
    } else if (strcmp(argv[1], "-d") == 0) {
        flag = 1;
        decryption(argv[3], argv[5], flag);
    } else {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
        return -1;
    }

    return 0;
}

int encrypt(char *key, char *pTxt, int flag) {

}

int decrypt(char *key, char *cTxt, int flag) {

}

int blockSplit(char *key, char *input) {

    char blocks[8][5]; // first 4 items = words, last 4 = subkeys. 8, 4-char (16 bit) blocks

    

}

int GFunction() {

}

int *FFunction() {

}

int keyScheduler(int x) {

}

int fTable() {

}