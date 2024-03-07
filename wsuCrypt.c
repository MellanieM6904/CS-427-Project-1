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
int hexToBinary(char *hex, int *binArray, int multiple);
int *fTable(int input);

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
        int paddedLen = length + (16 - (length % 16));
        for (i = length; i < paddedLen; i++) {
            txtBuffer[i] = '0';
        }
        txtBuffer[i] = '\0';
    }
    int pTxtLen = i;

    printf("BLOCK: %s\n", txtBuffer);
    

    // SPLITTING KEYS 
    char **keys = (char **)malloc(4 * sizeof(char *));
    for (i = 0; i < 4; i++) keys[i] = (char *)malloc(4 * sizeof(char));
    keys = keySplit(keyBuffer, keys); // array with k0, k1, k2, k3
    printf("KEYS:\nk0: %s\nk1: %s\nk2: %s\nk3: %s\n", keys[0], keys[1], keys[2], keys[3]);

    int K0[16], K1[16], K2[16], K3[16];
    hexToBinary(keys[0], K0, 4);
    hexToBinary(keys[1], K1, 4);
    hexToBinary(keys[2], K2, 4);
    hexToBinary(keys[3], K3, 4);

    printf("K0: ");
    for (int i = 0; i < 16; i++) {
        if (K0[i] & 1)
            printf("1");
        else
            printf("0");
    }
    printf("\n");

    printf("K1: ");
    for (int i = 0; i < 16; i++) {
        if (K1[i] & 1)
            printf("1");
        else
            printf("0");
    }
    printf("\n");

    printf("K2: ");
    for (int i = 0; i < 16; i++) {
        if (K2[i] & 1)
            printf("1");
        else
            printf("0");
    }
    printf("\n");

    printf("K3: ");
    for (int i = 0; i < 16; i++) {
        if (K3[i] & 1)
            printf("1");
        else
            printf("0");
    }
    printf("\n");

    // MAIN ENCRYPTION LOOP
    int numBlocks = pTxtLen/16;
    for (i = 0; i < numBlocks; i++) { // for each block

        char **words = (char **)malloc(4 * sizeof(char *));
        for (int k = 0; k < 4; k++) words[k] = (char *)malloc(4 * sizeof(char));

        char block[16];
        for (int k = 0; k < 16; k ++) {
            block[k] = txtBuffer[i*16 + k];
        }
        words = blockSplit(txtBuffer, words);
        printf("WORDS:\nw0: %s\nw1: %s\nw2: %s\nw3: %s\n", words[0], words[1], words[2], words[3]);

        int W0[16], W1[16], W2[16], W3[16];
        hexToBinary(words[0], W0, 4);
        hexToBinary(words[1], W1, 4);
        hexToBinary(words[2], W2, 4);
        hexToBinary(words[3], W3, 4);

        printf("W0: ");
        for (int i = 0; i < 16; i++) {
            if (W0[i] & 1)
                printf("1");
            else
                printf("0");
        }
        printf("\n");

        printf("W1: ");
        for (int i = 0; i < 16; i++) {
            if (W1[i] & 1)
                printf("1");
            else
                printf("0");
        }
        printf("\n");

        printf("W2: ");
        for (int i = 0; i < 16; i++) {
            if (W2[i] & 1)
                printf("1");
            else
                printf("0");
        }
        printf("\n");

        printf("W3: ");
        for (int i = 0; i < 16; i++) {
            if (W3[i] & 1)
                printf("1");
            else
                printf("0");
        }
        printf("\n");

        // WHITENING
        int R0[16], R1[16], R2[16], R3[16];
        for (int k = 0; k < 16; k++) {
            R0[k] = W0[k] ^ K0[k];
            R1[k] = W1[k] ^ K1[k];
            R2[k] = W2[k] ^ K2[k];
            R3[k] = W3[k] ^ K3[k];
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
            if (R1[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        }
        printf("\nR2: ");
        i = 0;
        while (i < 16) {
            if (R2[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        }
        printf("\nR3: ");
        i = 0;
        while (i < 16) {
            if (R3[i] & 1)
                printf("1");
            else
                printf("0");

            i++;
        } printf("\n");

        for (int roundNum = 0; roundNum <= 16; roundNum++) {

        }

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

int keyScheduler(int x, int flag) { // flag = 0 for encryption, = 1 for decryption

}

int *fTable(int input) {
    char ftable [256][2] =
                {"a3", "d7", "09", "83", "f8", "48", "f6", "f4", "b3", "21", "15", "78", "99", "b1", "af", "f9",
                "e7", "2d", "4d", "8a", "ce", "4c", "ca", "2e", "52", "95", "d9", "1e", "4e", "38", "44", "28",
                "0a", "df", "02", "a0", "17", "f1", "60", "68", "12", "b7", "7a", "c3", "e9", "fa", "3d", "53",
                "96", "84", "6b", "ba", "f2", "63", "9a", "19", "7c", "ae", "e5", "f5", "f7", "16", "6a", "a2",
                "39", "b6", "7b", "0f", "c1", "93", "81", "1b", "ee", "b4", "1a", "ea", "d0", "91", "2f", "b8",
                "55", "b9", "da", "85", "3f", "41", "bf", "e0", "5a", "58", "80", "5f", "66", "0b", "d8", "90",
                "35", "d5", "c0", "a7", "33", "06", "65", "69", "45", "00", "94", "56", "6d", "98", "9b", "76",
                "97", "fc", "b2", "c2", "b0", "fe", "db", "20", "e1", "eb", "d6", "e4", "dd", "47", "4a", "1d",
                "42", "ed", "9e", "6e", "49", "3c", "cd", "43", "27", "d2", "07", "d4", "de", "c7", "67", "18",
                "89", "cb", "30", "1f", "8d", "c6", "8f", "aa", "c8", "74", "dc", "c9", "5d", "5c", "31", "a4",
                "70", "88", "61", "2c", "9f", "0d", "2b", "87", "50", "82", "54", "64", "26", "7d", "03", "40",
                "34", "4b", "1c", "73", "d1", "c4", "fd", "3b", "cc", "fb", "7f", "ab", "e6", "3e", "5b", "a5",
                "ad", "04", "23", "9c", "14", "51", "22", "f0", "29", "79", "71", "7e", "ff", "8c", "0e", "e2",
                "0c", "ef", "bc", "72", "75", "6f", "37", "a1", "ec", "d3", "8e", "62", "8b", "86", "10", "e8",
                "08", "77", "11", "be", "92", "4f", "24", "c5", "32", "36", "9d", "cf", "f3", "a6", "bb", "ac",
                "5e", "6c", "a9", "13", "57", "25", "b5", "e3", "bd", "a8", "3a", "01", "05", "59", "2a", "46"};

    unsigned char row = (input >> 4) & 0x0F;
    unsigned char col = input & 0x0F;
    int index = row * 16 + col;
    char result[2]; 
    result[0] = ftable[index][0];
    result[1] = ftable[index][1];
    int bin[8];
    hexToBinary(result, bin, 2);
    return bin;
}

int *FFunction() {
    
}



int hexToBinary(char *hex, int *binArray, int multiple) {
    for (int i = 0; i < multiple; i++) {
 
        switch (hex[i]) {
        case '0':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            //printf("0000");
            break;
        case '1':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            //printf("0001");
            break;
        case '2':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            //printf("0010");
            break;
        case '3':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            //printf("0011");
            break;
        case '4':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            //printf("0100");
            break;
        case '5':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            //printf("0101");
            break;
        case '6':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            //printf("0110");
            break;
        case '7':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            //printf("0111");
            break;
        case '8':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            //printf("1000");
            break;
        case '9':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            //printf("1001");
            break;
        case 'A':
        case 'a':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            //printf("1010");
            break;
        case 'B':
        case 'b':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            //printf("1011");
            break;
        case 'C':
        case 'c':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            //printf("1100");
            break;
        case 'D':
        case 'd':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            //printf("1101");
            break;
        case 'E':
        case 'e':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            //printf("1110");
            break;
        case 'F':
        case 'f':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            //printf("1111");
            break;
        default:
            printf("\nInvalid hexadecimal digit %c",
                   hex[i]);
        }
    }
    return 0;
}