/*
Author: Mellanie Martin
Class: CS 427 - Cryptography & Network Security
Date: 3/9/23
*/

# include <stdio.h>
# include <string.h>
# include <fcntl.h>
# include <unistd.h>
# include <stdlib.h>

# define BUFF_SIZE 1024

int e(char *key, char *pTxt, char *cTxt, int flag);
char **blockSplit(char *block, char **words);
char **keySplit(char *wholeKey, char **keys);
int hexToBinary(char *hex, int *binArray, int multiple);
int fTable(int input);
int leftRotate(int *key);
int rightRotate(int *key);
int keyScheduler(int x, int keyNum, int *key, int (*subkeys)[8]);
int *F(int R0, int R1, int *F0, int *F1, int subkeys[12][8]);
int G(int word, int k0, int k1, int k2, int k3);

int main (int argc, char **argv) {

    if (argc > 8 || argc < 8) {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
    }

    int flag;
    if (strcmp(argv[1], "-e") == 0) {
        e(argv[3], argv[5], argv[7], 0); // 0 for encryption
    } else if (strcmp(argv[1], "-d") == 0) {
        e(argv[3], argv[5], argv[7], 1); // 1 for decryption
    } else {
        printf("Improper use. Run using:\n[ENCRYPTION] ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n[DECRYPTION] ./wsuCrypt -d -k key.txt -in ciphertext.txt -out plaintext.txt");
        return -1;
    }

    return 0;
}

// main encryption/decryption function. Top level- handles what would be more difficult to do in following functions, and passes values between functions
int e(char *key, char *pTxt, char *cTxt, int flag) {

    char txtBuffer[BUFF_SIZE];
    char keyBuffer[17];
    int input;
    int fd;

    // READ IN PLAINTEXT
    if ((fd = open(pTxt, O_RDONLY)) == -1) return -1; //error
    int i = 0;
    while (1) {
        input = read(fd, &txtBuffer[i], 1);
        if (input <= 0) { // EOF
            txtBuffer[i] = '\0';
            break;
        }
        i++;
    }
    close(fd);

    // READ IN KEY
    if ((fd = open(key, O_RDONLY)) == -1) return -1; //error
    int j = 0;
    while (1) {
        input = read(fd, &keyBuffer[j], 1);
        if (input <= 0) { // EOF
            keyBuffer[j] = '\0';
            break;
        }
        j++;
    }
    close(fd);
    //printf("KEY: %s\n", keyBuffer);

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

    //printf("BLOCK: %s\n", txtBuffer);

    // SPLITTING KEY
    char **keys = (char **)malloc(4 * sizeof(char *));
    for (i = 0; i < 4; i++) keys[i] = (char *)malloc(4 * sizeof(char));
    keys = keySplit(keyBuffer, keys); // array with k0, k1, k2, k3
    //printf("KEYS:\nk0: %s\nk1: %s\nk2: %s\nk3: %s\n", keys[0], keys[1], keys[2], keys[3]);

    int K0[16], K1[16], K2[16], K3[16]; // binary equivalents
    hexToBinary(keys[0], K0, 4);
    hexToBinary(keys[1], K1, 4);
    hexToBinary(keys[2], K2, 4);
    hexToBinary(keys[3], K3, 4);

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
        //printf("WORDS:\nw0: %s\nw1: %s\nw2: %s\nw3: %s\n", words[0], words[1], words[2], words[3]);

        int W0[16], W1[16], W2[16], W3[16];
        hexToBinary(words[0], W0, 4);
        hexToBinary(words[1], W1, 4);
        hexToBinary(words[2], W2, 4);
        hexToBinary(words[3], W3, 4);

        // WHITENING
        int R0[16], R1[16], R2[16], R3[16];
        for (int k = 0; k < 16; k++) {
            R0[k] = W0[k] ^ K0[k];
            R1[k] = W1[k] ^ K1[k];
            R2[k] = W2[k] ^ K2[k];
            R3[k] = W3[k] ^ K3[k];
        }
        int r0 = 0, r1 = 0, r2 = 0, r3 = 0; // for later use
        for (int i = 0; i < 16; i++) {
            r0 = (r0 << 1) | R0[i];
            r1 = (r1 << 1) | R1[i];
            r2 = (r2 << 1) | R2[i];
            r3 = (r3 << 1) | R3[i];
        }  //printf("r0: %x | r1: %x | r2: %x | r3: %x\n", r0, r1, r2, r3);
        int k0 = 0, k1 = 0, k2 = 0, k3 = 0; // for later use
        for (int i = 0; i < 16; i++) {
            k0 = (k0 << 1) | K0[i];
            k1 = (k1 << 1) | K1[i];
            k2 = (k2 << 1) | K2[i];
            k3 = (k3 << 1) | K3[i];
        }

        // binary rep of key
        int key[64];
        hexToBinary(keyBuffer, key, 16);
        for (int roundNum = 0; roundNum < 16; roundNum++) {
            //printf("ROUND %d:\n", roundNum);
            // GENERATE SUBKEYS - rotate key[64] and call key scheduler
            int subkeys[12][8]; // k0-k11, each 1 byte long (8 bits)
            if (flag == 0) {
                int keyNum = 0;
                for (int j = 0; j < 3; j++) {
                    for (int k = 0; k < 4; k++) {
                        leftRotate(key);
                        keyScheduler(4*roundNum + k, keyNum, key, subkeys);
                        keyNum++;
                    }
                }
            } else {
                int keyNum = 11;
                for (int j = 0; j < 3; j++) {
                    for (int k = 0; k < 4; k++) {
                        leftRotate(key);
                        keyScheduler(4*roundNum + k, keyNum, key, subkeys);
                        //leftRotate(key);
                        keyNum--;
                    }
                }
            }

            // F FUNCTION
            int F0, F1;
            F(r0, r1, &F0, &F1, subkeys);
            //printf("F0: %x | F1: %x\n", F0, F1);

            // PREP VALS FOR NEXT ROUND
            int temp, temp2;
            if (flag == 0) {
                temp = (r2 ^ F0);// >> 1;
                temp = (temp >> 1) | (temp << 15) % 65536;
                temp2 = ((r3 << 1) | (r3 >> 15)) % 65536;
                temp2 = temp2 ^ F1;
            }
            if (flag == 1) {
                temp = (((r2 << 1) | (r2 >> 15)) % 65536) ^ F0;
                temp2 = (r3 ^ F1); 
                temp2 = (temp2 >> 1) | (temp2 << 15) % 65536;
            }
            r2 = r0;
            r3 = r1;
            r1 = temp2;
            r0 = temp;
            //printf("r0: %x | r1: %x | r2: %x | r3: %x\n", r0, r1, r2, r3);
        }

        int y0 = r2, y1 = r3, y2 = r0, y3 = r1;
        int C0 = (y0 ^ k0);
        int C1 = (y1 ^ k1);
        int C2 = (y2 ^ k2);
        int C3 = (y3 ^ k3);

        FILE *fp = fopen(cTxt, "a");
        fprintf(fp, "%x", C0);
        fprintf(fp, "%x", C1);
        fprintf(fp, "%x", C2);
        fprintf(fp, "%x", C3);
        fclose(fp);

        for (int j = 0; j < 4; j++) {
            free(words[j]);
        }
        free(words);
    }

    for (int j = 0; j < 4; j++) {
        free(keys[j]);
    }
    free(keys);
    return 0;
}

// splits blocks into 4 16 bit words
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
// splits key into 4 16 bit keys
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
// G FUNCTION - as outlined in specs. Takes keys and a word, and outputs values for F FUNCTION
int G(int word, int k0, int k1, int k2, int k3) {
    int g1 = word >> 8; 
    int g2 = word & 0xFF;
    int g3 = fTable(g2 ^ k0) ^ g1;
    int g4 = fTable(g3 ^ k1) ^ g2;
    int g5 = fTable(g4 ^ k2) ^ g3;
    int g6 = fTable(g5 ^ k3) ^ g4;

    int res = (g5 << 8) | g6;
    //printf("g1: %x | g2: %x | g3: %x | g4: %x | g5: %x| g6: %x\n", g1, g2, g3, g4, g5, g6);
    return res;
}
// generates subkeys
int keyScheduler(int x, int keyNum, int *key, int (*subkeys)[8]) {
    int byteIndex = (7 - (x % 8))*8; // loc of first bit of target byte, w bytes indexed from right to left
    for (int i = 0; i < 8; i++) {
        subkeys[keyNum][i] = key[byteIndex + i];
    }
    return 0;
}
// given a hex value, returns the corresponding value in FTable lookup table
int fTable(int input) {
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
    int res = 0;
    for (int i = 0; i < 8; i++) {
        res = (res << 1) | bin[i];
    }
    return res;
}
// F FUNCTION - as outlined in specs. Calls G FUNCTION twice, 'returns' F0 and F1
int *F(int R0, int R1, int *F0, int *F1, int subkeys[12][8]) {
    int k0 = 0, k1 = 0, k2 = 0, k3 = 0, k4 = 0, k5 = 0, k6 = 0, k7 = 0, k8 = 0, k9 = 0, k10 = 0, k11 = 0;
    for (int i = 0; i < 8; i++) {
        k0 = (k0 << 1) | subkeys[0][i];
        k1 = (k1 << 1) | subkeys[1][i];
        k2 = (k2 << 1) | subkeys[2][i];
        k3 = (k3 << 1) | subkeys[3][i];
        k4 = (k4 << 1) | subkeys[4][i];
        k5 = (k5 << 1) | subkeys[5][i];;
        k6 = (k6 << 1) | subkeys[6][i];
        k7 = (k7 << 1) | subkeys[7][i];
        k8 = (k8 << 1) | subkeys[8][i];
        k9 = (k9 << 1) | subkeys[9][i];;
        k10 = (k10 << 1) | subkeys[10][i];
        k11 = (k11 << 1) | subkeys[11][i];
    } //printf("k0: %x | k1: %x | k2: %x | k3: %x | k4: %x | k5: %x | k6: %x | k7: %x | k8: %x | k9: %x | k10: %x | k11: %x\n", k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11);
    int T0 = G(R0, k0, k1, k2, k3);
    int T1 = G(R1, k4, k5, k6, k7);
    //printf("T0: %x | T1: %x\n", T0, T1);
    *F0 = (T0 + 2*T1 + ((k8 << 8) | k9)) % 65536;
    *F1 = (2*T0 + T1 + ((k10 << 8) | k11)) % 65536;
    return 0;
}
// Rotates an array of bits left
int leftRotate(int *key) {
    int i, head;
    head = key[0];
    for (i = 0; i < 64 - 1; i++) {
        key[i] = key[i + 1];
    }
    key[i] = head; // circular rotation
    return 0;
}
// Rotates an array of bits right
int rightRotate(int *key) {
    int i, tail;
    tail = key[64];
    for (i = 64; i > 0; i--) {
        key[i] = key[i - 1];
    }
    key[i] = tail; // circular rotation
    return 0;
}
// Converts an array of hex values to an array of binary bits
int hexToBinary(char *hex, int *binArray, int multiple) {
    for (int i = 0; i < multiple; i++) {
 
        switch (hex[i]) {
        case '0':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            break;
        case '1':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            break;
        case '2':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            break;
        case '3':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            break;
        case '4':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            break;
        case '5':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            break;
        case '6':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            break;
        case '7':
            binArray[0 + 4*i] = 0;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            break;
        case '8':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            break;
        case '9':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            break;
        case 'A':
        case 'a':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            break;
        case 'B':
        case 'b':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 0;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            break;
        case 'C':
        case 'c':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 0;
            break;
        case 'D':
        case 'd':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 0;
            binArray[3 + 4*i] = 1;
            break;
        case 'E':
        case 'e':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 0;
            break;
        case 'F':
        case 'f':
            binArray[0 + 4*i] = 1;
            binArray[1 + 4*i] = 1;
            binArray[2 + 4*i] = 1;
            binArray[3 + 4*i] = 1;
            break;
        case '\0':
            return 0; // end of a null terminated buffer
        default:
            printf("\nInvalid hex value %c",
                   hex[i]);
        }
    }
    return 0;
}