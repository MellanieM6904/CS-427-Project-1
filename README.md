# CS 427 Project 1
 CS 427 Project 1

Block Encryption Algorithm - WSU-CRYPT, based on the Twofish and SKIPJACK algorithms. Block and key size is 64 bit.
Test vectors.doc is to test encryption/decryption\ of a single block.

Name: Mellanie Martin
Email: mellanie.martin@wsu.edu
Files:
Makefile ; compiles program
wsuCrypt.c ; code

Compile/Run Instructions:
    1. run 'make' to compile ./wsuCrypt
    2. For encryption: ./wsuCrypt -e -k key.txt -in plaintext.txt -out ciphertext.txt
       For decryption: ./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt
NOTE TO GRADER: Mode for the output file is append to allow for several blocks. Make sure to clear the output file between test.