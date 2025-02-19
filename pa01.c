
/*============================================================================
|   Assignment:  pa01 - Encrypting a plaintext file using the Hill cipher
|
|   Author:  Jeremy Ballard
|   Language: c
|
|   To Compile:  gcc -o pa01 pa01.c
|
|
|   To Execute:  c   -> ./pa01 kX.txt pX.txt
|
|
|       Note:
|               All input files are simple 8 bit ASCII input
|               All execute commands above have been tested on Eustis
|
|        Class:  CIS3360 - Security in Computing - Fall 2023
|   Instructor:  McAlpin
|     Due Date:  10/8/23
 +===========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


// function deals with getting through each block of plaintext until the end
int *numArrayReturn(int *holdBlock, int plaintextIndex, int *intCharArray, int dimension){
    int j = 0;
    for (int i = 0 + plaintextIndex; i < plaintextIndex + dimension + 1; i++)
    {
        if (j - 1 == dimension){ //helps get block size exactly before returning block size array
            break;
        }
        holdBlock[j] = intCharArray[plaintextIndex + j]; // ptr holds each block of plaintext temporarily (freed in matrix math loops)
        j++;
    }
    return holdBlock;
}


int main(int argc, char **argv) {


    int dimension = 0; // block size and dimension size
    int **keyPtr = NULL; // double pointer for 2d dynamic array; will hold key file ints


    // input for key text file
    int b; // current position in text file
    char *fname = argv[1]; \
    FILE *file = fopen(fname, "r");
    if(file == 0)
    {
        printf("File could not be opened successfully.");
    }

    // store first int of key array for (block) size
    while (fscanf(file, "%d", &b) != EOF)
    {
        dimension = b;
        break;
    }
    fclose(file);


    // number of indices in key matrix
    int keySize = dimension* dimension;


    file = fopen(fname, "r");
    if(file == 0)
    {
        printf("File could not be opened successfully.");
    }

    // 2d array for key.text integers
    keyPtr = (int**)malloc(keySize * sizeof(int *));
    for (int k = 0; k < dimension; k++) {
        keyPtr[k] = (int*)malloc(keySize * sizeof(int));
    }


    int *intPtr = malloc(keySize * sizeof(int)); // holds values temporarily; will be put in 2d matrix array
    int skipCounter = 0; // counter to help put key file ints in array


    // hold key int values in array temporarily
   while (fscanf(file, "%d", &b) != EOF){
       if(skipCounter == 0)
       {
           skipCounter++;
           continue;
       }
       // skip first file number (matrix size); start in actual key matrix
       else {
           intPtr[skipCounter - 1] = b;
           skipCounter++;
       }
   }

    fclose(file);


   // put values from key text file (currently in intPtr) into 2d array
   int counter = 0;
   for (int y = 0; y < dimension; y++)
   {
       for(int z = 0; z < dimension; z++){
           keyPtr[y][z] = intPtr[counter];
           counter++;
       }
   }



    char *lowerCaseArray = malloc(10000 * sizeof(char)); // hold plaintext array
    int plainTextSize= 0; // helps with storing plaintext in array (also size of array to help with iteration)
    char a; // temp hold chars from text file


    // plaintext file input from cmd line
    fname = argv[2];
    file = fopen(fname, "r");
    while ((a = fgetc(file)) != EOF) {

        // check if current character in file is alphabetic
        if ((a >= 'A' && a <= 'Z') || (a >= 'a' && a <= 'z')) {

            // set current array[index] to alphabetic char
            lowerCaseArray[plainTextSize] = a;

            // check for an uppercase chars to lower
            if (lowerCaseArray[plainTextSize] >= 'A' && lowerCaseArray[plainTextSize] <= 'Z')
            {
                lowerCaseArray[plainTextSize] = tolower(lowerCaseArray[plainTextSize]);
            }
            plainTextSize++;
        }
    }



    // pad plaintext according to block size
    while (plainTextSize % dimension != 0) {
        char pad [2]= "x";
        strcat(lowerCaseArray, pad);
        plainTextSize++;
    }
    // don't forget about null terminator
    lowerCaseArray[plainTextSize] = '\0';
    fclose(file);



    // convert string to 0-26 integer; put in array to do math with (convert back at end for ciphertexts)
    int *tempIntChar = malloc(plainTextSize * sizeof(int));

    for(int p = 0; p < plainTextSize; p++)
    {
        if (lowerCaseArray[p] >= 'a' && lowerCaseArray[p] <= 'z')
        {
            tempIntChar[p] = lowerCaseArray[p] - 97;

        }
    }


    // store encrypted ints (change to chars later)
    int *cipherTextArray = malloc(plainTextSize * sizeof(int));
    // hold accumulated values to mod for ciphered data
    int tempHold = 0;
    //hold index for ciphertext array
    int currentIndex = 0;
    //index of plaintext
    int currentPlainIndex = 0;


    // *tempIntChar (holds ints (0-25) of plaintext chars)  | **keyPtr (holds int matrix from key)  | *cipherTextArray (holds encrypted ints)

    // matrix math for ciphertext
    for(int i = 1; i <= plainTextSize; i += dimension) {
        int *tempIntArray = malloc(dimension * sizeof(int)); // will hold block of plaintext temporarily (then go to next after loops)
        tempIntArray = numArrayReturn(tempIntArray, currentPlainIndex, tempIntChar, dimension);
        for (int j = 0; j < dimension; j++) {
            tempHold = 0;
            for (int k = 0; k < dimension; k++) {
                tempHold = tempHold + (keyPtr[j][k] * tempIntArray[k]);
            }
            cipherTextArray[currentIndex] = tempHold % 26;
            currentIndex++;
        }
        currentPlainIndex+=dimension;
        free(tempIntArray);
    }



    printf("\nKey matrix:"); // print out values in key matrix
    for (int i = 0; i < dimension; i++) {
        for (int j = 0; j < dimension; j++) {
            if (j % dimension == 0) {
                printf("\n");
            }
            printf("%4d", keyPtr[i][j]);
        }
    }



    printf("\n\nPlaintext:");
    // 80 chars per line
    for(int z = 0; z < plainTextSize; z++)
    {
        if (z % 80 == 0) {
            printf("\n%c", lowerCaseArray[z]);
        }
        else
        {
            printf("%c",lowerCaseArray[z]);
        }
    }


    // print out lower case letters ( +97 for 'a')
    printf("\n\nCiphertext:");
    for(int z = 0; z < plainTextSize; z++)
    {
        if (z % 80 == 0) {
            printf("\n%c", cipherTextArray[z] + 97);
        }
        else
        {
            printf("%c",cipherTextArray[z] + 97);
        }
    }
    printf("\n");


    // free all dynamic array memory
    free(cipherTextArray);
    free(tempIntChar);
    free(lowerCaseArray);
    free(intPtr);
    for(int i = 0; i < dimension; i++){
        free(keyPtr[i]);
    }
    free(keyPtr);

    return 0;
}


/*=============================================================================
 |     I [Jeremy Ballard] ([je666112]) affirm that this program is
 | entirely my own work and that I have neither developed my code together with
 | any another person, nor copied any code from any other person, nor permitted
 | my code to be copied  or otherwise used by any other person, nor have I
 | copied, modified, or otherwise used programs created by others. I acknowledge
 | that any violation of the above terms will be treated as academic dishonesty.
 +=============================================================================*/
