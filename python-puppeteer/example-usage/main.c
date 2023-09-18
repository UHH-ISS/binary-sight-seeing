#include <stdio.h>
#include <string.h>

void xorWithKey(char *input, const char *key) {
    int inputLength = strlen(input);
    int keyLength = strlen(key);

    for (int i = 0; i < inputLength; i++) {
        char originalChar = input[i];
        char xorChar = key[i % keyLength]; // Repeating key

        char resultChar = originalChar ^ xorChar;
        input[i] = resultChar;
    }
}

void printHex(const char *string, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02X ", (unsigned char)string[i]);
    }
    printf("\n");
}

int main() {
    char input[100]; // Assuming the input string won't exceed 100 characters
    printf("Enter a string: ");
    fgets(input, sizeof(input), stdin);

    // Remove the newline character at the end of the input
    int inputLength = strlen(input);
    input[strcspn(input, "\n")] = '\0';

    char xorKey[] = "acsac";

    printf("Original string: %s\n", input);
    printf("Original string as Hex: ");
    printHex(input, inputLength);

    xorWithKey(input, xorKey);

    printf("XORed string: %s\n", input);
    printf("XORed string as Hex: ");
    printHex(input, inputLength);

    return 0;
}