#include <stdio.h>
#include <stdlib.h>

int main() {
        char *arr = malloc(5 * sizeof(char));

        printf("%c\n", arr[10]);

        return 0;
}
