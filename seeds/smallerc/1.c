#include <stdio.h>
int main() {
    int a,b,c;
    scanf("%d %d %d",&a, &b, &c);
    char s [10];
    if (a > 10 && b < 5 && c>8) {
        puts("OK");
        gets(s);
    }
    else {
        puts("OK");
        puts(s);
    }
    return 0;
}
