#include <stdio.h>

int recursive_fibonacci(int n) {
    if (n <= 1) {
        return n;
    } else {
        return recursive_fibonacci(n - 1) + recursive_fibonacci(n - 2);
    }
}

// iterative_fibonacci
int func0(int n) {
    int a = 0, b = 1, c, i;
    if (n <= 1) {
        return n;
    }
    for (i = 2; i <= n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return b;
}

int main() {
    int n = 10;
    printf("Recursive Fibonacci of %d: %d\n", n, recursive_fibonacci(n));
    printf("Iterative Fibonacci of %d: %d\n", n, func0(n));
    return 0;
}