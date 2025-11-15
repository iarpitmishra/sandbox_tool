#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== SEC-001 Final Test ===\n");
    
    // Test BLOCKED variables
    printf("1. SECRET_PASSWORD: %s\n", getenv("SECRET_PASSWORD"));
    printf("2. API_KEY: %s\n", getenv("API_KEY")); 
    printf("3. MY_SECRET: %s\n", getenv("MY_SECRET"));
    
    // Test ALLOWED variables
    printf("4. NORMAL_VAR: %s\n", getenv("NORMAL_VAR"));
    printf("5. USER: %s\n", getenv("USER"));
    
    return 0;
}
