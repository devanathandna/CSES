#include <bits/stdc++.h>
using namespace std;

int main() {
    long long n;
    cin >> n;
    
    cout << n;
    
    const long long MAX_LL = LLONG_MAX / 3;
    
    if (n == 1) {
        cout << endl;
        return 0;
    }
    
    long long j = n;
    int steps = 0;
    const int MAX_STEPS = 1000000;
    
    while (j != 1) {
        if (j % 2 == 0) {
            j = j / 2;
        } else {
            if (j > MAX_LL) {
                return 1;
            }
            j = j * 3 + 1;
        }
        cout << " " << j;
        
        if (++steps > MAX_STEPS) {
            return 1;
        }
    }
    cout << endl;
    
    return 0;
}