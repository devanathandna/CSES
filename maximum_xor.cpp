#include <bits/stdc++.h>
using namespace std;

int main() {
    int n;
    cin >> n;

    vector<int> a(n);
    for (int &x : a) cin >> x;

    int left = 0, right = 0;
    int currXor = 0, maxXor = 0;

    while (right < n) {
        currXor ^= a[right];
        maxXor = max(maxXor, currXor);

      
        while (left < right && currXor < maxXor) {
            currXor ^= a[left];
            left++;
            maxXor = max(maxXor, currXor);
        }

        right++;
    }

    cout << maxXor << endl;
    return 0;
}
