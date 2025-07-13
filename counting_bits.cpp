#include<bits/stdc++.h>
using namespace std;

typedef long long ll;


int main(){
	ll n;
	cin >> n;
	ll total=0;
	for(int i=0;i<61;i++){
		ll groups = 1LL  << (i+1);
		ll full = (n+1) / groups;
		ll rem = (n+1) %groups;
		ll onesin = full * (1LL << i);
		onesin += max(0LL , rem -(1LL << i));
		total +=onesin;
	}

	cout << total << endl;
	return 0;
}