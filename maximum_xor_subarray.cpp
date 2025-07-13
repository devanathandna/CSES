#include<bits/stdc++.h>
using namespace std;


int main(){
	long long n;
	cin >> n;

	vector<long long>ans(n);
	for(int i=0;i<n;i++){
		cin >> ans[i];
	}

	unordered_set<long long>st;
	st.insert(0);
	long long prevxor=0;
	long long maxxor = 0;

	for(int i=0;i<n;i++){
		prevxor^=ans[i];


		for(int ii:st){
			maxxor = max(maxxor, ii^prevxor);
		}

		st.insert(prevxor);
	}

	cout << maxxor << endl;

	return 0;

}