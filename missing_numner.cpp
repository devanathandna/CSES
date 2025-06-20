#include<bits/stdc++.h>
using namespace std;

int main(){
	int n;
	cin >> n;
	long long total = 1LL * n*(n+1) /2;
	long long sum = 0;
	for(int i=0;i<n-1;i++){
		long long x;
		cin >> x;
		sum+=x;
	}
	cout << total - sum << endl;
	return 0;
}


/*

I am sure that the Tshark is working fine
PS D:\PXMonitor\pxmonitor\backend> tshark -i "Wi-Fi" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len -E "header=y" -E "separator=,"
frame.time_epoch,ip.src,ip.dst,frame.len
Capturing on 'Wi-Fi'
1750354160.253079000,35.200.182.115,192.168.220.216,54
1750354160.257978000,35.200.182.115,192.168.220.216,1414
1750354160.262712000,35.200.182.115,192.168.220.216,1414
1750354160.262712000,35.200.182.115,192.168.220.216,1414
1750354160.262712000,35.200.182.115,192.168.220.216,1414
1750354160.262712000,35.200.182.115,192.168.220.216,189
1750354160.262818000,192.168.220.216,140.82.113.22,54
1750354160.262866000,192.168.220.216,35.200.182.115,54
1750354160.263138000,192.168.220.216,140.82.113.22,54
Look at this 
I think there is some problem in websockets
If it causes problem means can we use some other thing like endpoint rather than a websocket

*/