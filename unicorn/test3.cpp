#include<iostream>

using namespace std;

int main(){
	cout << "Start" <<endl;

	int i;
	int sum = 0;
	for(i=0; i<10000; i++){
		sum+=1;
	}

	cout << "Stop "<<sum<<endl;

	return 0;
}