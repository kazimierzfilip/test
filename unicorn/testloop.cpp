#include <bits/stdc++.h> 
using namespace std; 
  
int main()  
{  
    int i,j;
    int sum = 0;
    for (i = 0; i < 1000; i++){
       int sum2 = 0;
       for (j = 0; j < 1000; j++) {
        sum2 += 1;
       }
        sum += 1;
        cout << sum2;
    }
    cout << sum;
    return 0;  
}  