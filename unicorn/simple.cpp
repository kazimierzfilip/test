#include<iostream> 
using namespace std; 
  
int main()  
{  
      
    cout<<"Hello"<<endl; 

    int i;
    int sum = 0;
    for(i=0; i<100000; i++){
        sum += i;
    }

    cout<<"Hello "<<sum<<endl; 

    return 0;  
}  