#include <bits/stdc++.h> 
using namespace std; 
  
void swap(int *xp, int *yp)  
{  
    int temp = *xp;  
    *xp = *yp;  
    *yp = temp;  
}  
  
void bubbleSort(int arr[], int n)  
{  
    int i, j;  
    for (i = 0; i < n-1; i++)      
      
    // Last i elements are already in place  
    for (j = 0; j < n-i-1; j++)  
        if (arr[j] > arr[j+1])  
            swap(&arr[j], &arr[j+1]);  
}  
  
void printArray(int arr[], int size)  
{  
    int i;  
    for (i = 0; i < size; i++)  
        cout << arr[i] << " ";  
    cout << endl;  
}  
  
int main()  
{  
    int arr[] = {64, 34, 25, 64, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 25, 64, 34, 25, 12, 22, 11, 90, 12, 22, 34, 25, 12, 22, 11, 90, 12, 22, 11, 90, 56, 63, 98, 74, 96, 56, 66, 21, 47, 69, 85, 32, 23, 12, 24, 47, 85, 65, 36, 45, 12, 23, 75, 85, 65, 95, 89, 69, 36, 54, 49, 15, 46, 37, 96, 85, 45, 59, 60};  
    int n = sizeof(arr)/sizeof(arr[0]);  
    bubbleSort(arr, n);  
    cout<<"Sorted array: \n";  
    printArray(arr, n);  
    return 0;  
}  