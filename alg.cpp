#include<iostream>

using namespace std;

#define A_a_OFFSET 32
#define OFFSET 97

int main()
{

    unsigned int ascii[26] = {}; // tablica liczebności liter gdzie ascii[i] to liczebność, a i to kod znaku (pomniejszony o 65)
    //czyli ascii[0] to liczebność 'a' itd.

    char c; //zmienna pomocnicza do operacji na wprowadzanych znakach

    char cMax, cMin; // cMax-znak o maksymalnej liczbie wyst¹pieñ, cMin- o minimalnej

    bool isEmpty=true; //czy ciąg znaków jest pusty

    while((c=cin.get())!='^') //wczytanie znaku dopóki nie zakończymy ciągu znakiem ^
    {
        if(c>=65&&c<=90 || c>=97&&c<=122) //jeżeli znak jest literą to wykonaj
        {
            if(c>=65&&c<=90) c+=A_a_OFFSET; //zamiana na małe litery
            c-=OFFSET;
            ++ascii[c]; //zwiêkszenie liczebnoœci pod komórką = znak-OFFSET
            if(isEmpty)
            {
                cMax=c;
                cMin=c; //inicjalizacja statystyk pierwszą literą
                isEmpty = false;
            }
        }
    }

    if(!isEmpty)
    {
        for(unsigned int i=0; i<26; i++)
        {
            if(ascii[i]!=0)
            {
                if(ascii[cMin]>ascii[i] || ascii[cMin]==ascii[i]&&cMin>i) cMin=i;
                //je¿eli liczebnoœæ minimalnej litery jest wiêksza od obecnej to zamieñ na obecn¹, a je¿eli jest równa to na wczeœniejsz¹ w alfabecie

                if(ascii[cMax]<ascii[i] || ascii[cMax]==ascii[i]&&cMax>i) cMax=i;
                //je¿eli liczebnoœæ maksymalnej litery jest mniejsza od obecnej to zamieñ na obecn¹, a je¿eli jest równa to na wczeœniejsz¹ w alfabecie

            }
        }
        cMax+=OFFSET; //przywrócenie poprawnych kodów ascii dla małych liter
        cMin+=OFFSET;

        cout << cMax << " " << cMin;
    }

    return 0;
}