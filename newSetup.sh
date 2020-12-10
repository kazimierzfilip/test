#!/bin/bash

test=`ping -c 2 8.8.8.8 2>&1`
if [[ $test == "connect: Network is unreachable" ]]; then
   echo "$test"
   exit 1
fi

echo 'Update apt'

apt-get update


echo 'install python3.9'

apt-get -y install python3.9


echo 'install curl'

apt-get -y install curl


echo 'install pip'

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py


echo 'install qiling'

python3 -m pip install qiling


echo 'python magic'

pip install python-magic

#win
#pip install python-magic-bin
#pip install windows-curses

echo 'install git'

apt-get -y install git

echo 'download backup'

apt -y install g++