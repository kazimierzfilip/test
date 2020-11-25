#!/bin/bash

test=`ping -c 2 8.8.8.8 2>&1`
if [[ $test == "connect: Network is unreachable" ]]; then
   echo "$test"
   exit 1
fi

echo 'Update apt'

apt-get update

echo 'install git'

apt-get -y install git

echo 'install python3'

apt-get -y install python3

echo 'install curl'

apt-get -y install curl

echo 'install pip'

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py

echo 'install unicorn'

python3 -m pip install unicorn

echo 'download backup'

git config --global user.name "Kazimierz Filip"
git config --global user.email "kazimierzfilipmail@gmail.com"

git clone https://github.com/kazimierzfilip/test.git

#ssh-keygen -t ed25519 -C "kazimierzfilipmail@gmail.com"

#eval "$(ssh-agent -s)"

#ssh-add ~/.ssh/id_ed25519

#git remote set-url origin git@github.com:kazimierzfilip/test.git

apt -y install gcc
apt -y install g++

python3 -m pip install pyelftools

apt -y install openjdk-8-jdk/oldstable

#apt -y install eric

pip3 install qiling