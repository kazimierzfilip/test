#!/bin/bash

test=`ping -c 2 8.8.8.8 2>&1`
if [[ $test == "connect: Network is unreachable" ]]; then
   echo "$test"
   exit 1
fi

apt update

apt -y install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev

wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tgz

tar -xf Python-3.9.0.tgz

cd Python-3.9.0
./configure --enable-optimizations

make -j 2

make install

python3 -m pip install qiling

apt -y install git

git clone https://github.com/kazimierzfilip/test.git

cd test

python3 qilingdemo.py