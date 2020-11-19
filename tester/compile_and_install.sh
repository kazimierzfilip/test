#!/bin/bash

if [ "$(id -u)" -gt 0 ]
    then
       echo >&2 'You have to be root in order to run this script'
       echo >&2 "Type: sudo $0 $*"
       exit 1
    fi

g++ 'test.cpp' -o 'test' && \
mkdir -p /checker/{tests,rundir}/ && \
chmod a+w /checker/{tests,rundir}/ && \
mv 'test' '/checker/' && \
chmod a+s '/checker/test'
