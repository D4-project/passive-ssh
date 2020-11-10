#!/bin/bash

set -e
set -x

# gcc libffi-dev
sudo apt-get install python3-pip virtualenv screen -y

if [ -z "$VIRTUAL_ENV" ]; then
    virtualenv -p python3 PSSHENV
    echo export PSSH_HOME=$(pwd) >> ./PSSHENV/bin/activate
    . ./PSSHENV/bin/activate
fi

python3 -m pip install -r requirement.txt


# REDIS #
test ! -d redis/ && git clone https://github.com/antirez/redis.git
pushd redis/
git checkout 5.0
make
popd
