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

cp configs/config.cfg.sample configs/config.cfg

# KVROCKS #
test ! -d kvrocks/ && git clone https://github.com/apache/incubator-kvrocks.git kvrocks
pushd kvrocks
./x.py build
popd
