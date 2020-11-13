# analyzer-d4-passivessh

The Passive SSH server provide a fast-lookup database with the history of all SSH keys seen per host (IPv4/IPv6/onion). The goal of the passive SSH server is to trace and track SSH network activities

# Overview

- SSH scanner and fingerprinter
- scan and fingerprint hidden services
- Get all SSH banners
- Search hosts by fingerprint
- Search hosts by [hassh](https://github.com/salesforce/hassh)

## Server Requirements

- Python >= 3.6
- Redis >5.0
- tornado

## Scanner Requirements

- Python >= 3.6
- [D4 paramiko](https://github.com/D4-project/paramiko.git)
- pysocks (required to scan hidden services)

## Install

~~~~
./install.sh
~~~~

Install Redis and all pythons requirements.  
All Python 3 code will be installed in a virtualenv (PSSHENV).

### Tor proxy

The ssh scanner can use the tor proxy to scan an host or an hidden service.

Install the tor proxy: `sudo apt-get install tor -y`

## Running

Launch the redis and the tornado server

~~~~
./LAUNCH -l
~~~~

## API

By default, the tornado server for Passive SSH is running on port 8500

~~~~
curl http://localhost:8500/banners
~~~~

### Endpoints
####  `/stats`
Return server staticstics:
  - number of SSH banners
  - number of scanned hosts:
      - ip
      - onion
  - number of fingerprints by type

#### `/banners`
Return the list of all banners

#### `/keys/types`
Return the list of all keys types

#### `/host/ssh/<host>`
Return host SSH metadata:
  - first seen
  - last seen
  - ports
  - list of banners
  - list of fingerprints

#### `/host/history/<host>`
Return the SSH history of an host

#### `/fingerprint/all/<fingerprint>`
Get hosts by fingerprint:
  - first seen
  - last seen
  - key type
  - key base64
  - fingerprint

#### `/fingerprint/type/<key_type>/<fingerprint>`
Get hosts by type of key and fingerprint:
  - first seen
  - last seen
  - key type
  - key base64
  - fingerprint

#### `/hassh/host/<hassh>`
Get hosts by [hassh](https://github.com/salesforce/hassh):
  - hassh
  - list of hosts
  - kexinit

# License

The software is free software/open source released under the GNU Affero General Public License version 3.
