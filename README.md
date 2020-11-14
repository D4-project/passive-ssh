# Passive SSH

Passive SSH is an open source framework composed of a scanner and server to store and lookup the SSH keys and fingerprints per host (IPv4/IPv6/onion).

The key materials along fingerprints and hosts are stored in a fast-lookup database. The system provides an historical view of SSH keys seen but also
common key materials reused on different IP addresses.

# Features

- A simple SSH scanner
- A server storing key materials in a Redis database
- A simple ReST API to lookup by SSH fingerprints (including [hassh](https://github.com/salesforce/hassh) or host (IPv4, IPv6 or onion addresses)
- Statistics of SSH banners and SSH fingerprints

## Server Requirements

- Python >= 3.6
- Redis >5.0
- tornado

## Scanner Requirements

- Python >= 3.6
- [D4 paramiko](https://github.com/D4-project/paramiko.git)
- pysocks (required to scan Tor hidden services)

## Install

~~~~
./install.sh
~~~~

- Install Redis and all pythons requirements.
- All Python 3 code will be installed in a virtualenv (PSSHENV).

### Tor proxy

The ssh scanner can be used with a Tor proxy to scan a host or an hidden service.

Don't forget to install the Tor proxy if you want to scan Tor hidden services: `sudo apt-get install tor -y`

## Running

Launch the redis and the tornado server

~~~~
./LAUNCH -l
~~~~

## API

An API is available to query the Passive SSH server.

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

