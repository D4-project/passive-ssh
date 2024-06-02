# Passive SSH

![Passive SSH logo](https://raw.githubusercontent.com/D4-project/passive-ssh/main/doc/logo/passivessh.png)

Passive SSH is an open source framework composed of a scanner and server to store and lookup the SSH keys and fingerprints per host (IPv4/IPv6/onion).

The key materials along fingerprints and hosts are stored in a fast-lookup database. The system provides an historical view of SSH keys seen but also
common key materials reused on different IP addresses.

Related paper for this work: [Active and Passive Collection of SSH Key Material for Cyber Threat Intelligence](https://dl.acm.org/doi/full/10.1145/3491262).

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

Launch the redis and the tornado server:

~~~~
./LAUNCH -l
~~~~

### Manual scan

A SSH scanner is included to scan small networks or internal infrastructure.

~~~~
. ./PSSHENV/bin/activate
cd bin/

# Scan a host
./ssh_scan.py -t <host: 10.0.0.12>

# Scan a network range
./ssh_scan.py -r <network range: 10.0.0.0/8>
~~~~

## API

An API is available to query the Passive SSH server.

By default, the tornado server for Passive SSH is running on port 8500.

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
Return all banners ordered by scores

#### `/banner/hosts/<banner>`
Get hosts by banner:
  - banner
  - list of hosts

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

#### `/fingerprints`
Return all fingerprints ordered by scores

#### `/fingerprint/all/<fingerprint>`
Get hosts by fingerprint:
  - first seen
  - last seen
  - key type
  - key base64
  - fingerprint
  - list of hosts

#### `/fingerprint/type/<key_type>/<fingerprint>`
Get hosts by type of key and fingerprint:
  - first seen
  - last seen
  - key type
  - key base64
  - fingerprint
  - list of hosts

#### `/hasshs`
Return all [hasshs](https://github.com/salesforce/hassh) ordered by scores

#### `/hassh/hosts/<hassh>`
Get hosts by [hassh](https://github.com/salesforce/hassh):
  - hassh
  - list of hosts
  - kexinit
# Existing Passive SSH database

- CIRCL Passive SSH - [access can be requested](https://www.circl.lu/contact/) if you are a CSIRT member of [FIRST.org](https://www.first.org/), [TF-CSIRT](https://www.trusted-introducer.org/), [CNW network](https://www.enisa.europa.eu/topics/csirts-in-europe/csirts-network) or vetted security researchers.

# License

The software is free software/open source released under the GNU Affero General Public License version 3.

# Citation

If you want to cite this work, you can cite it as follows: [Active and Passive Collection of SSH Key Material for Cyber Threat Intelligence](https://dl.acm.org/doi/full/10.1145/3491262)

~~~
@article{dulaunoy2022active,
  title={Active and Passive Collection of SSH key material for cyber threat intelligence},
  author={Dulaunoy, Alexandre and Huynen, Jean-Louis and Thirion, Aurelien},
  journal={Digital Threats: Research and Practice (DTRAP)},
  volume={3},
  number={3},
  pages={1--5},
  year={2022},
  publisher={ACM New York, NY}
}
~~~
