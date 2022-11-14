#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import base64
import io
import json
import os
import redis
from kaitaistruct import KaitaiStream
from ssh_public_key import SshPublicKey

import configparser

#### CONFIG ####
config_dir = os.path.join(os.environ['PSSH_HOME'], 'configs')
cfg = configparser.ConfigParser()
cfg.read(os.path.join(config_dir, os.path.join(config_dir, 'config.cfg')))

redis_host = cfg.get('Redis', 'redis_host')
redis_port = cfg.getint('Redis', 'redis_port')
redis_ssh = redis.StrictRedis(host=redis_host, port=redis_port, db=0, decode_responses=True)

cfg = None
# --- CONFIG --- #

######################################

# TODO: IP - port - Key

# def sanitize_date(date_from, date_to):
#     if not date_from and not date_to:
#         return (0, -1)
#     if date_from:


# (name, fingerprint)
def unpack_p_key(p_key):
    return p_key.split(';', 1)

def parse_crypto_material(base64key):
    b64 = base64key.split(' ')
    host_pkey = {}
    parsed_key = SshPublicKey(KaitaiStream(io.BytesIO(base64.b64decode(b64[1].encode('utf-8')))))
    if parsed_key.key_name.value == "ssh-rsa":
        host_pkey['exponent'] = str(int.from_bytes(parsed_key.body.rsa_e.body, "big"))
        host_pkey['modulus'] = str(int.from_bytes(parsed_key.body.rsa_n.body, "big"))
    elif parsed_key.key_name.value == "ecdsa-sha2-nistp256":
        host_pkey['curve'] = str(parsed_key.body.curve_name.value)
        host_pkey['ec'] = str(int.from_bytes(parsed_key.body.ec.body, "big"))
    elif parsed_key.key_name.value == "ssh-ed25519":
        host_pkey['len_pk'] = str(parsed_key.body.len_pk)
        host_pkey['pk'] = str(int.from_bytes(parsed_key.body.pk, "big"))
    elif parsed_key.key_name.value == "ssh-dss":
        host_pkey['p'] = str(int.from_bytes(parsed_key.body.dsa_p.body, "big"))
        host_pkey['q'] = str(int.from_bytes(parsed_key.body.dsa_q.body, "big"))
        host_pkey['g'] = str(int.from_bytes(parsed_key.body.dsa_g.body, "big"))
        host_pkey['dsa_pub_key'] = str(int.from_bytes(parsed_key.body.dsa_pub_key.body, "big"))
    return host_pkey

######################################

def get_host_type(host):
    if str(host).endswith('.onion'):
        return 'onion'
    else:
        return 'ip'

def get_all_hosts_types():
    return ['ip', 'onion']

def get_all_keys_types():
    return redis_ssh.smembers('all:key:type')

def get_all_hosts():
    l_redis_keys = []
    for host_type in get_all_hosts_types():
        l_redis_keys.append(f'all:{host_type}')
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_all_onion():
    return redis_ssh.smembers('all:onion')

def get_all_ip():
    return redis_ssh.smembers('all:ip')

def get_all_hosts_by_type(host_type):
    return redis_ssh.smembers(f'all:{host_type}')

#### BANNER ####
def get_all_banner():
    return redis_ssh.smembers('all:banner')

def get_banner_host(banner, hosts_types=None):
    if not hosts_types:
        hosts_types = get_all_hosts_types()
    l_redis_keys = []
    for host_type in hosts_types:
        l_redis_keys.append(f'banner:{host_type}:{banner}')
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_banner_host_nb(banner, host_type):
    return redis_ssh.scard(f'banner:{host_type}:{banner}')

def get_banner_by_host(host, host_type=None, r_list=False):
    if not host_type:
        host_type = get_host_type(host)
    banners = redis_ssh.smembers(f'{host_type}:banner:{host}')
    if r_list:
        banners = list(banners)
    return banners

#### ####

#### HASSH ####
def get_all_hasshs(withscores=False):
    if withscores:
        res = redis_ssh.zrevrange('all:hassh', 0, -1, withscores=True, score_cast_func=int)
        return dict(res)
    else:
        return redis_ssh.zrange('all:hassh', 0, -1)

def get_hosts_by_hassh(hassh, hosts_types=['ip']):
    if not hosts_types:
        hosts_types = get_all_hosts_types()
    l_redis_keys = []
    for host_type in hosts_types:
        l_redis_keys.append(f'hassh:{host_type}:{hassh}')
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_hasshs_by_host(host, host_type=None):
    if not host_type:
        host_type = get_all_hosts_types()
    return redis_ssh.smembers(f'{host_type}:hassh:kex:{host}')

def get_hassh_kex(hassh, r_format='str'):
    if r_format == 'str':
        return list(redis_ssh.smembers(f'hassh:kex:{hassh}'))
    else:
        l_kex = []
        for key in redis_ssh.smembers(f'hassh:kex:{hassh}'):
            l_kex.append(json.loads(key))
        return l_kex

def get_host_kex(host, host_type=None, hassh=None, hassh_host=None):  # # TODO: # OPTIMIZE:
    host_kex = {}
    for hassh in get_hasshs_by_host(host, host_type=host_type):
        host_kex[hassh] = get_hassh_kex(hassh, r_format='dict')
    return host_kex
#### ####

#### FINGERPRINT ####
def get_all_fingerprints(withscores=False):
    if withscores:
        res = redis_ssh.zrevrange('all:key:fingerprint', 0, -1, withscores=True, score_cast_func=int)
        return dict(res)
    else:
        return redis_ssh.zrange('all:key:fingerprint', 0, -1)

def get_all_key_fingerprint_by_type(key_type):
    return redis_ssh.smembers(f'all:key:fingerprint:{key_type}')

def get_host_fingerprints(host, host_type=None):
    if not host_type:
        host_type = get_host_type(host)
    return redis_ssh.smembers(f'{host_type}:{host}')

def get_hosts_by_fingerprint(fingerprint, host_types=['ip', 'onion']):
    l_redis_keys = []
    for host_type in host_types:
        for key_type in get_all_keys_types():
            l_redis_keys.append(f'{host_type}:fingerprint:{key_type}:{fingerprint}')
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_hosts_by_key_type_and_fingerprint(key_type, fingerprint, host_types=['ip', 'onion']):
    l_redis_keys = []
    for host_type in host_types:
        l_redis_keys.append(f'{host_type}:fingerprint:{key_type}:{fingerprint}')
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def exists_fingerprint(name, fingerprint):
    return redis_ssh.exists(f'key_metadata:{name}:{fingerprint}')

#### ####

def get_host_history(host, host_type=None, date_from=None, date_to=None, get_key=False):
    # # TODO:
    # date_from, date_to = sanitize_date()
    if not host_type:
        host_type = get_host_type(host)
    ssh_history = redis_ssh.zrange(f'fingerprint:history:{host_type}:{host}', 0, -1, withscores=True)
    if not get_key:
        return ssh_history
    else:
        host_history = {}
        for history_tuple in ssh_history:
            epoch = int(history_tuple[1])
            host_history[epoch] = list(get_host_key_by_epoch(host, epoch, host_type=host_type))
        return host_history

def get_host_key_by_epoch(host, epoch, host_type=None):
    return redis_ssh.smembers(f'{host_type}:fingerprint:{host}:{epoch}')


#### METADATA ####
# # TODO: # FIXME: het port by key/epoch
def get_host_ports(host, host_type):
    host_ports = redis_ssh.smembers(f'{host_type}:port:{host}')
    if not host_ports:
        host_ports = [22]
    return host_ports

def get_host_first_seen(host, host_type):
    return redis_ssh.hget(f'{host_type}_metadata:{host}', 'first_seen')

def get_host_last_seen(host, host_type):
    return redis_ssh.hget(f'{host_type}_metadata:{host}', 'last_seen')

# TODO TEST
# todo pkey
def get_host_metadata(host, host_type=None, banner=False, hassh=False, kex=False, pkey=False):
    if not host_type:
        host_type = get_host_type(host)
    host_metadata = {'first_seen': get_host_first_seen(host, host_type),
                     'last_seen': get_host_last_seen(host, host_type)}
    port = redis_ssh.hget(f'{host_type}_metadata:{host}', 'port')
    if not port:
        port = 22
    host_metadata['port'] = port
    if banner:
        host_metadata['banner'] = get_banner_by_host(host, host_type=host_type, r_list=True)
    if hassh:
        if kex:
            hasshs = get_host_kex(host, host_type)
        else:
            hasshs = get_hasshs_by_host(host, host_type)
        host_metadata['hassh'] = hasshs

    host_metadata['keys'] = []
    for ssh_key in get_host_fingerprints(host, host_type=host_type):
        key_type, fingerprint = ssh_key.split(';', 1)
        host_metadata['keys'].append({'type': key_type, 'fingerprint': fingerprint})
    return host_metadata

def exists_host(host_type, host):
    return redis_ssh.exists(f'{host_type}_metadata:{host}')

def exist_ssh_key(key_type, fingerprint):
    return redis_ssh.exists(f'key_metadata:{key_type}:{fingerprint}')

def get_key_metadata_first_seen(key_type, fingerprint):
    return redis_ssh.hget(f'key_metadata:{key_type}:{fingerprint}', 'first_seen')

def get_key_metadata_last_seen(key_type, fingerprint):
    return redis_ssh.hget(f'key_metadata:{key_type}:{fingerprint}', 'last_seen')

def get_key_metadata(fingerprint, keys_types=[]):
    if not keys_types:
        keys_types = get_all_keys_types()
    for key_type in keys_types:
        if exist_ssh_key(key_type, fingerprint):
            key_metadata = {'type': key_type,
                            'first_seen': get_key_metadata_first_seen(key_type, fingerprint),
                            'last_seen': get_key_metadata_last_seen(key_type, fingerprint),
                            'base64': get_key_base64(key_type, fingerprint)}
            key_metadata['crypto_material'] = parse_crypto_material(key_metadata['base64'])
            return key_metadata
    return {}

def get_key_metadata_by_key_type(key_type, fingerprint):
    key_metadata = {'first_seen': redis_ssh.hget(f'key_metadata:{key_type}:{fingerprint}', 'first_seen'),
                    'last_seen': redis_ssh.hget(f'key_metadata:{key_type}:{fingerprint}', 'last_seen'),
                    'base64': get_key_base64(key_type, fingerprint)}
    key_metadata['crypto_material'] = parse_crypto_material(key_metadata['base64'])
    return key_metadata

def get_key_base64(key_type, fingerprint):
    return redis_ssh.hget(f'key_metadata:{key_type}:{fingerprint}', 'base64')

#### ####

def save_banner(banner, host, host_type):
    ## banner ##
    redis_ssh.sadd('all:banner', banner)
    redis_ssh.sadd(f'banner:{host_type}:{banner}', host)

    redis_ssh.sadd(f'{host_type}:banner:{host}', banner)

def save_key_exchange(hassh, key_exchange):
    redis_ssh.sadd(f'hassh:kex:{hassh}', json.dumps(key_exchange))
    ## Additional statistics for compression algorithms, mac algorithms and
    ## symmetric encryption algorithms.
    ## The result is approximate as at each scan it will be updated but this gives
    ## an idea of the proportion of each of the algorithms.
    if 'compress' in key_exchange:
        for compress_algo in key_exchange['compress']:
            redis_ssh.zincrby('stats:compress', 1, compress_algo)
    if 'mac' in key_exchange:
        for mac_algo in key_exchange['mac']:
            redis_ssh.zincrby('stats:mac', 1, mac_algo)
    if 'encrypt' in key_exchange:
        for encrypt_algo in key_exchange['encrypt']:
            redis_ssh.zincrby('stats:encrypt', 1, encrypt_algo)


def save_hassh(hassh, key_exchange, host, host_type):
    res = redis_ssh.sadd(f'hassh:{host_type}:{hassh}', host)
    if res == 1:
        redis_ssh.zincrby('all:hassh', 1, hassh)
        save_key_exchange(hassh, key_exchange)
    redis_ssh.sadd(f'{host_type}:hassh:kex:{host}', hassh)

def save_host_port(host, host_type, port):
    redis_ssh.sadd(f'{host_type}:port:{host}', port)

def save_host(host, host_type, date, epoch):
    redis_ssh.sadd(f'all:{host_type}', host)

    ## host metadata ##
    if not exists_host(host_type, host):
        redis_ssh.hset(f'{host_type}_metadata:{host}', 'first_seen', date)
    redis_ssh.hset(f'{host_type}_metadata:{host}', 'last_seen', date)

    ## ssh history ##
    redis_ssh.zadd(f'fingerprint:history:{host_type}:{host}', {epoch: epoch})


def save_pub_key(name, fingerprint, b64, host_type, host, date, epoch):
    p_key = f'{name};{fingerprint}'

    redis_ssh.sadd('all:key:type', name)
    redis_ssh.sadd(f'all:key:fingerprint:{name}', fingerprint)

    redis_ssh.sadd(f'all:{host_type}:fingerprint', p_key)

    # search by fingerprint
    redis_ssh.sadd(f'{host_type}:fingerprint:{name}:{fingerprint}', host)

    # key history
    redis_ssh.sadd(f'{host_type}:fingerprint:{host}:{epoch}', p_key)

    # search by host
    res = redis_ssh.sadd(f'{host_type}:{host}', p_key)
    if res == 1:
        redis_ssh.zincrby('all:key:fingerprint', 1, fingerprint)

    # pkey metadata
    if not exists_fingerprint(name, fingerprint):
        redis_ssh.hset(f'key_metadata:{name}:{fingerprint}', 'first_seen', date)
        redis_ssh.hset(f'key_metadata:{name}:{fingerprint}', 'base64', b64)
    redis_ssh.hset(f'key_metadata:{name}:{fingerprint}', 'last_seen', date)


#### ADVANCED ####
def deanonymize_onion():
    fing_inter = redis_ssh.sinter('all:ip:fingerprint', 'all:onion:fingerprint')
    deanonymized_onion = {}
    for row_fingerprint in fing_inter:
        key_type, fingerprint = row_fingerprint.split(';')
        domains = get_hosts_by_fingerprint(fingerprint, host_types=['onion'])
        for domain in domains:
            if domain not in deanonymized_onion:
                deanonymized_onion[domain] = get_host_metadata(domain, banner=True, hassh=True, kex=True, pkey=True)
            if 'ip' not in deanonymized_onion[domain]:
                deanonymized_onion[domain]['ip'] = list(get_hosts_by_fingerprint(fingerprint, host_types=['ip']))
            else:
                for ip_addr in get_hosts_by_fingerprint(fingerprint, host_types=['ip']):
                    if ip_addr not in deanonymized_onion[domain]['ip']:
                        deanonymized_onion[domain]['ip'].append(ip_addr)
            if 'matched_keys' not in deanonymized_onion[domain]:
                deanonymized_onion[domain]['matched_keys'] = [{'type': key_type, 'fingerprint': fingerprint}]
            else:
                deanonymized_onion[domain]['matched_keys'].append({'type': key_type, 'fingerprint': fingerprint})
    return deanonymized_onion

# TODO
def get_stats_nb_banner(sort=True, hosts_types=[], reverse=False):
    nb_banner = {}
    hosts_types = get_all_hosts_types()
    for banner in get_all_banner():
        for host_type in hosts_types:
            nb_banner[banner] = nb_banner.get(banner, 0) + get_banner_host_nb(banner, host_type)
    if sort:
        return {k: nb_banner[k] for k in sorted(nb_banner, key=nb_banner.get, reverse=reverse)}
    else:
        return nb_banner

def get_all_stats():
    dict_stat = {'banners': redis_ssh.scard('all:banner'),
                 'hosts': {}}
    for host_type in get_all_hosts_types():
        dict_stat['hosts'][host_type] = redis_ssh.scard(f'all:{host_type}')
    dict_stat['keys'] = {}
    for key_type in get_all_keys_types():
        dict_stat['keys'][key_type] = redis_ssh.scard(f'all:key:fingerprint:{key_type}')
    dict_stat['compress'] = redis_ssh.zrevrange('stats:compress', 0, -1,
                                                withscores=True,
                                                score_cast_func=int)
    dict_stat['mac'] = redis_ssh.zrevrange('stats:mac', 0, -1, withscores=True, score_cast_func=int)
    dict_stat['encrypt'] = redis_ssh.zrevrange('stats:encrypt', 0, -1,
                                               withscores=True,
                                               score_cast_func=int)
    return dict_stat

#### ####


if __name__ == '__main__':
    print(json.dumps(deanonymize_onion()))
