#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import redis
import json
import io
import base64
from kaitaistruct import KaitaiStream, BytesIO
from ssh_public_key import SshPublicKey

redis_host = 'localhost'
redis_port = 7301
redis_ssh = redis.StrictRedis(host=redis_host, port=redis_port, db=0, decode_responses=True)

######################################

# def sanityze_date(date_from, date_to):
#     if not date_from and not date_to:
#         return (0, -1)
#     if date_from:

def unpack_date(date):
    if len(date) == 8:
        date = time.mktime(time.strptime(s, "%Y%m%d"))
    else:
        try:
            date = int(date)
        except:
            date = None
    return date

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
        l_redis_keys.append('all:{}'.format(host_type))
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_all_onion():
    return redis_ssh.smembers('all:onion')

def get_all_ip():
    return redis_ssh.smembers('all:ip')

#### BANNER ####
def get_all_banner():
    return redis_ssh.smembers('all:banner')

def get_banner_host(banner, hosts_types=None):
    if not hosts_types:
        hosts_types = get_all_hosts_types()
    l_redis_keys = []
    for host_type in hosts_types:
        l_redis_keys.append('banner:{}:{}'.format(host_type, banner))
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_banner_host_nb(banner, host_type=None):
    if not host_type:
        host_type = get_host_type(host)
    return int(redis_ssh.scard('banner:{}:{}'.format(host_type, banner)))

def get_banner_by_host(host, host_type=None):
    if not host_type:
        host_type = get_host_type(host)
    return redis_ssh.smembers('{}:banner:{}'.format(host_type, host))

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
        hosts_types = get_all_hosts_types(host)
    l_redis_keys = []
    for host_type in hosts_types:
        l_redis_keys.append('hassh:{}:{}'.format(host_type, hassh))
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_hasshs_by_host(host, hosts_types=['ip']):
    if not hosts_types:
        hosts_types = get_all_hosts_types(host)
    l_redis_keys = []
    for host_type in hosts_types:
        l_redis_keys.append('{}:hassh:kex:{}'.format(host_type, host))
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_hassh_kex(hassh, r_format='str'):
    if r_format == 'str':
        return list(redis_ssh.smembers('hassh:kex:{}'.format(hassh)))
    else:
        l_kex = []
        for key in redis_ssh.smembers('hassh:kex:{}'.format(hassh)):
            l_kex.append(json.loads(key))
        return l_kex

def get_host_kex(host, host_type=None, hassh=None, hassh_host=None): ## TODO: # OPTIMIZE:
    host_kex = {}
    for hassh in get_hasshs_by_host(host, hosts_types=[host_type]):
        host_kex[hassh] = get_hassh_kex(hassh)
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
    return redis_ssh.smembers('all:key:fingerprint:{}'.format(key_type))

def get_host_fingerprints(host, host_type=None):
    if not host_type:
        host_type = get_host_type(host)
    return redis_ssh.smembers('{}:{}'.format(host_type, host))

def get_hosts_by_fingerprint(fingerprint, host_types=['ip', 'onion']):
    l_redis_keys = []
    for host_type in host_types:
        for key_type in get_all_keys_types():
            l_redis_keys.append('{}:fingerprint:{}:{}'.format(host_type, key_type, fingerprint))
    return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])

def get_hosts_by_key_type_and_fingerprint(key_type, fingerprint, host_types=['ip', 'onion']):
        l_redis_keys = []
        for host_type in host_types:
            l_redis_keys.append('{}:fingerprint:{}:{}'.format(host_type, key_type, fingerprint))
        return redis_ssh.sunion(l_redis_keys[0], *l_redis_keys[1:])
#### ####

def get_host_history(host, host_type=None, date_from=None, date_to=None, get_key=False):
    # # TODO:
    #date_from, date_to = sanityze_date()
    if not host_type:
        host_type = get_host_type(host)
    ssh_history = redis_ssh.zrange('fingerprint:history:{}:{}'.format(host_type, host), 0 , -1, withscores=True)
    if not get_key:
        return ssh_history
    else:
        host_history = {}
        for history_tuple in ssh_history:
            epoch = int(history_tuple[1])
            host_history[epoch] = list(get_host_key_by_epoch(host, epoch, host_type=host_type))
        return host_history

def get_host_key_by_epoch(host, epoch, host_type=None):
    return redis_ssh.smembers('{}:fingerprint:{}:{}'.format(host_type, host, epoch))


#### METADATA ####
def get_host_metadata(host, host_type=None, banner=False, hassh=False, kex=False, pkey=False):
    if not host_type:
        host_type = get_host_type(host)
    host_metadata = {}
    host_metadata['first_seen'] = redis_ssh.hget('{}_metadata:{}'.format(host_type, host), 'first_seen')
    host_metadata['last_seen'] = redis_ssh.hget('{}_metadata:{}'.format(host_type, host), 'last_seen')
    port = host_metadata['port'] = redis_ssh.hget('{}_metadata:{}'.format(host_type, host), 'port')
    if not port:
        port = 22
    host_metadata['port'] = port
    if banner:
        host_metadata['banner'] = list(get_banner_by_host(host, host_type=host_type))
    if hassh:
        if kex:
            host_metadata['hassh'] = get_host_kex(host, host_type=host_type)
        else:
            host_metadata['hassh'] = get_host_kex(host, host_type=host_type)
            host_metadata['kex'] = json.load(get_hasshs_by_host(host, host_type=host_type))
    host_metadata['keys'] = []
    for ssh_key in get_host_fingerprints(host, host_type=host_type):
        key_type, fingerprint = ssh_key.split(';', 1)
        host_metadata['keys'].append({'type': key_type, 'fingerprint': fingerprint})
    return host_metadata


def exist_ssh_key(key_type, fingerprint):
    return redis_ssh.exists('key_metadata:{}:{}'.format(key_type, fingerprint))

def get_key_metadata_first_seen(key_type, fingerprint):
    return redis_ssh.hget('key_metadata:{}:{}'.format(key_type, fingerprint), 'first_seen')

def get_key_metadata_last_seen(key_type, fingerprint):
    return redis_ssh.hget('key_metadata:{}:{}'.format(key_type, fingerprint), 'last_seen')

def get_key_metadata(fingerprint, keys_types=[]):
    if not keys_types:
        keys_types = get_all_keys_types()
    for key_type in keys_types:
        if exist_ssh_key(key_type, fingerprint):
            key_metadata = {}
            key_metadata['type'] = key_type
            key_metadata['first_seen'] = get_key_metadata_first_seen(key_type, fingerprint)
            key_metadata['last_seen'] = get_key_metadata_last_seen(key_type, fingerprint)
            key_metadata['base64'] = get_key_base64(key_type, fingerprint)
            key_metadata['crypto_material'] = parse_crypto_material(key_metadata['base64'])
            return key_metadata
    return {}

def get_key_metadata_by_key_type(key_type, fingerprint):
    key_metadata = {}
    key_metadata['first_seen'] = redis_ssh.hget('key_metadata:{}:{}'.format(key_type, fingerprint), 'first_seen')
    key_metadata['last_seen'] = redis_ssh.hget('key_metadata:{}:{}'.format(key_type, fingerprint), 'last_seen')
    key_metadata['base64'] = get_key_base64(key_type, fingerprint)
    key_metadata['crypto_material'] = parse_crypto_material(key_metadata['base64'])
    return key_metadata

def get_key_base64(key_type, fingerprint):
    return redis_ssh.hget('key_metadata:{}:{}'.format(key_type, fingerprint), 'base64')

#### ####

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
            deanonymized_onion['ip'] = get_hosts_by_fingerprint(fingerprint, host_types=['ip'])
            deanonymized_onion['matched_keys'] = row_fingerprint
    return deanonymized_onion

def get_stats_nb_banner(sort=True, hosts_types=[], reverse=False):
    nb_banner = {}
    hosts_types = get_all_hosts_types()
    for banner in get_all_banner():
        for host_type in hosts_types:
            nb_banner[banner] = nb_banner.get(banner, 0) + get_banner_host_nb(banner, host_type=host_type)
    if sort:
        return {k: nb_banner[k] for k in sorted(nb_banner, key=nb_banner.get, reverse=reverse)}
    else:
        return nb_banner

def get_all_stats():
    dict_stat = {}
    dict_stat['banners'] = redis_ssh.scard('all:banner')
    dict_stat['hosts'] = {}
    for host_type in get_all_hosts_types():
        dict_stat['hosts'][host_type] = redis_ssh.scard('all:{}'.format(host_type))
    dict_stat['keys'] = {}
    for key_type in get_all_keys_types():
        dict_stat['keys'][key_type] = redis_ssh.scard('all:key:fingerprint:{}'.format(key_type))
    dict_stat['compress'] = redis_ssh.zrevrange('stats:compress', 0, -1,
                                                withscores=True,
                                                score_cast_func=int)
    dict_stat['mac'] = redis_ssh.zrevrange('stats:mac', 0, -1, withscores=True,
                                          score_cast_func=int)
    dict_stat['encrypt'] = redis_ssh.zrevrange('stats:encrypt', 0, -1,
                                               withscores=True,
                                               score_cast_func=int)
    return dict_stat

#### ####

if __name__ == '__main__':
    print(json.dumps(deanonymize_onion()))
