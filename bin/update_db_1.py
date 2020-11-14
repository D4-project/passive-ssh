#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import redis

import passive_ssh

redis_host = 'localhost'
redis_port = 7301
redis_ssh = redis.StrictRedis(host=redis_host, port=redis_port, db=0, decode_responses=True)

def update_zset_all_ingerprints():
    for key_type in passive_ssh.get_all_keys_types():
        for fingerprint in passive_ssh.get_all_key_fingerprint_by_type(key_type):
            for host in passive_ssh.get_hosts_by_fingerprint(fingerprint):
                redis_ssh.zincrby('all:key:fingerprint', 1, fingerprint)

if __name__ == '__main__':
    update_zset_all_ingerprints()
