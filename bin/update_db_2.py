#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import redis

import passive_ssh

redis_host = 'localhost'
redis_port = 7301
redis_ssh = redis.StrictRedis(host=redis_host, port=redis_port, db=0, decode_responses=True)

def update_zset_all_hasshs():
    for host in passive_ssh.get_all_hosts():
        for hassh in passive_ssh.get_hasshs_by_host(host):
            redis_ssh.zincrby('all:hassh', 1, hassh)

if __name__ == '__main__':
    update_zset_all_hasshs()
