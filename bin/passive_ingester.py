#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import json
import time
import redis
import logging
import binascii


redis_host = '127.0.0.1'
redis_port = 7301

redis_ssh = redis.StrictRedis(host=redis_host, port=redis_port, db=0, )

def save_ssh_scan(scan_dict):

    # check host type
    if scan_dict.get('onion'):
        host_type = 'onion'
    else:
        host_type = 'ip'
    host = scan_dict[host_type]

    # set by host type
    redis_ssh.sadd('all:{}'.format(host_type), host)

    ## banner ##
    redis_ssh.sadd('all:banner', scan_dict['banner'])
    redis_ssh.sadd('banner:{}:{}'.format(host_type, scan_dict['banner']), host)

    redis_ssh.sadd('{}:banner:{}'.format(host_type, host), scan_dict['banner'])
    ## ##

    ## hassh ##
    res = redis_ssh.sadd('hassh:{}:{}'.format(host_type, scan_dict['hassh']), host)
    if res == 1:
        redis_ssh.zincrby('all:hassh', 1, scan_dict['hassh'])
    redis_ssh.sadd('hassh:kex:{}'.format(scan_dict['hassh']), json.dumps(scan_dict['key_exchange']))

    redis_ssh.sadd('{}:hassh:kex:{}'.format(host_type, host), scan_dict['hassh'])
    ## ##

    ## host metadata ##
    if not redis_ssh.exists('{}_metadata:{}'.format(host_type, host)):
        redis_ssh.hset('{}_metadata:{}'.format(host_type, host), 'first_seen', scan_dict['date'])
    redis_ssh.hset('{}_metadata:{}'.format(host_type, host), 'last_seen', scan_dict['date'])

    ## ssh history ##
    # hassh
    redis_ssh.zadd('fingerprint:history:{}:{}'.format(host_type, host), {scan_dict['epoch']: scan_dict['epoch']})

    if scan_dict['port'] != 22:
        redis_ssh.sadd('{}:port:{}'.format(host_type, host), scan_dict['port'])

    ## pkey ##
    for pkey in scan_dict['host_keys']:
        if pkey and 'name' in pkey:
            redis_ssh.sadd('all:key:type', pkey['name'])
            redis_ssh.sadd('all:key:fingerprint:{}'.format(pkey['name']), pkey['fingerprint'])

            redis_ssh.sadd('all:{}:fingerprint'.format(host_type), ';'.join( (pkey['name'], pkey['fingerprint']) ))

            # search by fingerprint
            redis_ssh.sadd('{}:fingerprint:{}:{}'.format(host_type, pkey['name'], pkey['fingerprint']), host)

            # key history
            redis_ssh.sadd('{}:fingerprint:{}:{}'.format(host_type, host, scan_dict['epoch']), ';'.join( (pkey['name'], pkey['fingerprint']) ))

            # search by host
            res = redis_ssh.sadd('{}:{}'.format(host_type, host), ';'.join( (pkey['name'], pkey['fingerprint']) ))
            if res == 1:
                redis_ssh.zincrby('all:key:fingerprint', 1, pkey['fingerprint'])

            # pkey metadata
            if not redis_ssh.exists('key_metadata:{}:{}'.format(pkey['name'], pkey['fingerprint'])):
                redis_ssh.hset('key_metadata:{}:{}'.format(pkey['name'], pkey['fingerprint']), 'first_seen', scan_dict['date'])
                redis_ssh.hset('key_metadata:{}:{}'.format(pkey['name'], pkey['fingerprint']), 'base64', pkey['base64'])
            redis_ssh.hset('key_metadata:{}:{}'.format(pkey['name'], pkey['fingerprint']), 'last_seen', scan_dict['date'])


if __name__ == '__main__':
    pass
