#!/usr/bin/env python3
# -*-coding:UTF-8 -*

"""
Migrate the DB from redis or Kvrocks
source: args
destination: redis config in configs/conf.cfg
"""

import argparse
from datetime import datetime
import importlib.util
import redis
import sys

import passive_ssh

spec = importlib.util.find_spec('passive_ssh')
old_passive_ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old_passive_ssh)


def migrate_db():
    for host_type in passive_ssh.get_all_hosts_types():
        print(f'MIGRATE {host_type} hosts')
        for host in old_passive_ssh.get_all_hosts_by_type(host_type):
            print(f'    MIGRATE {host}')
            for banner in old_passive_ssh.get_banner_by_host(host, host_type=host_type):
                passive_ssh.save_banner(banner, host, host_type)

            for port in old_passive_ssh.get_host_ports(host, host_type):
                passive_ssh.save_host_port(host, host_type, port)

            host_history = old_passive_ssh.get_host_history(host, host_type=host_type, get_key=True)
            for epoch in host_history:
                for raw_key in host_history[epoch]:
                    key_type, fingerprint = passive_ssh.unpack_p_key(raw_key)

                    date = datetime.fromtimestamp(epoch).strftime("%Y%m%d")
                    print(date)
                    passive_ssh.save_host(host, host_type, date, epoch)

                    base64 = old_passive_ssh.get_key_base64(key_type, fingerprint)
                    passive_ssh.save_pub_key(key_type, fingerprint, base64, host_type, host, date, epoch)

            hasshs = old_passive_ssh.get_hasshs_by_host(host, host_type=host_type)
            for hassh in hasshs:
                key_exchanges = old_passive_ssh.get_hassh_kex(hassh, r_format='dict')
                for key_exchange in key_exchanges:
                    passive_ssh.save_hassh(hassh, key_exchange, host, host_type)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DB Migration')
    parser.add_argument('--host', help='redis source host', type=str, default='localhost', dest='host_source')
    parser.add_argument('-p', '--port', help='redis source port', type=int, dest='port_source', required=True)
    args = parser.parse_args()

    if args.host_source is None and args.port_source:
        parser.print_help()
        sys.exit(0)
    host_source = args.host_source
    port_source = args.port_source

    try:
        old_passive_ssh.redis_ssh = redis.StrictRedis(host=host_source, port=port_source, db=0, decode_responses=True)
    except redis.exceptions.ConnectionError:
        print('Redis Source Unreachable')
        sys.exit(0)
    try:
        if not old_passive_ssh.redis_ssh.ping():
            print('Redis Source Unreachable')
            sys.exit(0)
        if not passive_ssh.redis_ssh.ping():
            print('Redis Destination Unreachable')
            sys.exit(0)
    except Exception as e:
        print(e)
        sys.exit(0)

    migrate_db()
