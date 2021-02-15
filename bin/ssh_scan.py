#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import io
import os
import re
import sys
import json
import time
import socks
import socket
import logging
import argparse
import binascii
import datetime
import paramiko
import netaddr
from hashlib import md5

import passive_ingester


#### SSH BANNER ####
SSH_BANNER = 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3'
####  ####

#### LOG CATCHER ####

# Create log buffer
LOG_BUFFER = io.StringIO()

# set logging debug level + log in LOG_BUFFER
logger = logging.getLogger('paramiko')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(LOG_BUFFER)
logger.addHandler(handler)

# Debug
#paramiko.common.logging.basicConfig(level=logging.DEBUG)

def get_log_buffer_content():
    content = LOG_BUFFER.getvalue()
    # Clean buffer
    clean_log_buffer()
    return content

# Clean buffer
def clean_log_buffer():
    LOG_BUFFER.truncate(0)

####  ####

#### LOG PARSER ####
regex_server = [
    ('key', r'server key:\[(.*?)\]'),
    ('encrypt', r'server encrypt:\[(.*?)\]'),
    ('mac', r'server mac:\[(.*?)\]'),
    ('compress', r'server compress:\[(.*?)\]'),
    ('lang', r'server lang:\[(.*?)\]')
]
banner_regex = r'Remote version/idstring:'

def get_key_exchange(content):
    dict_key_exchange = {}
    for field_name, regex in regex_server:
        server_field = re.search(regex, content)
        if server_field:
            elem_field = server_field[1].replace("'", "")
            if elem_field:
                dict_key_exchange[field_name] = [ elem.replace(' ', '') for elem in elem_field.split(',') ]
            else:
                dict_key_exchange[field_name] = []
    return dict_key_exchange

def get_banner(content):
    return content.replace('Remote version/idstring: ', '')

def log_parser():
    dict_kex = {}
    log_lines = get_log_buffer_content()
    for line in log_lines.splitlines():
        if line.startswith('kex algos:'):
            dict_kex['key_exchange'] = get_key_exchange(line)
        elif line.startswith('Remote version/idstring:'):
            dict_kex['banner'] = get_banner(line)
    return dict_kex

####  ####

def is_domain_onion(domain):
    return str(domain).endswith('.onion')

# timeout standard!=onion
def get_socket_timeout(domain, use_proxy=False, timeout=0):
    if timeout:
        try:
            timeout = int(timeout)
            if timeout > 0:
                return timeout
        except Exception:
            pass

    if is_domain_onion(domain):
        return 30
    else:
        if use_proxy:
            return 30
        return 1

def add_error_stats(stats_dict, error_name):
    if not 'errors' in stats_dict:
        stats_dict['errors'] = {}
    error_name = str(error_name).replace('()', '')
    stats_dict['errors'][error_name] = stats_dict['errors'].get(error_name, 0) + 1

#### HASSH ####
# # TODO: add lang ?
def get_hassh(key_exchange):
    ckexAlgs = ','.join([ alg for alg in key_exchange['key'] ])
    cencCS = ','.join([ alg for alg in key_exchange['encrypt'] ])
    cmacCS = ','.join([ alg for alg in key_exchange['mac'] ])
    ccompCS = ','.join([ alg for alg in key_exchange['compress'] ])
    hasshAlgorithms = "{kex};{enc};{mac};{cmp}".format(kex=ckexAlgs, enc=cencCS, mac=cmacCS, cmp=ccompCS)
    return md5(hasshAlgorithms.encode('utf-8')).hexdigest()
####  ####

def get_ssh_fingerprint(target, port, socket_timeout, preferred_key=None , use_proxy=False, proxy_ip="127.0.0.1", proxy_port=9050):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    s = socks.socksocket()
    if use_proxy:
        s.setproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, proxy_port)
    s.settimeout(socket_timeout)
    s.connect((target, port))

    # manage transport
    ssh_transport = paramiko.transport.Transport(s)
    ssh_transport.local_version = SSH_BANNER
    # Default ssh timeout
    ssh_transport.banner_timeout = 5
    ssh_transport.handshake_timeout = 5
    ssh_transport.auth_timeout = 10
    ssh_transport.clear_to_send_timeout = 20

    # force key algo
    if preferred_key:
        ssh_transport._preferred_keys = [preferred_key]

    ssh_transport.set_gss_host(gss_host=None, trust_dns=True, gssapi_requested=False)

    # clear other logs
    clean_log_buffer()
    try:
        ssh_transport.start_client(timeout=20)
    except paramiko.ssh_exception.SSHException as e:
        print('SSH EXCEPTION: {}:{} - {}, {}'.format(target, port, preferred_key, e))
        return {}
    except EOFError as e:
        print('EOF in paramiko transport thread: {}:{} - key: {}'.format(target, port, preferred_key))
        return {}

    if not preferred_key:
        dict_key_exchange = log_parser()
        host_ref = s.getpeername()[0]

    try:
        key = ssh_transport.get_remote_server_key()
        fingerprint = binascii.hexlify(key.get_fingerprint()).decode()
    except paramiko.ssh_exception.SSHException as e:
        print('SSH EXCEPTION: {}:{} - {}, {}'.format(target, port, preferred_key, e))
        return {}

    host_pkey = {}
    host_pkey['fingerprint'] = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
    host_pkey['name'] = key.get_name()
    host_pkey['base64'] = '{} {}'.format(host_pkey['name'], key.get_base64())

    # # TODO: get IP/Domain
    # # TODO: # FIXME: AD DNS

    #print(ssh_transport.getpeername()[0])
    #print(ssh_transport.getpeername()[1])

    ssh_transport.close()
    client.close()
    s.close()
    # clear buffer
    clean_log_buffer()

    if preferred_key:
        return host_pkey

    else:
        return (dict_key_exchange, host_pkey, host_ref)


def ssh_fingerprinter(target, port, use_proxy=False, proxy_ip="127.0.0.1", proxy_port=9050, timeout=0):
    socket_timeout = get_socket_timeout(target, use_proxy=use_proxy, timeout=timeout)

    try:
        ssh_fingerprint, host_pkey, host_ref = get_ssh_fingerprint(target, port, socket_timeout, use_proxy=use_proxy, proxy_ip=proxy_ip, proxy_port=proxy_port)
    except socket.timeout:
        #add_error_stats(stats, 'socket_timeout')
        return {}
    except OSError as e:
        #add_error_stats(stats, e)
        print(e)
        return {}

    if is_domain_onion(target):
        ssh_fingerprint['onion'] = host_ref
    else:
        ssh_fingerprint['ip'] = host_ref
    ssh_fingerprint['port'] = port
    ssh_fingerprint['date'] = datetime.datetime.now().strftime("%Y%m%d")
    ssh_fingerprint['epoch'] = int(time.time())

    ssh_fingerprint['host_keys'] = []
    ssh_fingerprint['host_keys'].append(host_pkey)

    ssh_fingerprint['hassh'] = get_hassh(ssh_fingerprint['key_exchange'])

    host_key_list = [ pkey for pkey in ssh_fingerprint['key_exchange']['key'] if pkey != host_pkey['name'] ]
    for host_key in host_key_list:
        try:
            host_pkey = get_ssh_fingerprint(target, port, socket_timeout, preferred_key=host_key, use_proxy=use_proxy, proxy_ip=proxy_ip, proxy_port=proxy_port)
            ssh_fingerprint['host_keys'].append(host_pkey)
        except socket.timeout:
            pass
    return ssh_fingerprint

def ssh_scanner(target, ssh_port, use_proxy=False, proxy_ip='127.0.0.1', proxy_port=9050, timeout=0):
    if is_domain_onion(target):
        target = target.lower()
        use_proxy = True
    try:
        res_scan = ssh_fingerprinter(target, ssh_port, use_proxy=use_proxy, proxy_ip=proxy_ip, proxy_port=proxy_port, timeout=timeout)
    except ConnectionRefusedError:
        res_scan = {}
        #add_error_stats(stats, 'ConnectionRefusedError')
    except socks.GeneralProxyError as e: # Unknow Host + Socket Timeout
        print(e)
        res_scan = {}
        #add_error_stats(stats, e)

    # stats
    # stats['nb_hosts_scanned'] = stats.get('nb_hosts_scanned', 0) + 1
    # if res_scan:
    #     stats['nb_ssh_hosts'] = stats.get('nb_ssh_hosts', 0) + 1
    return res_scan

if __name__ == '__main__':

    ds = time.time()

    parser = argparse.ArgumentParser(description='SSH Scanner')
    parser.add_argument('-p', '--port',help='SSH port' , type=int, default=22, dest='ssh_port')
    parser.add_argument('--proxy', help='SSH port', action="store_true")
    parser.add_argument('-v', '--verbose', help='Verbose output', action="store_true", default=False)
    parser.add_argument('--timeout',help='timeout' , type=int, default=0, dest='in_timeout')
    parser.add_argument('-i', '--proxy_ip',help='proxy ip' , type=str, default='127.0.0.1', dest='proxy_ip')
    parser.add_argument('-pp', '--proxy_port',help='proxy port' , type=int, default=9050, dest='proxy_port')
    parser.add_argument('-r', '--trange', help='target network range express in CIDR block', type=str, dest='trange', required=False, default=None)
    parser.add_argument('-f', '--file', help='Scan all targets from the given file', type=str, dest='tflist', required=False, default=None)

    # Required argument
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument('-t', '--target',help='target domain or ip' , type=str, dest='target', required=False, default=None)
    args = parser.parse_args()

    trange = []
    if args.trange:
        trange = netaddr.IPNetwork(args.trange)

    if args.target is None and args.trange is None and args.tflist is None:
        parser.print_help()
        sys.exit(0)

    l_targets = []
    if args.tflist:
        if not os.path.isfile(args.tflist):
            print(f'Error: File not found {args.tflist}')
            sys.exit(1)
        else:
            with open (args.tflist, 'r') as f:
                content = f.read()
                l_targets = content.splitlines()

    # target to scan
    target = args.target
    ssh_port = args.ssh_port

    # socket proxy
    use_proxy = args.proxy
    proxy_ip = args.proxy_ip
    proxy_port = args.proxy_port
    in_timeout = args.in_timeout

    if args.verbose:
        print(target)
    if args.target:
        res_scan = ssh_scanner(target, ssh_port, use_proxy=use_proxy, proxy_ip=proxy_ip, proxy_port=proxy_port, timeout=in_timeout)
        print(json.dumps(res_scan))
        if res_scan:
            passive_ingester.save_ssh_scan(res_scan)
    if trange:
        for v in trange:
            try:
                res_scan = ssh_scanner(str(v), ssh_port, use_proxy=use_proxy, proxy_ip=proxy_ip, proxy_port=proxy_port, timeout=in_timeout)
            except:
                continue
            print(json.dumps(res_scan))
            if res_scan:
                passive_ingester.save_ssh_scan(res_scan)
    if l_targets:
        for target in l_targets:
            try:
                print(target)
                res_scan = ssh_scanner(str(target), ssh_port, use_proxy=use_proxy, proxy_ip=proxy_ip, proxy_port=proxy_port, timeout=in_timeout)
            except Exception as e:
                print(e)
                continue
            print(json.dumps(res_scan))
            if res_scan:
                passive_ingester.save_ssh_scan(res_scan)

    print(time.time()-ds)
