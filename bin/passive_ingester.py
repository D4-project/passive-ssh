

import passive_ssh

def save_ssh_scan(scan_dict):
    # check host type
    if scan_dict.get('onion'):
        host_type = 'onion'
    else:
        host_type = 'ip'
    host = scan_dict[host_type]

    ## Host ##
    passive_ssh.save_host(host, host_type, scan_dict['date'], scan_dict['epoch'])

    ## Port ##
    passive_ssh.save_host_port(host, host_type, scan_dict['port'])

    ## Banner ##
    passive_ssh.save_banner(scan_dict['banner'], host, host_type)

    ## HASSHS ##
    passive_ssh.save_hassh(scan_dict['hassh'], scan_dict['key_exchange'], host, host_type)

    ## PKeys ##
    for pkey in scan_dict['host_keys']:
        if pkey and 'name' in pkey:
            passive_ssh.save_pub_key(pkey['name'], pkey['fingerprint'], pkey['base64'], host_type, host, scan_dict['date'], scan_dict['epoch'])


# if __name__ == '__main__':
#     pass

# TODO hassh LIST -> Single key ???
# PORT HISTORY

