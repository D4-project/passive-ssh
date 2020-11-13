#!/usr/bin/env python3
# -*-coding:UTF-8 -*

import json
import redis
import ipaddress

import passive_ssh


import tornado.escape
import tornado.ioloop
import tornado.web

def is_valid_ip_address(ip_address):
    try:
        res = ipaddress.ip_address(ip_address)
        return True
    except:
        return False

# # TODO: check len
def is_valid_fingerprint(fingerprint):
    if len(fingerprint) == 47:
        return True
    else:
        return False

# # TODO: check chars
def is_valid_hassh(hassh):
    if len(hassh) == 32:
        return True
    else:
        return False

class Get_all_banner(tornado.web.RequestHandler):
    def get(self):
        response = {"banners": list(passive_ssh.get_all_banner())}
        self.write(json.dumps(response))

class get_all_keys_types(tornado.web.RequestHandler):
    def get(self):
        response = {"keys_types": list(passive_ssh.get_all_keys_types())}
        self.write(json.dumps(response))

class Get_host(tornado.web.RequestHandler):
    def get(self, q):
        if not is_valid_ip_address(q):
            self.set_status(400)
            self.finish(json.dumps({"Error": "Invalid IP Address"}))
        else:
            response = passive_ssh.get_host_metadata(q, 'ip', banner=True, hassh=True, kex=True, pkey=True)
            self.write(json.dumps(response))

class Get_host_history(tornado.web.RequestHandler):
    def get(self, q):
        if not is_valid_ip_address(q):
            self.set_status(400)
            self.finish(json.dumps({"Error": "Invalid IP Address"}))
        else:
            response = passive_ssh.get_host_history(q, host_type='ip', get_key=True)
            self.write(json.dumps({"hosts": q, "history": response}))

class Get_all_host_by_fingerprint(tornado.web.RequestHandler):
    def get(self, q):
        if not is_valid_fingerprint(q):
            self.set_status(400)
            self.finish(json.dumps({"Error": "Invalid Fingerprint"}))
        else:
            response = passive_ssh.get_key_metadata(q)
            response['fingerprint'] = q
            self.write(json.dumps(response))

class Get_all_host_by_key_type_and_fingerprint(tornado.web.RequestHandler):
    def get(self, q1, q2):
        # # TODO: sanityse key_type
        if not is_valid_fingerprint(q2):
            self.set_status(400)
            self.finish(json.dumps({"Error": "Invalid Fingerprint"}))
        else:
            response = list(passive_ssh.get_hosts_by_key_type_and_fingerprint(q1, q2))
            dict_resp = passive_ssh.get_key_metadata_by_key_type(q1, q2)
            dict_resp['type'] = q1
            dict_resp['hosts'] = response
            self.write(json.dumps(dict_resp))

class Get_hosts_by_hassh(tornado.web.RequestHandler):
    def get(self, q):
        if not is_valid_hassh(q):
            self.set_status(400)
            self.finish(json.dumps({"Error": "Invalid Hassh"}))
        else:
            response = list(passive_ssh.get_hosts_by_hassh(q))
            kex = passive_ssh.get_hassh_kex(q, r_format='dict')
            self.write(json.dumps({"hassh": q, "hosts": response, "kexs": kex}))


#### TORNADO ####

application = tornado.web.Application([
    (r"/banners",Get_all_banner),  # show nb ?
    (r"/keys/types",get_all_keys_types), # show nb ?
    (r"/host/ssh/(.*)", Get_host),
    (r"/host/history/(.*)",Get_host_history), # remove host from url path ?

    (r"/fingerprint/all/(.*)", Get_all_host_by_fingerprint),
    (r"/fingerprint/type/([a-zA-Z0-9-]*)/(.*)", Get_all_host_by_key_type_and_fingerprint),

    (r"/hassh/host/(.*)", Get_hosts_by_hassh),

])

if __name__ == '__main__':
    application.listen(8500)
    tornado.ioloop.IOLoop.instance().start()
