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
    #print(ip_address)
    try:
        res = ipaddress.ip_address(ip_address)
        return True
    except:
        return False

class Get_all_banner(tornado.web.RequestHandler):
    def get(self):
        response = {"banners": list(passive_ssh.get_all_banner())}
        self.write(response)

class get_all_keys_types(tornado.web.RequestHandler):
    def get(self):
        response = {"keys_types": list(passive_ssh.get_all_keys_types())}
        self.write(response)

class Get_ip(tornado.web.RequestHandler):
    def get(self, q):
        if not is_valid_ip_address(q):
            self.set_status(400)
            self.finish({"Error": "Invalid IP Address"})
        else:
            response = passive_ssh.get_host_metadata(q, 'ip', banner=True, hassh=True, kex=True, pkey=True)
            self.write(response)

class Get_ip_history(tornado.web.RequestHandler):
    def get(self, q):
        if not is_valid_ip_address(q):
            self.set_status(400)
            self.finish({"Error": "Invalid IP Address"})
        else:
            response = passive_ssh.get_host_history(q, host_type='ip', get_key=True)
            self.write({"ip": q, "history": response})

#### TORNADO ####

application = tornado.web.Application([
    (r"/banners",Get_all_banner),
    (r"/keys/types",get_all_keys_types),
    (r"/ip/(.*)",Get_ip),
    (r"/ip_history/(.*)",Get_ip_history),
    #(r"/info", InfoHandler)
    # ssh pkey to ip
    # fingerprint/hassh to ip
])

if __name__ == '__main__':
    application.listen(8500)
    tornado.ioloop.IOLoop.instance().start()
