#!/usr/bin/env python
#
#  Copyright 2017 Michal Belica <https://beli.sk>
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
VERSION = '0.0.1'
PROG_NAME = "ItcProxy"
DESCRIPTION = 'ItcProxy - HTTP(S) intercepting proxy'

import SocketServer
import BaseHTTPServer
import scapy
import httplib
import select
import argparse
import threading
import time
import sys

from scapy_ssl_tls.ssl_tls import *


def data_loop(sock, outsock, shutdown=None, bufsize=4096):
    while True:
        (rtr, rtw, err) = select.select([sock, outsock], [], [sock, outsock], 1)
        if shutdown is not None and shutdown.is_set(): break
        for s in rtr:
            if s == sock:
                direction = 1 # from client to remote
            elif s == outsock:
                direction = 2 # from remote to client
            else:
                raise Exception("Unknown socket found in loop!")
            data = s.recv(bufsize)
            if len(data) == 0:
                return
            if direction == 1:
                outsock.sendall(data)
            else:
                sock.sendall(data)


class TLSTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        tls = TLS(data)
        #tls.show()
        ssl_hs_type = tls.records[0].payload.type
        if ssl_hs_type != 1:
            raise Exception('Not client hello')
        target_host = str(tls.records[0].payload[TLSExtServerNameIndication].server_names[0].data)
        print "TLS request from %s:%d for %s" % ((self.client_address) + (target_host,))
        out_con = httplib.HTTPConnection(self.server.upstream_host, self.server.upstream_port)
        out_con.set_tunnel(target_host, 443)
        out_con.send(data)
        data_loop(self.request, out_con.sock)
        self.request.close()
        out_con.sock.close()


class HTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def handle_one_request(self):
        self.raw_requestline = self.rfile.readline(65537)
        if len(self.raw_requestline) > 65536:
            self.requestline = ''
            self.request_version = ''
            self.command = ''
            self.send_error(414)
            return
        if not self.raw_requestline:
            self.close_connection = 1
            return
        if not self.parse_request():
            return
        hostport = self.headers.get('host', None)
        if self.path.startswith('http:') or self.command.upper() == 'CONNECT':
            url = self.path
        else:
            if hostport is None:
                raise Exception('Incoming request without full URL or Host header')
            url = 'http://%s%s' % (hostport, self.path)
        print "HTTP request from %s:%d for %s (%s %s)" % ((self.client_address) + (hostport, self.command, url))
        length = int(self.headers.get('content_length', 0))
        if length > 0:
            data = self.rfile.read(length)
        else:
            data = None
        self.headers['connection'] = 'close'
        out_con = httplib.HTTPConnection(self.server.upstream_host, self.server.upstream_port)
        out_con.putrequest(self.command, url, skip_host=1, skip_accept_encoding=1)
        for hdr in self.headers.headers:
            out_con._output(hdr.rstrip())
        out_con.endheaders(data)
        data_loop(self.request, out_con.sock)
        self.request.close()
        out_con.sock.close()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


def start_tls_server(host, port, upstream_host, upstream_port):
    server = ThreadedTCPServer((host, port), TLSTCPHandler)
    server.allow_reuse_address = True
    server.upstream_host = upstream_host
    server.upstream_port = upstream_port
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server_thread, server


def start_http_server(host, port, upstream_host, upstream_port):
    server = ThreadedTCPServer((host, port), HTTPHandler)
    server.allow_reuse_address = True
    server.upstream_host = upstream_host
    server.upstream_port = upstream_port
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server_thread, server


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-l', '--listen', default='', help='Listening address (default: any)')
    parser.add_argument('-p', '--port', type=int, help='Listening HTTP port (default: disable)')
    parser.add_argument('-t', '--tlsport', type=int, help='Listening TLS port (default: disable)')
    parser.add_argument('upstream_host', help='Upstream HTTP proxy host')
    parser.add_argument('upstream_port', type=int, help='Upstream HTTP proxy port')
    parser.add_argument('-V', '--version', action='version',
            version='{} {}'.format(PROG_NAME, VERSION))
    args = parser.parse_args()
    servers = []
    if args.tlsport:
        tls_server_thread, tls_server = start_tls_server(args.listen, args.tlsport, args.upstream_host, args.upstream_port)
        servers.append(tls_server)
    if args.port:
        http_server_thread, http_server = start_http_server(args.listen, args.port, args.upstream_host, args.upstream_port)
        servers.append(http_server)
    if servers:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print "Interrupted"
        for server in servers:
            server.shutdown()
            server.server_close()

