#!/usr/bin/env python
import SocketServer
import BaseHTTPServer
import scapy
import httplib
import select
import argparse
import threading
import time

from scapy_ssl_tls.ssl_tls import *


# Dictionary of SSL/TLS handshake type values
ssl_handshake_type = {
        0: "HELLO_REQUEST",
        1: "CLIENT_HELLO",
        2: "SERVER_HELLO",
        11: "CERTIFICATE",
        12: "SERVER_KEY_EXCHANGE",
        13: "CERTIFICATE_REQUST",
        14: "SERVER_DONE",
        15: "CERTIFICATE_VERIFY",
        16: "CLIENT_KEY_EXCHANGE",
        20: "FINISHED",
        }

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
                if direction == 1:
                    raise Disconnect('Client disconnected')
                else:
                    raise Disconnect('Remote end disconnected')
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
        print "*** TLS server name (%s)" % target_host
        out_con = httplib.HTTPConnection(upstream_host, upstream_port)
        out_con.set_tunnel(target_host, 443)
        out_con.send(data)
        data_loop(self.request, out_con.sock)


class HTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def handle_one_request():
        if host not in self.headers:
            raise('Incoming request without Host header')
        hostport = self.headers['host']
        out_con = httplib.HTTPConnection(upstream_host, upstream_port)
        url = 'http://%s%s' % (hostport, path)
        data = read(self.rfile)
        out_con.request(self.command, url, data, self.headers)
        #TODO


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


def tls_server(host, port):
    server = ThreadedTCPServer((host, port), TLSTCPHandler)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server_thread, server


def http_server(host, port):
    server = ThreadedTCPServer((host, port), HTTPHandler)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server_thread, server


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--listen', default='', help='Listening address (default: any)')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Listening HTTP port (default: %(default)s')
    parser.add_argument('-t', '--tlsport', type=int, default=8443, help='Listening TLS port (default: %(default)s')
    parser.add_argument('host', help='Upstream HTTP proxy host')
    parser.add_argument('port', help='Upstream HTTP proxy port')
    args = parser.parse_args()
    tls_server_thread, tls_server = tls_server(args.listen, args.tlsport)
    http_server(args.listen, args.port)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Interrupted"
    tls_server.shutdown()
    tls_server.server_close()

