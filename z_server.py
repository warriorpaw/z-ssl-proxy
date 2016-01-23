import myssl, select, socket
import sys, struct, os, random, hashlib, time, threading
import json
import signal
import logging
from util import *


class zProxyHandle(Mix, myssl.zProxyRequestHandler):
    def __init__(self, *argv):
        Mix.__init__(self)
        myssl.zProxyRequestHandler.__init__(self, *argv)

    def handle_socks5(self, sock, remote):
        try:
            fdset = [sock, remote]
            while 1:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = ''
                    try:
                        data = self.split_mix_up(sock)
                    except TcpFIN:
                        break
                    if len(data) <= 0:
                        continue
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(1024)
                    if len(data) <= 0:
                        break
                    send_data = self.add_mix_up(data)
                    result = send_all(sock, send_data)
                    if result < len(send_data):
                        raise Exception('failed to send all data')
                if not len(r):
                    break
        finally:
            sock.close()
            remote.close()

    def handleProxy(self):
        try:
            sock = self.connection
            addrtype = ord(sock.recv(1))
            if addrtype == 1:
                addr = socket.inet_ntoa(sock.recv(4))
            elif addrtype == 3:
                addr = sock.recv(ord(sock.recv(1)))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', sock.recv(2))
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.create_connection((addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_socks5(sock, remote)
        except socket.error, e:
            logging.warn(e)
            return

    def verify(self):
        global PW
        data = self.connection.recv(20)
        if data[:20] == PW:
            return None
        else:
            return data

    def handleHTTP(self, data):
        global HTTP_ADDR, HTTP_PORT
        try:
            sock = self.connection
            try:
                remote = socket.create_connection((HTTP_ADDR, HTTP_PORT))
                result = send_all(remote, data)
                if result < len(data):
                    remote.close()
                    return
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)
            return

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while 1:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if not len(r):
                    break
        finally:
            sock.close()
            remote.close()


def main():
    global PW, HTTPLOG, TCP_CLIENTS, HTTP_ADDR, HTTP_PORT
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    with open(filepath('config.json'), 'rb') as f:
        config = json.load(f)
    logging.info('loading config from %s' % filepath('config.json'))

    SERVER = config['server']
    PORT = config['server_port']
    PW = hashlib.sha1(config['password'] + "3dfghuyrfplndd3e2sdrr4dddff").digest()
    CRT = filepath(config['crt'])
    KEY = filepath(config['key'])
    HTTP_ADDR = config['http_addr']
    HTTP_PORT = config['http_port']

    HTTPLOG = filepath('http.log')

    server = myssl.ThreadingzProxyServer((SERVER, PORT),
                                         zProxyHandle,
                                         CRT,
                                         KEY)
    logging.info("starting server at %s:%d" % tuple(server.server_address[:2]))

    try:
        server.serve_forever()
    except:
        server.shutdown()
        server.server_close()
        sys.exit()

if __name__ == '__main__':
    main()
