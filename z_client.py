import select, socket, ssl, os
import sys, struct, random, hashlib
import json
import logging
import threading
import SocketServer
from util import *


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Server(Mix, SocketServer.StreamRequestHandler):
    def __init__(self, *argv):
        Mix.__init__(self)
        SocketServer.StreamRequestHandler.__init__(self, *argv)

    def handle_socks5(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(1024)
                    if len(data) <= 0:
                        break
                    send_data = self.add_mix_up(data)
                    result = send_all(remote, send_data)
                    if result < len(send_data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = ''
                    try:
                        data = self.split_mix_up(remote)
                    except TcpFIN:
                        break
                    if len(data) <= 0:
                        continue
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def handle(self):
        try:
            sock = self.connection
            sock.recv(262)
            sock.send("\x05\x00")
            data = self.rfile.read(4) or '\x00' * 4
            mode = ord(data[1])
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])
            addr_to_send = PW
            addr_to_send += data[3]
            if addrtype == 1:
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:
                addr_len = self.rfile.read(1)
                addr = self.rfile.read(ord(addr_len))
                addr_to_send += addr_len + addr
            elif addrtype == 4:
                addr_ip = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
                addr_to_send += addr_ip
            else:
                logging.warn('addr_type not support')
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
                self.wfile.write(reply)
                #R_P = REMOTE_PORT[random.randint(0,len(REMOTE_PORT) - 1)]
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote = ssl.wrap_socket(s,
                                         ca_certs=CA,
                                         cert_reqs=ssl.CERT_REQUIRED)
                remote.connect(self.server.seradd)
                crt_ok = False
                for _, crt_name in remote.getpeercert()['subjectAltName']:
                    if self.server.seradd[0] == crt_name:
                        crt_ok = True
                        break
                if not crt_ok:
                    logging.error('Server crt error !! Server Name don\'t mach !!')
                    logging.error(str(remote.getpeercert()['subjectAltName']))
                    return
                remote.send(addr_to_send)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_socks5(sock, remote)
        except socket.error, e:
            logging.warn(e)


def main():
    global PW, CA
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    with open(filepath('config.json'), 'rb') as f:
        config = json.load(f)
    logging.info('loading config from %s' % filepath('config.json'))

    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    LOCAL = config['local']
    PW = hashlib.sha1(config['password'] + "3dfghuyrfplndd3e2sdrr4dddff").digest()
    CA = filepath(config['CA'])

    try:
        server = ThreadingTCPServer((LOCAL, PORT), Socks5Server)
        server.seradd = (SERVER, REMOTE_PORT)
        print "starting local at", PORT, 'to', SERVER
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
