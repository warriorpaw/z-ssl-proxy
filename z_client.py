import select, socket, ssl, os
import sys, struct, random, hashlib
import json
import logging
import threading
import SocketServer

def filepath(f):
    return os.path.join(os.path.split(os.path.realpath(__file__))[0], f)

def send_all(sock, data):
    bytes_sent = 0
    con = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
        con = con + 1
        if con > 14:
            raise Exception('send too many times!')
        
class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
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
        finally:
            sock.close()
            remote.close()

    def send_PW(self, sock):
        sock.send(PW + '\x00' * random.randint(10,80))
        rePW = sock.recv(2048)
        return (rePW[:len(PW)] == PW)

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
            addr_to_send = data[3]
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
                # not support
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
                                           ca_certs= CA,
                                           cert_reqs=ssl.CERT_REQUIRED)
                remote.connect(self.server.seradd)
                if not self.server.seradd[0] == remote.getpeercert()['subjectAltName'][0][1]:
                    logging.error('Server crt error !! Server Name don\'t mach !!')
                    logging.error(remote.getpeercert()['subjectAltName'][0][1])
                    return
                if not self.send_PW(remote):
                    logging.warn('PW error !')
                    return
                remote.send(addr_to_send)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)

class local_server(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server
    def run(self):
        self.server.serve_forever()

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
    IPv6 = int(config['ipv6'])
    CA = filepath(config['CA'])

    if IPv6:
        ThreadingTCPServer.address_family = socket.AF_INET6
    
    try:
        for i in xrange(0,len(SERVER)):
            server = ThreadingTCPServer((LOCAL, PORT[i]),Socks5Server)
            server.seradd = (SERVER[i], REMOTE_PORT)
            print "starting local at", PORT[i], 'to', SERVER[i]
            local_server(server).start()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
