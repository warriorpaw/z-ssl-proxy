import select, socket, ssl, os
import sys, struct, random, hashlib, time, threading
import json
import logging
import threading
import SocketServer

#MAXSYN = 2 ** 15
MAXSYN = 1024
MAXSYNBUFFER = 200
#REMOTE_lines = 4

def filepath(f):
    return os.path.join(os.path.split(os.path.realpath(__file__))[0], f)

def send_all(sock, data):
    bytes_sent = 0
    con = 0
    while 1:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
        con = con + 1
        if con > 14:
            raise Exception('send too many times!')

def read_all(sock):
    data_len = sock.recv(2)
    if len(data_len) <= 0:
        raise Exception('read_all zero data!')
    data_len = struct.unpack("H",data_len)[0]
    if data_len <= 0:
        raise Exception('read_all data_len error!')
    data = ''
    while data_len > 0:
        d = sock.recv(data_len)
        if len(d) <= 0:
            raise Exception('read_all read error!')
        data += d
        data_len -= len(d)
    return data


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class Mytimer(threading.Thread):
    def __init__(self, callback):
        threading.Thread.__init__(self)
        self.callback = callback
        self.over = False

    def run(self):
        while not self.over:
            self.callback()
            time.sleep(random.randint(5,20))

    def kill(self):
        self.over = True

class TcpProxyClient(SocketServer.StreamRequestHandler):
    def handle_tcp(self):
        sock = self.connection
        fset = [sock]
        try:
            while len(self.remotes):
                r, w, e = select.select(fset, [], [])
                if sock in r:
                    data = sock.recv(1020)
                    if len(data) <= 0:
                        print 'handle_tcp close!!!!!!!!!!!!'
                        break
                    data = struct.pack("H",self.SendSYN) + data
                    self.SendSYN = (self.SendSYN + 1) % MAXSYN
                    data = struct.pack("H",len(data)) + data
                    while len(self.remotes):
                        if random.choice(self.remotes[-4:]).send(data):
                            break
        except:
            print 'handle_tcp'
            print sys.exc_info()
        finally:
            self.destroy()

    def timer_connect(self):
        while len(self.remotes) > 4:
            self.remotes[0].destroy()
        newline = random.randint(1,4)
        for i in range(0,newline):
            remote = self.newconnect()
            if not remote:
                break
            try:
                remote.send('\x08' + self.ID + '\x00' * random.randint(10,50))
                reID = remote.recv(65535)[:20]
                if not reID == self.ID:
                    remote.close()
                    break
                r = tcp_remote(remote, self)
                r.start()
                self.remotes.append(r)
            except:
                print 'Time'
                print sys.exc_info()
                remote.close()
                break

    def remove(self, remote):
        if remote in self.remotes:
            self.remotes.remove(remote)
        if not len(self.remotes):
            self.destroy()

    def send(self, data):
        def _send(self, data):
            result = send_all(self.connection, data)
            if result < len(data):
                raise Exception('failed to send all data')
            self.RecvSYN = (self.RecvSYN + 1) % MAXSYN
        try:
            self.mutex.acquire()
            syn = struct.unpack("H",data[:2])[0]
            if syn == self.RecvSYN:
                _send(self, data[2:])
                while len(self.SYNbuffer):
                    if self.RecvSYN in self.SYNbuffer:
                        _send(self, self.SYNbuffer.pop(self.RecvSYN))
                    else:
                        break
            else:
                if len(self.SYNbuffer) >= MAXSYNBUFFER:
                    raise Exception('SYNbuffer overflow')
                self.SYNbuffer[syn] = data[2:]
                #print 'SYN len', len(self.SYNbuffer)
        except:
            print 'Hsend'
            print sys.exc_info()
            self.destroy()
        finally:
            self.mutex.release()

    def handle(self):
        if self.Start():
            try:
                self.handle_tcp()
            except socket.error, e:
                logging.warn(e)
        self.destroy()

    def send_PW(self, sock):
        sock.send(PW + '\x00' * random.randint(10,80))
        rePW = sock.recv(65535)
        return (rePW[:20] == PW)

    def newconnect(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote = ssl.wrap_socket(s,
                                     ca_certs= CA,
                                     cert_reqs=ssl.CERT_REQUIRED,
                                     ssl_version = ssl.PROTOCOL_SSLv3)
            remote.connect(self.server.seradd)
            if not self.server.seradd[0] == remote.getpeercert()['subjectAltName'][0][1]:
                logging.error('Server crt error !! Server Name don\'t mach !!')
                logging.error(remote.getpeercert()['subjectAltName'][0][1])
                return
            if not self.send_PW(remote):
                logging.warn('PW error !')
                return
        except socket.error, e:
            logging.warn(e)
            return
        return remote

    def Start(self):
        self.remotes = []
        self.mutex = threading.Lock()
        self.SendSYN = 0
        self.RecvSYN = 0
        self.SYNbuffer = {}
        try:
            addr_to_send = '\x05'
            addr_to_send += socket.inet_aton(self.server.r_sock[0])
            addr_to_send += struct.pack('>H', self.server.r_sock[1])
            remote = self.newconnect()
            if not remote:
                return
            remote.send(addr_to_send)
            self.ID = remote.recv(65535)[:20]
            remote.send(self.ID + '\x00' * random.randint(10,50))
            r = tcp_remote(remote, self)
            r.start()
            self.remotes.append(r)
        except socket.error, e:
            logging.warn(e)
            return
        self.mytimer = Mytimer(self.timer_connect)
        self.mytimer.start()
        return True

    def destroy(self):
        self.connection.close()
        self.mytimer.kill()
        #self.server.shutdown()
        while len(self.remotes):
            self.remotes.pop().destroy()


class tcp_remote(threading.Thread):
    def __init__(self, sock, local):
        threading.Thread.__init__(self)
        self.sock = sock
        self.local = local
        self.tcpruning = True

    def run(self):
        sock = self.sock
        fset = [sock]
        try:
            while self.tcpruning:
                r, w, e = select.select(fset, [], [])
                if sock in r:
                    self.local.send(read_all(sock))
        except:
            print 'tcp_remote'
            print sys.exc_info()
        finally:
            self.destroy()

    def send(self, data):
        try:
            result = send_all(self.sock, data)
            if result < len(data):
                raise Exception('failed to send all data')
            return True
        except:
            print 'Tsend'
            print sys.exc_info()
            self.destroy()
            return False

    def destroy(self):
        self.tcpruning = False
        self.local.remove(self)
        self.sock.close()

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
    SERVER_PORT = config['server_port']
    #PORT = config['local_port']
    LOCAL = config['local']
    PW = hashlib.sha1(config['password'] + "3dfghuyrfplndd3e2sdrr4dddff").digest()
    IPv6 = int(config['ipv6'])
    CA = filepath(config['CA'])
    tcptrans = config['tcptrans']

    if IPv6:
        ThreadingTCPServer.address_family = socket.AF_INET6

    try:
        for s, r_add, r_port, l_port in tcptrans:
            server = ThreadingTCPServer((LOCAL, l_port),TcpProxyClient)
            server.seradd = (SERVER, SERVER_PORT)
            server.r_sock = (r_add, r_port)
            print 'TCPTrans', l_port, 'to', server.r_sock[0],server.r_sock[1],'@',server.seradd[0]
            local_server(server).start()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
