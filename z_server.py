import myssl, select, handleHTTP, socket
import sys, struct, os, random, hashlib, time, threading
import json
import logging

#MAXSYN = 2 ** 15
MAXSYNBUFFER = 64
MAXSYN = 1024
#REMOTE_lines = 4

def filepath(f):
    return os.path.join(os.path.split(os.path.realpath(__file__))[0], f)

def random_data(len):
    d = ''
    for i in range(0, len):
        d += chr(random.randint(0,255))
    return d

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
        if con > 20:
            raise Exception('send too many times!')

def read_all(sock):
    data_len = sock.recv(2)
    con = 0
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
        con += 1
        if con > 20:
            raise Exception('read too many times!')
    return data

class zProxyHandle(myssl.zProxyRequestHandler):
    def handle_socket5(self, sock, remote):
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

    def socket5proxy(self):
        try:
            sock = self.connection
            addrtype = ord(sock.recv(1))
            if addrtype > 4:
                return addrtype
            if addrtype == 1:
                addr = socket.inet_ntoa(self.rfile.read(4))
            elif addrtype == 3:
                addr = self.rfile.read(ord(sock.recv(1)))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6,self.rfile.read(16))
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.rfile.read(2))
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.create_connection((addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_socket5(sock, remote)
        except socket.error, e:
            logging.warn(e)
            return
    
    def handleProxy(self):
        addrtype = self.socket5proxy()
        if addrtype:
            self.tcpproxy(addrtype)

    def tcpproxy(self, addrtype):
        self.tcpruning = True
        try:
            sock = self.connection
            if addrtype == 8:
                self.remote = TCP_CLIENTS.handleproxy(self)
                if self.remote:
                    self.handle_TCP()
                return
            elif addrtype == 5:
                addr = socket.inet_ntoa(self.rfile.read(4))
            elif addrtype == 6:
                addr = self.rfile.read(ord(sock.recv(1)))
            elif addrtype == 7:
                addr = socket.inet_ntop(socket.AF_INET6,self.rfile.read(16))
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.rfile.read(2))
            clientID = hashlib.sha1(str(self.client_address) + random_data(20) + str(time.time())).digest()
            self.remote = TCP_CLIENTS.newproxy(clientID, addr, port[0], self)
            if self.remote:
                self.handle_TCP()
            return
        except socket.error, e:
            logging.warn(e)
            return

    def handle_TCP(self):
        try:
            sock = self.connection
            fset = [sock]
            while self.tcpruning:
                r, w, e = select.select(fset, [], [])
                if sock in r:
                    self.remote.send(read_all(sock))
                else:
                    break
        except:
            print 'handle_TCP'
            print sys.exc_info()
        finally:
            self.destroy()

    def destroy(self):
        self.tcpruning = False
        self.remote.remove(self)
        self.connection.close()

    def send(self, data):
        try:
            result = send_all(self.connection, data)
            if result < len(data):
                raise Exception('failed to send all data')
            return True
        except:
            print 'Hsend'
            print sys.exc_info()
            self.destroy()
            return False
    
    def verify(self):
        global PW
        if self.data[:20] == PW:
            #Going up, as a proxy
            self.connection.send(PW + '\x00' * random.randint(30,150))
            return True
        else:
            #Going down, as a HTTP
            return False
    def log_message(self, format, *args):
        s = ("%s - - [%s] %s\n" %
             (self.client_address[0],
              self.log_date_time_string(),
              format%args))
        l = open(HTTPLOG,'a+')
        l.write(s)
        l.close()
        sys.stderr.write(s)
        
    version_string = handleHTTP.version_string
    do_HEAD = handleHTTP.send404
    do_PUT = handleHTTP.send404
    do_POST = handleHTTP.send404
    do_DELETE = handleHTTP.send404
    do_CONNECT = handleHTTP.send404
    do_GET = handleHTTP.do_GET

class tcpproxyhandle:
    def __init__(self):
        self.clientlist = {}

    def newproxy(self, clientID, addr, port, client):
        try:
            remote = socket.create_connection((addr, port))
            client.connection.send(clientID + '\x00' * random.randint(10,80))
            reID = client.connection.recv(65535)
            if reID[:20] == clientID:
                t = tcp_remote(remote, clientID)
                t.Load(client)
                t.start()
                self.clientlist[clientID] = t
                return t
        except:
            print sys.exc_info()

    def handleproxy(self, client):
        try:
            ID = client.connection.recv(65535)[:20]
            if ID in self.clientlist:
                client.connection.send(ID + '\x00' * random.randint(10, 80))
                t = self.clientlist[ID]
                t.Load(client)
                return t
        except:
            print sys.exc_info()

    def removeID(self, ID):
        if ID in self.clientlist:
            del self.clientlist[ID]
        
class tcp_remote(threading.Thread):
    def __init__(self, sock, clientID):
        threading.Thread.__init__(self)
        self.sock = sock
        self.ID = clientID
        self.clients = []
        self.mutex = threading.Lock()
        self.SendSYN = 0
        self.RecvSYN = 0
        self.SYNbuffer = {}
        
    def run(self):
        sock = self.sock
        fset = [sock]
        try:
            while len(self.clients):
                r, w, e = select.select(fset, [], [])
                if sock in r:
                    data = sock.recv(1020)
                    if len(data) <= 0:
                        break
                    data = struct.pack("H",self.SendSYN) + data
                    self.SendSYN = (self.SendSYN + 1) % MAXSYN
                    data = struct.pack("H",len(data)) + data
                    while len(self.clients):
                        if random.choice(self.clients[-4:]).send(data):
                            break
                else:
                    break
        except:
            print 'tcp_remote'
            print sys.exc_info()
        finally:
            self.destroy()

    def Load(self, client):
        self.clients.append(client)

    def remove(self, client):
        if client in self.clients:
            self.clients.remove(client)
        if not len(self.clients):
            self.destroy()

    def send(self, data):
        def _send(self, data):
            result = send_all(self.sock, data)
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
                        #print 'SYN out', self.RecvSYN
                        _send(self, self.SYNbuffer.pop(self.RecvSYN))
                    else:
                        break
            else:
                if len(self.SYNbuffer) >= MAXSYNBUFFER:
                    raise Exception('SYNbuffer overflow')
                #print 'SYN need', self.RecvSYN, 'save', syn
                self.SYNbuffer[syn] = data[2:]

        except:
            print 'Tsend'
            print sys.exc_info()
            self.destroy()
        finally:
            self.mutex.release()
                

    def destroy(self):
        TCP_CLIENTS.removeID(self.ID)
        while len(self.clients):
            self.clients.pop().destroy()
        self.sock.close()
    
    
def main():
    global PW, HTTPLOG, TCP_CLIENTS
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    
    with open(filepath('config.json'), 'rb') as f:
        config = json.load(f)
    logging.info('loading config from %s' % filepath('config.json'))

    SERVER = config['server']
    PORT = config['server_port']
    PW = hashlib.sha1(config['password'] + "3dfghuyrfplndd3e2sdrr4dddff").digest()
    IPv6 = int(config['ipv6'])
    CRT = filepath(config['crt'])
    KEY = filepath(config['key'])
    TCP_CLIENTS = tcpproxyhandle()
    

    if IPv6:
        ThreadingTCPServer.address_family = socket.AF_INET6

    HTTPLOG = filepath('http.log')
    
    server = myssl.ThreadingzProxyServer((SERVER,PORT[0]),
                                            zProxyHandle,
                                            CRT,
                                            KEY)
    logging.info("starting server at %s:%d" % tuple(server.server_address[:2]))
    try:
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
        server.shutdown()
        server.server_close()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
        sys.exit(0)

if __name__ == '__main__':
    main()
