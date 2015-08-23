import ssl, socket, SocketServer, BaseHTTPServer, select
from cStringIO import StringIO

class TCPServer(SocketServer.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile = None,
                 keyfile = None,
                 ssl_version=ssl.PROTOCOL_SSLv23,
                 bind_and_activate=True):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        if certfile or keyfile:
            self.socket = ssl.wrap_socket(self.socket,
                                         server_side=True,
                                         certfile = certfile,
                                         keyfile = keyfile,
                                         ssl_version = ssl_version)
        

class ThreadingTCPServer(SocketServer.ThreadingMixIn, TCPServer): pass

class ThreadingzProxyServer(ThreadingTCPServer):
    # copy from BaseHTTPServer.py
    allow_reuse_address = 1
    def server_bind(self):
        ThreadingTCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port

class zProxyRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):  
    def handleProxy(self):
        pass

    def verify(self):
        pass
    
    def handle(self):
        self.data = self.connection.recv(65535)
        if self.verify():
            del self.data
            self.handleProxy()
        else:
            if len(self.data) < 10:
                con = 0
                while 1:
                    r, w, e = select.select([self.connection], [], [], 0.0001)
                    if con > 20:
                        break
                    if self.connection in r:
                        self.data = self.data + self.connection.recv(65535)
                    else:
                        break
                    con += 1
            tmp_rfile = self.rfile
            self.rfile = StringIO(self.data)
            # copy from BaseHTTPServer.py
            self.close_connection = 1
            self.handle_one_request()
            del self.rfile
            del self.data
            self.rfile = tmp_rfile
            while not self.close_connection:
                self.handle_one_request()
