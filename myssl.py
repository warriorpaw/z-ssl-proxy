import ssl, socket, SocketServer, BaseHTTPServer, select

try:
    max_ssl_version = ssl.PROTOCOL_TLSv1_2
except:
    max_ssl_version = ssl.PROTOCOL_TLSv1


class TCPServer(SocketServer.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile=None,
                 keyfile=None,
                 ssl_version=max_ssl_version,
                 bind_and_activate=True):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        if certfile or keyfile:
            self.socket = ssl.wrap_socket(self.socket,
                                          server_side=True,
                                          certfile=certfile,
                                          keyfile=keyfile,
                                          ssl_version=ssl_version)


class ThreadingzProxyServer(SocketServer.ThreadingMixIn, TCPServer):
    pass


class zProxyRequestHandler(SocketServer.StreamRequestHandler):
    def handleProxy(self):
        pass

    def verify(self):
        pass

    def handleHTTP(self):
        pass

    def handle(self):
        data = self.verify()
        if data:
            self.handleHTTP(data)
        else:
            self.handleProxy()
