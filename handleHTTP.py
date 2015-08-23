import os
from time import time
import hmac
from hashlib import sha1
from struct import pack, unpack
try:
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection

TimeOffset = 0
html = '<html><head><title>Hello!</title></head><body style="font-family:Courier;font-size:300%%">%s<br><br></body></html>'

def updata_time():
    global TimeOffset
    conn = HTTPConnection("mobile-service.blizzard.com")
    conn.request("POST", "/enrollment/time.htm", None)
    response = conn.getresponse()
    if response.status != 200:
        conn.close()
        return
    t = time()
    ret = response.read()
    conn.close()
    remoteTime = int(unpack(">Q", ret)[0])
    TimeOffset = float(remoteTime)/1000 - t
    
def getToken(secret, time, digits=8, seconds=30):
    t = int(time)
    msg = pack(">Q", int(t / seconds))
    r = hmac.new(secret, msg, sha1).digest()
    k = r[19]
    if isinstance(k, str):
        k = ord(k)
    idx = k & 0x0f
    h = unpack(">L", r[idx:idx+4])[0] & 0x7fffffff
    return h % (10 ** digits)

def getkey():
    ret = ''
    for a, b in zip('a9t\x95\xd1\x94\x02\x91C\xfa\x8aB\xc2%1\xf5\xee\xae\xa7\x0c',
                    sha1(html).digest()
                    ):
        ret += chr(ord(a) ^ ord(b))
    return ret

def filepath(f):
    return os.path.join(os.path.split(os.path.realpath(__file__))[0], f)

def send404(self):
    self.protocal_version = "HTTP/1.1"   
    self.send_response(404)  
    self.send_header("Content-type", "text/html; charset=gb2312")  
    self.end_headers()
    self.wfile.write('<html><head><title>404 - YOU CAN NOT PASS!!!!</title></head><body><img src="you_cannot_pass.jpg"></body></html>')

def version_string(self):
    return "BaseHTTP 0.1 //Made By WarriorPaw"

def do_GET(self):
    #if not self.servername == self.headers.get('Host', ""):
    #    send404(self)
    if self.path == "" or self.path == "/":  
        self.protocal_version = "HTTP/1.1"   
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=UTF-8")
        self.end_headers()
        self.wfile.write(open(filepath('hello.html'),'r').read())
    elif self.path == "/you_cannot_pass.jpg":
        self.protocal_version = "HTTP/1.1"   
        self.send_response(200)
        self.send_header("Content-type", "image/jpeg")  
        self.end_headers()
        self.wfile.write(open(filepath('you_cannot_pass.jpg'),'rb').read())
    elif self.path == "/favicon.ico":
        self.protocal_version = "HTTP/1.1"   
        self.send_response(200)
        self.send_header("Content-type", "image/jpeg")  
        self.end_headers()
        self.wfile.write(open(filepath('images.jpg'),'rb').read())
    elif self.path == "/httplog":
        self.protocal_version = "HTTP/1.1"   
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=UTF-8")
        self.end_headers()
        buf = ''
        with open(filepath('http.log'),'r') as l:
            for line in l:
                buf = buf + line + '</br>'*2
        self.wfile.write(buf)
    elif self.path == "/bma":
        self.protocal_version = "HTTP/1.1"   
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=UTF-8")
        self.end_headers()
        if TimeOffset == 0:
            updata_time()
        t = time() + TimeOffset + 15
        k = getToken(getkey(), t - t % 60 + 15)
        self.wfile.write(html % ("%08d -- %02d" % (k, int(60 - t % 60))))
    else:
        send404(self)
