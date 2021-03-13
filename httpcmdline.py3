#!/usr/bin/env python3

__version__ = "httpcmdline/0.2"
__author__ = "karthik@houseofkodai.in"

import sys
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
from urllib.parse import urlparse, parse_qs
from io import BytesIO
from functools import partial
from base64 import standard_b64encode
from hashlib import sha1

class Doit:
  '''
  each command returns a 3tuple [http-statue-code, content-type, content]
  standard http-status-codes:
    200 OK/Updated
    201 Created
    400 Error
    404 Not Found
    406 Invalid data
  '''
  def __init__(self, path='.'):
    # load from path of pickles - from current-directory
    # to move-to directory of where the script resides
    #os.chdir(os.path.dirname(__file__))
    #print('loading from', os.getcwd())
    pass

  def request1(self, data, *args, **kwargs):
    return 200, 'text/plain', 'pndng request1 ' + str(len(data)) + ' bytes args=' + str(args) + ' kwargs=' + str(kwargs)

  def request2(self, data, *args, **kwargs):
    return 200, 'text/plain', 'pndng request2 ' + str(len(data)) + ' bytes args=' + str(args) + ' kwargs=' + str(kwargs)

class RequestHandler(SimpleHTTPRequestHandler):
  '''
  pndng: testing http/1.1 multiple-request-same-connection
  single-requests can be closed with "self.close_connection = True"
  '''
  server_version = __version__
  protocol_version = 'HTTP/1.1'
  _ws_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
  _ws_opcode_cont = 0x0
  _ws_opcode_text = 0x1
  _ws_opcode_binary = 0x2
  _ws_opcode_close = 0x8
  _ws_opcode_ping = 0x9
  _ws_opcode_pong = 0xa
  mutex = threading.Lock()

  def __init__(self, *args, **kwargs):
    self.doit = kwargs.pop('doit', None)
    self._auth = kwargs.pop('auth', None)
    self.ws_ready = False
    super().__init__(*args, **kwargs)
    #directory = kwargs.pop('directory', None)
    #super().__init__(*args, directory=directory)

  def info(self, data, *args, **kwargs):
    parsed_path = urlparse(self.path)
    result = [
        'SERVER:',
        'server_version={}'.format(self.server_version),
        'sys_version={}'.format(self.sys_version),
        'protocol_version={}'.format(self.protocol_version),
        'active Thread Count={}'.format(threading.active_count()),
        'current Thread id={}'.format(threading.currentThread().getName()),
        '',
        'CLIENT:',
        'client_address={} ({})'.format(self.client_address, self.address_string()),
        'command={}'.format(self.command),
        'path={}'.format(self.path),
        'query={}'.format(parsed_path.query),
        'real path={}'.format(parsed_path.path),
        'request_version={}'.format(self.request_version),
        '',
        'HEADERS:',
    ]
    for name, value in sorted(self.headers.items()):
      result.append('{}={}'.format(name, value.rstrip()))
    result.append('')
    return [200, 'text/plain; charset=utf-8', '\r\n'.join(result)]

  def echo(self, data, *args, **kwargs):
    '''
    curl --header "Content-Type:application/octet-stream" --data-binary @asdf.file http://localhost:8080/echo
    following-also-works-as-echo-does not discriminate
    curl --data-binary @asdf.file http://localhost:8080/echo
    '''
    return (200, self.headers.get('Content-Type', 'application/octect-stream'), data)


  def ws_read(self,rfile):
    preamble = rfile.read(2)
    opcode = preamble[0] & 0x0F
    mask = preamble[1] >> 7
    length = preamble[1] & 0x7f

    if length == 126:
      length = int.from_bytes(rfile.read(2), 'big')
    elif length == 127:
      length = int.from_bytes(rfile.read(4), 'big')
    if mask:
      mask_key = rfile.read(4)
    data = rfile.read(length)
    if mask:
      data = bytes([data[i] ^ mask_key[i % 4] for i in range(len(data))])
    if opcode == self._ws_opcode_text:
      data = data.decode('utf-8')

    if opcode == self._ws_opcode_close:
      self.ws_close()
    elif opcode == self._ws_opcode_ping:
      self.ws_write(data, self.ws_opcode_pong)
    elif opcode == self._ws_opcode_pong:
      pass
    else:
      return data, opcode

  def ws_write(self,wfile,data,opcode=0x00):
    # Setting fin to 1
    #preamble = 1 << 7
    preamble = 0x80 + opcode
    if isinstance(data, str):
      preamble |= 1
      data = data.encode('utf-8')
    else:
      preamble |= 2
    frame = bytes([preamble])
    nbytes = len(data)
    if len(msg) <= 125:
      frame += bytes([nbytes])
    elif len(msg) < 2 ** 16:
      frame += bytes([126])
      frame += nbytes.to_bytes(2, 'big')
    else:
      frame += bytes([127])
      frame += nbytes.to_bytes(4, 'big')
    frame += data
    return wfile.write(frame) #two writes are probably better - check first

  def ws_close(self):
    self.close_connection = 1
    if self.ws_ready:
      #avoid closing a single socket multiple times during send/receive.
      self.mutex.acquire()
      self.ws_ready = False
      #Terminate BaseHTTPRequestHandler.handle() loop:
      try:
        self.wfile.write(b'\x88\x00') #server-to-client websocket-close-message client-to-server b'\x88\x80\x00\x00\x00\x00'
      except:
        pass
      self.mutex.release()

  def ws_handshake(self):
    handshake_key = self.headers.get('Sec-WebSocket-Key', None)
    if ((handshake_key == None) or
        (self.headers.get('Sec-WebSocket-Version', None) != '13') or
        (self.headers.get('Connection', None) != 'Upgrade') or
        (self.headers.get('Upgrade', None) != 'websocket')):
      return False
    self.send_response(101)
    self.send_header('Upgrade', 'websocket')
    self.send_header('Connection', 'upgrade')
    self.send_header('Sec-WebSocket-Accept', standard_b64encode(sha1((handshake_key + self._ws_GUID).encode()).digest()).decode())
    self.end_headers()
    self.ws_ready = True
    return True

  def ws(self, *args, **kwargs):
    '''
    https://sookocheff.com/post/networking/how-do-websockets-work/
    curl --no-buffer \
       --header "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
       --header "Sec-WebSocket-Version: 13" \
       --header "Connection: Upgrade" \
       --header "Upgrade: websocket" \
       http://localhost:8080/ws
    '''
    if not self.ws_handshake():
      return self.send_error(403)
    while True:
      try:
        msg, opcode = self.ws_read(self.rfile)
        if not self.ws_ready:
          # got close
          break
        if msg:
          self.ws_write(self.wfile, msg, opcode)
      except:
        #some exception
        break
    self.ws_close()
    return [0,None,None]

  def _http_response(self, code, ctype, content):
    if 0 == code: return #used-by-websocket handler
    clen = 0
    if content:
      clen = len(content)
    self.send_response(code)
    if ctype:
      self.send_header('Content-Type', ctype)
    self.send_header('Content-Length', clen)
    self.end_headers()
    if (clen > 0):
      if isinstance(content, bytes):
        self.wfile.write(content)
      else:
        self.wfile.write(str(content).encode())

  def isAuthorized(self):
    if (self.headers.get('Authorization') != self._auth):
      self.close_connection = True
      self.send_response(401)
      self.send_header('WWW-Authenticate', 'Basic realm="'+self.headers.get('Host', '???')+'"')
      self.end_headers()
      return False
    return True

  def do_POST(self):
    if self._auth and (not self.isAuthorized()): return
    up = urlparse(self.path)
    parts = up.path[1:].split('/')

    fn = getattr(self, parts[0], None)
    if not fn:
      fn = getattr(self.doit, parts[0], None)
    if not callable(fn):
      return self.send_error(403) #forbidden

    qs = parse_qs(up.query)

    #pndng: transfer-encoding-chunked
    try:
      clen = int(self.headers.get('content-length', 0))
    except:
      clen = 0
    if (clen < 1):
      return self.send_error(411) #Length Required

    # 1 MB - set to max length
    if (clen > (1*(1024**2))):
      return self.send_error(411) #Length Required

    try:
      data = self.rfile.read(clen)
    except:
      return self.send_error(500) #pndng

    self._http_response(*fn(data,**qs))
    return

  def do_GET(self):
    if self._auth and (not self.isAuthorized()): return
    #path, _, query_string = self.path.partition('?')
    #qs = parse_qs(query_string)
    up = urlparse(self.path)
    parts = up.path[1:].split('/')
    #['/' + '/'.join(parts[:index+1]) for index in range(len(parts))]
    fn = getattr(self, parts[0], None)
    if not fn:
      fn = getattr(self.doit, parts[0], None)
    if callable(fn):
      self._http_response(*fn(None, None, **parse_qs(up.query)))
      return
    else:
      super().do_GET() #serves directory-listing, files

class ThreadedSimpleServer(ThreadingMixIn, HTTPServer):
  pass

def httpd(doit=None, *args):
  hostaddr = '0.0.0.0'
  port = 8080
  auth = None
  argc = len(args)
  if argc > 0:
    port = int(args[0])
    if argc > 1:
      hostaddr = args[1]
      if argc > 3:
        auth = "Basic " + standard_b64encode(f"{args[2]}:{args[3]}".encode()).decode()
  #print(str(auth))
  svr = ThreadedSimpleServer((hostaddr, port), partial(RequestHandler,doit=doit,auth=auth))
  svr.timeout = 5
  print('Starting http server (' + hostaddr + ':' + str(port) + '), use <Ctrl-C> to stop')
  try:
    svr.serve_forever()
  except KeyboardInterrupt:
    pass
  svr.server_close()
  print("http server stopped.")

if __name__ == '__main__':
  doit = Doit()
  #print(inspect.signature(doit))
  if (len(sys.argv) > 1):
    if 'http' == sys.argv[1]:
      httpd(doit, *sys.argv[2:])
      sys.exit(0)
    else:
      fn = getattr(doit, sys.argv[1], None)
      if callable(fn):
        code, ctype, content = fn(sys.stdin.buffer.read(), *sys.argv[2:])
        print(code)
        print(ctype)
        print(content)
        sys.exit(0)
  doit_method_list = [fn for fn in dir(doit) if callable(getattr(doit, fn)) and not fn.startswith('__')]
  print('usage: ' + __version__ + ''' [commands] [params]
  http [port=8080] [hostaddr='0.0.0.0']
  Doit
    \
''' + '\n    '.join(doit_method_list))
