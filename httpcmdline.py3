#!/usr/bin/env python3

__version__ = "httpcmdline/0.1"
__author__ = "karthik@houseofkodai.in"

import sys
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
from urllib.parse import urlparse, parse_qs
from io import BytesIO
from functools import partial

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

  def __init__(self, doit, *args, **kwargs):
    self.doit = doit
    super().__init__(*args, **kwargs)

  def info(self, data, *args, **kwargs):
    response = BytesIO()
    response.write(b'info: Active Threads='+
      str(threading.active_count()).encode() + b' Id=' +
      threading.currentThread().getName().encode() + b'\n')
    response.write(b'Headers: ' + str(self.headers).encode() + b'\n')
    response.write(b'Path: ' + self.path.encode() + b'\n')
    response.write(b'Query-String: ' + str(kwargs).encode() + b'\n')
    return [200, 'text/plain', response.getvalue()]

  def echo(self, data, *args, **kwargs):
    '''
    curl --header "Content-Type:application/octet-stream" --data-binary @asdf.file http://localhost:8080/echo
    following-also-works-as-echo-does not discriminate
    curl --data-binary @asdf.file http://localhost:8080/echo
    '''
    return (200, self.headers.get('Content-Type', 'application/octect-stream'), data)

  def __http_response(self, code, ctype, content):
    clen = 0
    if content:
      clen = len(content)
    self.send_response(code)
    if ctype:
      self.send_header('Content-Type', ctype)
    if (clen > 0):
      self.send_header('Content-Length', len(content))
      self.end_headers()
      if (type(content) == type(b'')):
        self.wfile.write(content)
      else:
        self.wfile.write(str(content).encode())
    else:
      self.end_headers()

  def do_POST(self):
    up = urlparse(self.path)
    parts = up.path[1:].split('/')

    fn = getattr(self, parts[0], None)
    if not fn:
      fn = getattr(self.doit, parts[0], None)
    if not callable(fn):
      return self.send_error(403) #forbidden

    qs = parse_qs(up.query)

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

    self.__http_response(*fn(data,**qs))
    return

  def do_GET(self):
    #path, _, query_string = self.path.partition('?')
    #qs = parse_qs(query_string)
    up = urlparse(self.path)
    parts = up.path[1:].split('/')
    #['/' + '/'.join(parts[:index+1]) for index in range(len(parts))]
    fn = getattr(self, parts[0], None)
    if not fn:
      fn = getattr(self.doit, parts[0], None)
    if callable(fn):
      self.__http_response(*fn(None, None, **parse_qs(up.query)))
      return
    else:
      super().do_GET() #serves directory-listing, files

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
  pass

def httpd(dothis=None, *args):
  hostaddr='0.0.0.0'
  port=8080
  if len(args) > 0:
    port = int(args[0])
    if len(args) > 1:
      hostaddr = args[1]
  svr = ThreadingSimpleServer((hostaddr, port), partial(RequestHandler,dothis))
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
