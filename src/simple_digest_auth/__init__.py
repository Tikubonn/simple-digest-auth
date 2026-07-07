
from . import header
from .enum_ import Algorithm, Qop
from .digest import Digest
from .digest_auth import DigestAuth

"""http.server 向けの簡素な Digest 認証の機能を提供します。

Examples
--------
>>> from http.server import BaseHTTPRequestHandler, HTTPServer
>>> from simple_digest_auth import DigestAuth, Algorithm
>>>
>>> auth = DigestAuth("anonymous", "password", "SecretZone")
>>>
>>> class _Handler (BaseHTTPRequestHandler):
>>>   def do_GET (self):
>>>     authorized, stale = auth.authorize(self)
>>>     if authorized:
>>>       self.send_response(200)
>>>       self.send_header("Content-Type", "text/plain")
>>>       self.end_headers()
>>>       self.wfile.write("Authorization was succeed.")
>>>     else:
>>>       auth.send_unauthorized(self, stale)
>>>
>>> with HTTPServer(("127.0.0.1", 8080), _Handler) as server:
>>>   try:
>>>     server.serve_forever()
>>>   except KeyboardInterrupt:
>>>     pass
"""
