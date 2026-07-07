
import re
import urllib.parse
import hashlib
import logging
import secrets
import traceback
from enum import Enum, auto, unique
from typing import ClassVar
from dataclasses import dataclass

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

_LOGGER:"logging.Logger" = logging.getLogger(__name__)

@unique
class Algorithm (Enum):

  """ハッシュアルゴリズムを表す列挙型です。
  """

  MD5 = "MD5"
  SHA256 = "SHA-256"
  SHA512 = "SHA-512"

@unique
class Qop (Enum):

  """保護品質を表す列挙型です。
  """

  AUTH = "auth"
  AUTH_INT = "auth-int"

@dataclass(frozen=True)
class WWWAuthenticate:

  """WWW-Authenticate ヘッダを表すデータクラスです。
  """

  realm:str
  nonce:str
  opaque:str
  stale:bool
  algorithm:Algorithm
  qop:Qop
  userhash:bool

  def as_str (self) -> str:
    return 'Digest realm="{realm:s}", nonce="{nonce:s}", opaque="{opaque:s}", stale="{stale:s}", qop="{qop:s}", charset="UTF-8", algorithm="{algorithm:s}", userhash="{userhash:s}"'.format(
      realm=self.realm, 
      nonce=self.nonce, 
      opaque=self.opaque, 
      stale="true" if self.stale else "false", 
      qop=self.qop.value,
      algorithm=self.algorithm.value,
      userhash="true" if self.userhash else "false"
    )

@dataclass(frozen=True)
class Authorization:

  """Authorization ヘッダを表すデータクラスです。
  """

  response:str
  username:str
  uri:str
  realm:str
  opaque:str
  algorithm:Algorithm
  nonce:str
  nc:str
  qop:str
  cnonce:str
  userhash:bool #is optional.

  _REGEXP_BODY:ClassVar[re.Pattern] = re.compile(r'^Digest (.*?)$')
  _REGEXP_FIELD:ClassVar[re.Pattern] = re.compile(r'^(\S+)=(.*?)$')
  _REGEXP_QUOTED:ClassVar[re.Pattern] = re.compile(r'^"(.*?)"$')

  @classmethod
  def _parse_fields (cls, source:str) -> "typing.Generator[tuple[str, str], None, None]":
    match = cls._REGEXP_BODY.match(source)
    if match:
      body, = match.groups()
      for field in body.split(","):
        match2 = cls._REGEXP_FIELD.match(field.strip())
        if match2:
          field_name, field_value = match2.groups()
          match3 = cls._REGEXP_QUOTED.match(field_value)
          if match3:
            field_value, = match3.groups()
          yield field_name, field_value
        else:
          raise ValueError("Invalid field was detected: {!r}".format(field))
    else:
      raise ValueError("Invalid source was detected: {!r}".format(source))

  @classmethod
  def from_str (cls, source:str) -> "typing.Self":
    fields = dict(cls._parse_fields(source))
    return cls(
      response=fields["response"],
      username=fields["username"],
      uri=fields["uri"],
      realm=fields["realm"],
      opaque=fields.get("opaque", ""),
      algorithm=Algorithm(fields["algorithm"]),
      nonce=fields["nonce"],
      nc=fields["nc"],
      qop=Qop(fields["qop"]),
      cnonce=fields["cnonce"],
      userhash={"true": True, "false": False}[fields.get("userhash", "false")]
    )

def calc_digest (
  user:str, 
  password:str, 
  realm:str, 
  http_method:str, 
  http_uri:str, 
  nonce:str,
  nc:str,
  cnonce:str,
  qop:"simple_digest_auth.Qop",
  algorithm:"simple_digest_auth.Algorithm") -> str:

  """引数の値からハッシュダイジェストを算出します。

  Parameters
  ----------
  user : str
    算出に用いられるユーザ名です。
  password : str
    算出に用いられるユーザのパスワードです。
  realm : str
    算出に用いられる保護領域名です。
  http_method : str
    算出に用いられる HTTP メソッドです。
  http_uri : str
    算出に用いられる HTTP URL です。
  nonce : str
    算出に用いられる nonce 値です。
  nc : str
    算出に用いられる nc 値です。
  cnonce : str
    算出に用いられる cnonce 値です。
  qop : simple_digest_auth.Qop
    算出に用いられる保護品質です。
  algorithm : simple_digest_auth.Algorithm
    算出に用いられるハッシュアルゴリズムです。

  Returns
  -------
  str
    所定の手順で算出されたハッシュダイジェストです。
  """

  a1 = "{:s}:{:s}:{:s}".format(user, realm, password)
  a2 = "{:s}:{:s}".format(http_method, http_uri)
  result = hashlib.new(
    algorithm.value,
    "{:s}:{:s}:{:s}:{:s}:{:s}:{:s}".format(
      hashlib.new(algorithm.value, a1.encode("utf-8")).hexdigest(),
      nonce,
      nc,
      cnonce,
      qop.value,
      hashlib.new(algorithm.value, a2.encode("utf-8")).hexdigest()
    ).encode("utf-8")
  ).hexdigest()
  return result

class DigestAuth:

  """1ユーザに対する Digest 認証機能を提供します。
  """

  def __init__ (
    self, 
    user:str, 
    password:str, 
    realm:str, 
    opaque:str="", 
    algorithm:"simple_digest_auth.Algorithm"=Algorithm.SHA256):

    """インスタンスの初期化を行います。

    Parameters
    ----------
    user : str
      認証するユーザ名です。
    password : str
      認証するユーザのパスワードです。
    realm : str
      認証する保護領域名です。
    opaque : str
      認証時に相手に送信する任意の文字列です。
      未指定ならば空の文字列が使用されます。
    nonce : str
      認証時に相手に送信する任意の無作為な文字列です。
      未指定ならば secrets.token_hex 関数の結果が使用されます。
    algorithm : simple_digest_auth.Algorithm
      ハッシュダイジェストの算出に用いられるアルゴリズムです。
      未指定ならば Algorithm.SHA256 が使用されます。
    """

    self.user = user
    self.password = password
    self.realm = realm
    self.opaque = opaque
    self.algorithm = algorithm
    self.last_nonce = ""

  def _gen_expect_digest (
    self, 
    handler:"http.server.BaseHTTPRequestHandler", 
    path:str, 
    nonce:str, 
    nc:str, 
    cnonce:str) -> str:
    return calc_digest(
      user=self.user,
      password=self.password,
      realm=self.realm,
      http_method=handler.command,
      http_uri=path,
      nonce=self.last_nonce,
      nc=nc,
      cnonce=cnonce,
      qop=Qop.AUTH,
      algorithm=self.algorithm
    )

  def authorize (self, handler:"http.server.BaseHTTPRequestHandler") -> tuple[bool, bool]:

    """BaseHTTPRequestHandler の内容から認証を試みます。

    Parameters
    ----------
    handler : http.server.BaseHTTPRequestHandler
      認証情報を取得するために参照される BaseHTTPRequestHandler オブジェクトです。

    Returns
    -------
    tuple[bool, bool]
      2つの真偽値の組を返します。
      1つ目は認証の成功の有無を表す真偽値です。
      2つ目は認証失敗時に無効な nonce 値が指定されたかどうかを表す真偽値です。
      2つ目の返り値は send_unauthorized メソッドの引数に使用することができます。
    """

    try:
      authorization_content = handler.headers.get("Authorization", "")
      if authorization_content:
        authorization = Authorization.from_str(authorization_content)
        if (authorization.realm == self.realm and 
            authorization.opaque == self.opaque and 
            authorization.qop == Qop.AUTH and #qop="auth" のみ対応
            authorization.algorithm == self.algorithm and
            authorization.userhash == False): #userhash="false" のみ対応
          if authorization.nonce == self.last_nonce:
            parsed_url = urllib.parse.urlparse(handler.path)
            expect_digest = self._gen_expect_digest(
              handler, 
              path=parsed_url.path, 
              nonce=authorization.nonce, 
              nc=authorization.nc, 
              cnonce=authorization.cnonce
            )
            if secrets.compare_digest(authorization.response, expect_digest):

              _LOGGER.info("Authorization was succeed.") #log.

              return True, False
            else:

              _LOGGER.info("Authorization was failed: {:s}".format("Mismatched hash digest.")) #log.

              return False, False
          else:

            _LOGGER.info("Authorization was failed: {:s}".format("Matched hash digest, but mismatched nonce fields.")) #log.

            return False, True
        else:

          _LOGGER.info("Authorization was failed: {:s}".format("Mismatched realm, opaque, qop, algorithm, userhash fields.")) #log.

          return False, False
      else:

        _LOGGER.info("Authorization was failed: {:s}".format("Authorization header not found.")) #log.

        return False, False
    except:
      traceback.print_exc()

      _LOGGER.info("Authorization was failed: {:s}".format("Caused some error inside server on processing.")) #log.

      return False, False
  
  def send_unauthorized (self, handler:"http.server.BaseHTTPRequestHandler", stale:bool):

    """接続先の相手に認証情報を要求します。

    Parameters
    ----------
    handler : http.server.BaseHTTPRequestHandler
      認証情報を要求するために使われる BaseHTTPRequestHandler オブジェクトです。
    stale : bool
      ...
    """

    self.last_nonce = secrets.token_hex()
    www_authentication = WWWAuthenticate(
      realm=self.realm,
      nonce=self.last_nonce,
      opaque=self.opaque,
      stale=stale,
      algorithm=self.algorithm,
      qop=Qop.AUTH,
      userhash=False
    )
    handler.send_response(401)
    handler.send_header("WWW-Authenticate", www_authentication.as_str())
    handler.end_headers()
