
import re
import urllib.parse
import hashlib
import logging
import secrets
import traceback
from typing import ClassVar
from dataclasses import dataclass
from .enum_ import Algorithm, Qop
from .digest import Digest
from .header import Authorization, WWWAuthenticate

_LOGGER:"logging.Logger" = logging.getLogger(__name__)

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
    self.digest = Digest() #tmp.
    self.last_nonce = ""

  def _gen_expect_digest (
    self, 
    handler:"http.server.BaseHTTPRequestHandler", 
    path:str, 
    nonce:str, 
    nc:str, 
    cnonce:str) -> str:
    return self.digest.gen(
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
