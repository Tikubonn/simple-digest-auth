
from dataclasses import dataclass
from simple_digest_auth.enum_ import Algorithm, Qop

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
