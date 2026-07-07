
from enum import Enum, auto, unique

@unique
class Algorithm (Enum):

  """ハッシュ関数名を表す列挙型です。
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
