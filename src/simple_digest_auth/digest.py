
import caches
import hashlib
from .enum_ import Algorithm, Qop

class Digest:

  """Digest認証のダイジェストを計算する機能を提供します。
  """

  def _a1_caches_calc_value_func (self, args:"tuple[str, str, str, simple_digest_auth.Algorithm]", kwargs:dict[str, str]) -> str:
    user, realm, password, algorithm = args
    return hashlib.new(
      algorithm.value,
      "{:s}:{:s}:{:s}".format(user, realm, password).encode("utf-8")
    ).hexdigest()

  def _a2_caches_calc_value_func (self, args:"tuple[str, str, simple_digest_auth.Algorithm]", kwargs:dict[str, str]) -> str:
    http_method, http_uri, algorithm = args
    return hashlib.new(
      algorithm.value,
      "{:s}:{:s}".format(http_method, http_uri).encode("utf-8")
    ).hexdigest()

  def __init__ (self, max_cache_count:tuple[int, int]=(8, 16)):

    """インスタンスの初期化を行います。

    Parameters
    ----------
    max_cache_count : tuple[int, int]
      Digest認証の A1, A2 の最大キャッシュ数を指定します。
      未指定ならば (8, 16) が使用されます。
    """

    a1_max_cache_count, a2_max_cache_count = max_cache_count
    self._a1_caches = caches.Caches(a1_max_cache_count, calc_value_func=self._a1_caches_calc_value_func)
    self._a2_caches = caches.Caches(a2_max_cache_count, calc_value_func=self._a2_caches_calc_value_func)

  def gen (
    self,
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

    return hashlib.new(
      algorithm.value,
      "{:s}:{:s}:{:s}:{:s}:{:s}:{:s}".format(
        self._a1_caches.get((user, realm, password, algorithm)),
        nonce,
        nc,
        cnonce,
        qop.value,
        self._a2_caches.get((http_method, http_uri, algorithm))
      ).encode("utf-8")
    ).hexdigest()
