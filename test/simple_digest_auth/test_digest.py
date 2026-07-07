
import pytest
from simple_digest_auth import Digest, Algorithm, Qop

@pytest.mark.parametrize(
  [
    "user",
    "password",
    "realm",
    "http_method",
    "http_uri",
    "nonce",
    "nc",
    "cnonce",
    "qop",
    "algorithm",
    "expect_digest",
  ],
  [
    pytest.param(
      "Mufasa",
      "Circle of Life",
      "http-auth@example.org",
      "GET",
      "/dir/index.html",
      "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
      "00000001",
      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
      Qop.AUTH,
      Algorithm.MD5,
      "8ca523f5e9506fed4657c9700eebdbec"
    ),
  ]
)
def test_digest_gen (
  user:str,
  password:str,
  realm:str,
  http_method:str,
  http_uri:str,
  nonce:str,
  nc:str,
  cnonce:str,
  qop:"simple_digest_auth.Qop",
  algorithm:"simple_digest_auth.Algorithm",
  expect_digest:str):
  digest = Digest()
  assert digest.gen(
    user,
    password,
    realm,
    http_method,
    http_uri,
    nonce,
    nc,
    cnonce,
    qop,
    algorithm
  ) == expect_digest
