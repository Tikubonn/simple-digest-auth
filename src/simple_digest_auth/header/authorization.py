
import re
from typing import ClassVar
from dataclasses import dataclass
from simple_digest_auth.enum_ import Algorithm, Qop

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
  qop:Qop
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
            field_value2, = match3.groups()
          else:
            field_value2 = field_value
          yield field_name, field_value2
        else:
          raise ValueError("Invalid field was detected: {!r}".format(field))
    else:
      raise ValueError("Invalid source was detected: {!r}".format(source))

  @classmethod
  def from_str (cls, source:str) -> "typing.Self":

    """Authorization ヘッダの内容からインスタンスを作成します。
    """

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
