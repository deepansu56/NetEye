"""显示过滤器：类 Wireshark 语法的子集。

支持：
  字段比较  tcp.port == 80        ip.addr == 192.168.1.0/24
  存在判断  http                  dns
  文本包含  http.request.uri contains "login"
  正则      dns.qry.name ~ ".*\\.cn$"
  逻辑      && || ! ()  以及 and/or/not
  简写      直接写 "tcp"、"dns"、"tls"
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, List, Optional

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<str>"[^"]*"|'[^']*')
    | (?P<op>==|!=|>=|<=|~|>|<)
    | (?P<lp>\()
    | (?P<rp>\))
    | (?P<logic>&&|\|\||\bnot\b|!)
    | (?P<cidr>\d+\.\d+\.\d+\.\d+/\d{1,2})
    | (?P<ip>\d+\.\d+\.\d+\.\d+)
    | (?P<hex>0x[0-9a-fA-F]+)
    | (?P<num>\d+)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
    )
""", re.VERBOSE)


# ---------------------------------------------------------------- 字段取值
def field_values(rec, name: str) -> List[Any]:
    n = name.lower().strip()
    L = rec.layers
    if n == "frame.number":
        return [rec.id]
    if n in ("frame.len", "frame.cap_len"):
        return [rec.length]
    if n == "frame.time":
        return [rec.time]
    if n == "eth.src":
        return [getattr(rec, "src", "")] if "arp" not in L and ":" in (rec.src or "") else []
    if n == "eth.dst":
        return [getattr(rec, "dst", "")] if ":" in (rec.dst or "") else []
    if n == "ip.addr":                       # 源或目的任一匹配
        return [rec.src, rec.dst]
    if n in ("ip.src", "ipv6.src"):
        return [rec.src]
    if n in ("ip.dst", "ipv6.dst"):
        return [rec.dst]
    if n == "ip.proto":
        return [rec.ip_proto]
    if n == "ip.ttl":
        return [rec.ttl]
    if n == "tcp.srcport":
        return [rec.src_port] if rec.proto == "TCP" else []
    if n == "tcp.dstport":
        return [rec.dst_port] if rec.proto == "TCP" else []
    if n == "udp.srcport":
        return [rec.src_port] if rec.proto == "UDP" else []
    if n == "udp.dstport":
        return [rec.dst_port] if rec.proto == "UDP" else []
    if n in ("tcp.port", "udp.port", "port"):
        return [rec.src_port, rec.dst_port] if rec.src_port else []
    if n == "tcp.flags":
        return [rec.tcp_flags] if rec.proto == "TCP" else []
    if n.startswith("tcp.flags."):
        bit = n.rsplit(".", 1)[-1].upper()
        alias = {"RESET": "RST", "PUSH": "PSH"}          # Wireshark 别名
        bit = alias.get(bit, bit)
        order = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10,
                 "URG": 0x20, "ECE": 0x40, "CWR": 0x80, "NS": 0x100}
        if bit not in order or rec.proto != "TCP":
            return []
        return [1 if (rec.tcp_flags or 0) & order[bit] else 0]
    if n == "tcp.seq":
        return [rec.seq] if rec.proto == "TCP" else []
    if n == "tcp.ack":
        return [rec.ack] if rec.proto == "TCP" else []
    if n == "tcp.window":
        return [rec.window] if rec.proto == "TCP" else []
    if n == "tcp.len":
        return [rec.payload_len] if rec.proto == "TCP" else []
    if n == "tcp.stream":
        return [rec.stream]
    if n in ("icmp.type", "icmp.code"):
        return [getattr(rec, n.replace(".", "_"), None)]
    if n == "dns.qry.name":
        return [rec.dns_name] if rec.dns_name else []
    if n == "http.request.method":
        return [rec.http_method] if rec.http_method else []
    if n == "http.request.uri":
        return [rec.http_uri] if rec.http_uri else []
    if n == "http.host":
        return [rec.http_host] if rec.http_host else []
    if n == "http.response.code":
        return [rec.http_code] if rec.http_code else []
    if n == "tls.handshake.type":
        return [rec.tls_type] if rec.tls_type else []
    if n == "tls.sni":
        return [rec.tls_sni] if rec.tls_sni else []
    if n == "doip.payload_type":
        return [rec.tls_type] if rec.app == "DoIP" else []
    if n == "someip.message_id":
        return [rec.tls_type] if rec.app == "SOME/IP" else []
    if n in ("protocol", "proto"):
        return [rec.proto]
    return []


def has_layer(rec, name: str) -> bool:
    n = name.lower()
    return n in rec.layers or n == (rec.proto or "").lower() or n == (rec.app or "").lower()


# ---------------------------------------------------------------- 词法
def _tokenize(expr: str):
    pos, out = 0, []
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            nxt = _TOKEN.search(expr, pos)
            if not nxt:
                raise SyntaxError(f"无法解析的位置 {pos}: {expr[pos:pos + 20]}")
            pos = nxt.start()
            continue
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        out.append((kind, val))
    return out


class _Parser:
    """递归下降：or → and → not → primary。"""

    def __init__(self, tokens) -> None:
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def next(self):
        t = self.peek()
        self.i += 1
        return t

    def parse(self) -> Callable[[Any], bool]:
        node = self.parse_or()
        if self.i < len(self.toks):
            raise SyntaxError("表达式尾部有多余内容")
        return node

    def parse_or(self):
        left = self.parse_and()
        while True:
            k, v = self.peek()
            if k == "logic" and v in ("||", "or"):
                self.next()
                right = self.parse_and()
                left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
            else:
                return left

    def parse_and(self):
        left = self.parse_not()
        while True:
            k, v = self.peek()
            if k == "logic" and v in ("&&", "and"):
                self.next()
                right = self.parse_not()
                left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
            else:
                return left

    def parse_not(self):
        k, v = self.peek()
        if k == "logic" and v in ("!", "not"):
            self.next()
            inner = self.parse_not()
            return lambda r: not inner(r)
        return self.parse_primary()

    def parse_primary(self):
        k, v = self.peek()
        if k == "lp":
            self.next()
            node = self.parse_or()
            if self.peek()[0] != "rp":
                raise SyntaxError("括号不匹配")
            self.next()
            return node
        if k == "ident":
            self.next()
            nk, nv = self.peek()
            # 纯协议存在判断
            if nk in (None, "rp", "logic"):
                return lambda r, n=v.lower(): has_layer(r, n)
            if nk == "op":
                self.next()
                return self._comparison(v, nv)
            if nk in ("ident",):
                # "contains" / "matches" 关键字
                if nv.lower() in ("contains", "matches", "has"):
                    self.next()
                    vk, vv = self.next()
                    if vk != "str" and vk != "ident" and vk != "num":
                        raise SyntaxError(f"contains 需要字符串参数，得到 {vv}")
                    target = vv.strip("\"'")
                    if nv.lower() == "matches":
                        rx = re.compile(target, re.I)
                        return lambda r, f=v, rx=rx: any(
                            rx.search(str(x)) for x in field_values(r, f) if x is not None)
                    return lambda r, f=v, t=target.lower(): any(
                        t in str(x).lower() for x in field_values(r, f) if x is not None)
            raise SyntaxError(f"字段 {v} 后无法识别的内容：{nv}")
        raise SyntaxError(f"意外的记号：{v}")

    def _comparison(self, field: str, op: str):
        k, v = self.next()
        if k is None:
            raise SyntaxError(f"{field} {op} 之后缺少比较值")
        if k == "cidr":
            net = ipaddress.ip_network(v, strict=False)
            return lambda r, f=field, net=net: any(
                _in_net(x, net) for x in field_values(r, f) if x is not None)
        if k == "str":
            val: Any = v.strip("\"'")
        elif k == "hex":
            val = int(v, 16)
        elif k == "num":
            val = int(v)
        elif k == "ip":
            val = v
        else:
            val = v

        def cmp(r, f=field, op=op, val=val) -> bool:
            for x in field_values(r, f):
                if x is None:
                    continue
                try:
                    if op == "==":
                        if _eq(x, val):
                            return True
                    elif op == "!=":
                        if not _eq(x, val):
                            return True
                    else:
                        a, b = _num(x), _num(val)
                        if a is None or b is None:
                            continue
                        if op == ">" and a > b:
                            return True
                        if op == "<" and a < b:
                            return True
                        if op == ">=" and a >= b:
                            return True
                        if op == "<=" and a <= b:
                            return True
                        if op == "~" and re.search(str(val), str(x), re.I):
                            return True
                except Exception:                                   # noqa: BLE001
                    continue
            return False

        if op == "!=":
            # != 语义：没有任何值等于目标 → 为真
            def ne(r, f=field, val=val) -> bool:
                vals = [x for x in field_values(r, f) if x is not None]
                if not vals:
                    return True
                return not any(_eq(x, val) for x in vals)
            return ne
        return cmp


def _in_net(value, net) -> bool:
    try:
        return ipaddress.ip_address(str(value)) in net
    except Exception:                                               # noqa: BLE001
        return False


def _num(x):
    if isinstance(x, (int, float)):
        return x
    try:
        return int(str(x), 0)
    except Exception:                                               # noqa: BLE001
        try:
            return float(x)
        except Exception:                                           # noqa: BLE001
            return None


def _eq(a, b) -> bool:
    if isinstance(b, str) and not str(b).replace(".", "").isdigit():
        return str(a).lower() == str(b).lower()
    na, nb = _num(a), _num(b)
    if na is not None and nb is not None:
        return na == nb
    return str(a).lower() == str(b).lower()


def compile_filter(expr: str) -> Optional[Callable[[Any], bool]]:
    """编译显示过滤器；空表达式返回 None（表示不过滤）。"""
    if not expr or not expr.strip():
        return None
    try:
        tokens = _tokenize(expr)
        if not tokens:
            return None
        return _Parser(tokens).parse()
    except Exception:                                               # noqa: BLE001
        return None


def validate_filter(expr: str) -> Optional[str]:
    """返回错误信息，合法返回 None。"""
    if not expr or not expr.strip():
        return None
    try:
        tokens = _tokenize(expr)
        _Parser(tokens).parse()
        return None
    except Exception as exc:                                        # noqa: BLE001
        return str(exc)
