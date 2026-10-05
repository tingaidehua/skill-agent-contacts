#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
universal_agent_comm / core.py
==============================
全球去中心化 Agent 通讯录 · 核心协议组件（种子协议 v1）

本模块为任意 Agent 沙箱提供一套最小、可移植的去中心化通讯能力：
  1. DID 身份引擎  —— secp256k1 密钥对；公钥（x-only hex）即全球唯一 ID；
                     可导出标准 JSON 名片，并兼容 npub/nsec（bech32）。
  2. E2EE 加密引擎  —— 严格遵循 NIP-04：
                     ECDH（secp256k1）协商共享密钥 -> AES-256-CBC 加密明文。
  3. 网络路由引擎  —— 通过公共 Nostr 中继（Relays）发布/订阅 Kind-4 加密事件，
                     事件按 NIP-01 规范做 BIP-340 Schnorr 签名。

设计约束（面向"仅有出口网络、无公网 IP"的沙箱）：
  * 只发起出站连接（WSS/HTTPS），从不监听端口；
  * 代理感知：自动读取 https_proxy/HTTPS_PROXY/all_proxy 环境变量（含认证）；
  * 纯 Python 实现，依赖仅为：cryptography / coincurve / websocket-client。

安全说明：
  * 私钥只存在于本地内存与本地文件（0600 权限），永不经过网络；
  * NIP-04 在生产环境建议升级到 NIP-44（本版本为与种子协议兼容采用 NIP-04）。
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# ---------------------------------------------------------------- 依赖检查
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as e:  # pragma: no cover
    raise SystemExit(f"[core] 缺少依赖 cryptography，请先 pip install -r requirements.txt ({e})")

try:
    from coincurve import PrivateKey as _CCPrivateKey
    from coincurve import PublicKeyXOnly as _CCPublicKeyXOnly
except ImportError as e:  # pragma: no cover
    raise SystemExit(f"[core] 缺少依赖 coincurve，请先 pip install -r requirements.txt ({e})")

try:
    import websocket
except ImportError as e:  # pragma: no cover
    raise SystemExit(f"[core] 缺少依赖 websocket-client，请先 pip install -r requirements.txt ({e})")

# ================================================================ 常量
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DM_KIND = 4  # NIP-04 加密私信事件类型


# ================================================================ 代理配置
def proxy_kwargs() -> dict:
    """从环境变量解析出站代理参数（供 websocket-client 使用）。

    凭证只从环境变量读取，不写入任何文件或日志。
    """
    for var in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
                "http_proxy", "HTTP_PROXY"):
        raw = os.environ.get(var)
        if not raw:
            continue
        p = urlparse(raw)
        if not p.hostname:
            continue
        kw = {"http_proxy_host": p.hostname,
              "http_proxy_port": p.port or 3128,
              "proxy_type": "http"}
        if p.username:
            kw["http_proxy_auth"] = (p.username, p.password or "")
        return kw
    return {}


# ================================================================ 1. DID 身份引擎
def generate_keypair() -> tuple[str, str]:
    """生成 secp256k1 密钥对。返回 (private_key_hex, public_key_xonly_hex)。"""
    while True:
        secret = secrets.token_bytes(32)
        if 1 <= int.from_bytes(secret, "big") < _SECP256K1_N:
            break
    priv_hex = secret.hex()
    return priv_hex, privkey_to_pubkey(priv_hex)


def privkey_to_pubkey(priv_hex: str) -> str:
    """由私钥推导 x-only 公钥（64 hex 字符）——即该 Agent 的全球唯一 ID。"""
    pk = _CCPrivateKey(bytes.fromhex(priv_hex))
    return pk.public_key.format(compressed=True)[1:].hex()


def _y_from_x(x: int) -> int:
    """由 secp256k1 曲线方程恢复 y（取偶数 y，与 x-only 公钥约定一致）。"""
    y_sq = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
    y = pow(y_sq, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    return y if y % 2 == 0 else _SECP256K1_P - y


# ---------------- bech32（npub / nsec 互操作） ----------------
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_encode(hrp: str, data: bytes) -> str:
    def convertbits(d, frm, to, pad=True):
        acc = bits = 0
        out = []
        for b in d:
            acc = (acc << frm) | b
            bits += frm
            while bits >= to:
                bits -= to
                out.append((acc >> bits) & ((1 << to) - 1))
        if pad and bits:
            out.append((acc << (to - bits)) & ((1 << to) - 1))
        return out
    data5 = convertbits(data, 8, 5)
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data5 + [0] * 6) ^ 1
    checksum = [(pm >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data5 + checksum)


def _bech32_decode(s: str):
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1:
        raise ValueError("invalid bech32")
    hrp, payload = s[:pos], s[pos + 1:]
    data = [_BECH32_CHARSET.index(c) for c in payload]
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ValueError("invalid bech32 checksum")
    def convertbits(d, frm, to, pad=False):
        acc = bits = 0
        out = bytearray()
        for b in d:
            acc = (acc << frm) | b
            bits += frm
            while bits >= to:
                bits -= to
                out.append((acc >> bits) & ((1 << to) - 1))
        return bytes(out)
    return hrp, convertbits(data[:-6], 5, 8)


def pubkey_to_npub(pub_hex: str) -> str:
    return _bech32_encode("npub", bytes.fromhex(pub_hex))


def privkey_to_nsec(priv_hex: str) -> str:
    return _bech32_encode("nsec", bytes.fromhex(priv_hex))


def npub_to_pubkey(npub: str) -> str:
    hrp, data = _bech32_decode(npub)
    if hrp != "npub" or len(data) != 32:
        raise ValueError("not a valid npub")
    return data.hex()


# ================================================================ 2. E2EE 加密引擎（NIP-04）
def nip04_shared_secret(my_priv_hex: str, their_pub_hex: str) -> bytes:
    """ECDH 密钥协商：返回 32 字节共享密钥（ECDH 共享点的 x 坐标，不做哈希）。

    ECDH 的对称性保证：shared(A_priv, B_pub) == shared(B_priv, A_pub)。
    """
    priv = ec.derive_private_key(int.from_bytes(bytes.fromhex(my_priv_hex), "big"),
                                 ec.SECP256K1(), default_backend())
    x = int.from_bytes(bytes.fromhex(their_pub_hex), "big")
    peer_nums = ec.EllipticCurvePublicNumbers(x, _y_from_x(x), ec.SECP256K1())
    return priv.exchange(ec.ECDH(), peer_nums.public_key(default_backend()))


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv),
                 backend=default_backend()).encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv),
                 backend=default_backend()).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def nip04_encrypt(sender_priv_hex: str, recipient_pub_hex: str, plaintext: str) -> str:
    """NIP-04 加密。返回形如 base64(ciphertext)+"?iv="+base64(iv) 的载荷。"""
    if len(recipient_pub_hex) != 64:
        raise ValueError("recipient public key 必须是 64 hex 字符的 x-only 公钥")
    shared = nip04_shared_secret(sender_priv_hex, recipient_pub_hex)
    iv = secrets.token_bytes(16)
    ct = _aes_cbc_encrypt(shared, iv, plaintext.encode("utf-8"))
    return base64.b64encode(ct).decode() + "?iv=" + base64.b64encode(iv).decode()


def nip04_decrypt(my_priv_hex: str, sender_pub_hex: str, payload: str) -> str:
    """NIP-04 解密。载荷格式与 nip04_encrypt 互逆；失败时抛出异常。"""
    ct_b64, _, iv_b64 = payload.partition("?iv=")
    if not ct_b64 or not iv_b64:
        raise ValueError("载荷不是合法的 NIP-04 格式")
    shared = nip04_shared_secret(my_priv_hex, sender_pub_hex)
    pt = _aes_cbc_decrypt(shared, base64.b64decode(iv_b64),
                          base64.b64decode(ct_b64))
    return pt.decode("utf-8")


# ================================================================ 3. Nostr 事件（NIP-01 + BIP-340）
def _canonical_event_id(pubkey: str, created_at: int, kind: int,
                        tags: list, content: str) -> bytes:
    raw = json.dumps([0, pubkey, created_at, kind, tags, content],
                     separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).digest()


def build_signed_event(priv_hex: str, kind: int, tags: list,
                       content: str, created_at: int | None = None) -> dict:
    """构造并用 BIP-340 Schnorr 签名一个 Nostr 事件。"""
    pubkey = privkey_to_pubkey(priv_hex)
    created_at = created_at or int(time.time())
    event_id = _canonical_event_id(pubkey, created_at, kind, tags, content)
    sig = _CCPrivateKey(bytes.fromhex(priv_hex)).sign_schnorr(event_id)
    return {"id": event_id.hex(), "pubkey": pubkey, "created_at": created_at,
            "kind": kind, "tags": tags, "content": content, "sig": sig.hex()}


def verify_event(event: dict) -> bool:
    """校验事件 id 与 Schnorr 签名是否合法。"""
    try:
        recomputed = _canonical_event_id(event["pubkey"], event["created_at"],
                                         event["kind"], event["tags"],
                                         event["content"]).hex()
        if recomputed != event["id"]:
            return False
        return bool(_CCPublicKeyXOnly(bytes.fromhex(event["pubkey"])).verify(
            bytes.fromhex(event["sig"]), bytes.fromhex(event["id"])))
    except Exception:  # noqa: BLE001
        return False


def build_dm_event(sender_priv_hex: str, recipient_pub_hex: str,
                   plaintext: str) -> dict:
    """构造一条 Kind-4 加密私信事件（NIP-04）。"""
    payload = nip04_encrypt(sender_priv_hex, recipient_pub_hex, plaintext)
    return build_signed_event(sender_priv_hex, DM_KIND,
                              [["p", recipient_pub_hex]], payload)


# ================================================================ 4. 网络路由引擎
def load_relays(path: str | None = None) -> list[str]:
    """读取 valid_relays.json（默认取本文件同目录下的）。"""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "valid_relays.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    relays = data.get("relays") if isinstance(data, dict) else data
    if not relays:
        raise ValueError(f"{path} 中没有可用的中继列表")
    return list(relays)


class RelayPool:
    """中继池：把同一事件并行广播到多个公共中继，并行订阅。"""

    def __init__(self, relays: list[str], connect_timeout: int = 15):
        self.relays = list(relays)
        self.connect_timeout = connect_timeout
        self._proxy = proxy_kwargs()
        self.last_errors: dict[str, str] = {}  # 最近一次 subscribe 各中继的错误

    def _connect(self, url: str):
        return websocket.create_connection(
            url, timeout=self.connect_timeout,
            sslopt={"cert_reqs": 2}, **self._proxy)

    # ---------------- 发布 ----------------
    def publish(self, event: dict, timeout: int = 15) -> list[dict]:
        """向所有中继发布事件。返回每条中继的 ["OK", id, 是否接受, 原因] 结果。"""
        results = []

        def _pub(url: str):
            try:
                ws = self._connect(url)
                ws.send(json.dumps(["EVENT", event]))
                ws.settimeout(timeout)
                accepted, reason = False, "no OK response"
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        raw = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        break
                    msg = json.loads(raw)
                    if msg[0] == "OK" and msg[1] == event["id"]:
                        accepted, reason = bool(msg[2]), str(msg[3] if len(msg) > 3 else "")
                        break
                ws.close()
                return {"relay": url, "accepted": accepted, "reason": reason}
            except Exception as e:  # noqa: BLE001
                return {"relay": url, "accepted": False,
                        "reason": f"{type(e).__name__}: {e}"}

        with ThreadPoolExecutor(max_workers=len(self.relays)) as ex:
            for r in ex.map(_pub, self.relays):
                results.append(r)
        return results

    # ---------------- 订阅 ----------------
    def subscribe(self, filters: dict, duration: int = 30,
                  on_event=None, stop_on_first: bool = False) -> list[dict]:
        """在所有中继上并行订阅；on_event(event) 返回 True 可提前结束。"""
        collected, stop = [], threading.Event()
        lock = threading.Lock()
        self.last_errors = {}

        def _sub(url: str):
            try:
                ws = self._connect(url)
            except Exception as e:  # noqa: BLE001
                with lock:
                    self.last_errors[url] = f"connect: {type(e).__name__}: {e}"
                return
            try:
                sub_id = "sub" + secrets.token_hex(6)
                ws.send(json.dumps(["REQ", sub_id, filters]))
                ws.settimeout(2)
                deadline = time.time() + duration
                while time.time() < deadline and not stop.is_set():
                    try:
                        raw = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        continue
                    except Exception as e:  # noqa: BLE001
                        with lock:
                            self.last_errors[url] = (
                                f"recv: {type(e).__name__}: {e}")
                        break
                    try:
                        msg = json.loads(raw)
                    except Exception:  # noqa: BLE001
                        continue
                    if msg[0] == "EVENT" and msg[1] == sub_id:
                        ev = msg[2]
                        with lock:
                            collected.append(ev)
                        if on_event and on_event(ev):
                            stop.set()
                            break
                        if stop_on_first:
                            stop.set()
                            break
                try:
                    ws.close()
                except Exception:  # noqa: BLE001
                    pass
            except Exception as e:  # noqa: BLE001
                with lock:
                    self.last_errors[url] = f"{type(e).__name__}: {e}"

        with ThreadPoolExecutor(max_workers=len(self.relays)) as ex:
            list(ex.map(_sub, self.relays))
        return collected


# ================================================================ 5. 高层节点抽象
def negotiate_relays(my_relays: list[str], their_relays: list[str],
                     k: int = 5) -> list[str]:
    """为两个节点协商共享中继集合（两两加好友时的关键步骤）。

    私信投递要求"发送方发布的中继"与"接收方订阅的中继"有交集，
    因此优先取双方中继池的交集；交集不足时用己方池补足到 k 个。
    """
    mine = list(dict.fromkeys(my_relays))
    theirs = list(dict.fromkeys(their_relays))
    shared = [r for r in mine if r in theirs]
    if shared:
        # 有交集：只用共享中继，不多广播（百万用户规模下省带宽）
        return shared[:k]
    # 无交集：回退到己方池（对方名片可能过期，尽力投递）
    return mine[:k]


class AgentNode:
    """一个 Agent 通讯节点：身份 + 中继池 + 好友 + 收发原语。"""

    def __init__(self, priv_hex: str | None = None,
                 relays: list[str] | None = None,
                 friends_path: str | None = None):
        if priv_hex:
            self.priv_hex = priv_hex
            self.pub_hex = privkey_to_pubkey(priv_hex)
        else:
            self.priv_hex, self.pub_hex = generate_keypair()
        self.pool = RelayPool(relays or load_relays())
        self.friends_path = friends_path or "friends.json"
        self.friends: dict[str, dict] = {}
        self._load_friends()

    # -- 名片 --
    def contact_card(self) -> str:
        """导出通用名片 JSON（准入凭证）：{"id": 公钥, "relays": [...]}。"""
        return json.dumps({"id": self.pub_hex, "relays": self.pool.relays},
                          ensure_ascii=False)

    def npub(self) -> str:
        return pubkey_to_npub(self.pub_hex)

    # -- 好友（两两加好友 + 中继协商）--
    def _load_friends(self) -> None:
        try:
            with open(self.friends_path, encoding="utf-8") as f:
                self.friends = json.load(f)
        except (FileNotFoundError, ValueError):
            self.friends = {}

    def _save_friends(self) -> None:
        tmp = self.friends_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.friends, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.friends_path)

    def add_friend(self, card: str | dict, alias: str = "") -> list[str]:
        """两两加好友：解析对方名片，协商共享中继并持久化。

        返回本次协商出的共享中继列表。之后与该好友的收发只走这些中继，
        而不是向全网广播——这是支撑百万级用户规模的关键。
        """
        data = json.loads(card) if isinstance(card, str) else dict(card)
        pubkey = data.get("id") or data.get("pubkey")
        if not pubkey or len(pubkey) != 64:
            raise ValueError("名片中没有合法的 64 hex 公钥 id")
        their_relays = data.get("relays") or []
        shared = negotiate_relays(self.pool.relays, their_relays)
        self.friends[pubkey] = {
            "alias": alias,
            "relays": shared,
            "their_relays": their_relays,
            "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._save_friends()
        return shared

    def remove_friend(self, pubkey: str) -> bool:
        if pubkey in self.friends:
            del self.friends[pubkey]
            self._save_friends()
            return True
        return False

    def _relays_for(self, recipient_pub_hex: str) -> list[str]:
        fr = self.friends.get(recipient_pub_hex)
        return fr["relays"] if fr else self.pool.relays

    # -- 发送 --
    def send_message(self, recipient_pub_hex: str,
                     plaintext: str) -> tuple[dict, list[dict]]:
        """加密并广播一条私信。好友走协商中继，陌生人走全池。返回 (事件, 各中继发布结果)。"""
        event = build_dm_event(self.priv_hex, recipient_pub_hex, plaintext)
        pool = RelayPool(self._relays_for(recipient_pub_hex),
                         connect_timeout=self.pool.connect_timeout)
        return event, pool.publish(event)

    # -- 接收 --
    def wait_for_message(self, sender_pub_hex: str,
                         timeout: int = 90) -> tuple[dict | None, str | None]:
        """订阅并等待来自指定发送者的下一条私信；成功返回 (事件, 明文)。"""
        found: dict = {}

        def _match(ev: dict) -> bool:
            if ev.get("kind") != DM_KIND or ev.get("pubkey") != sender_pub_hex:
                return False
            tags = ev.get("tags") or []
            if not any(len(t) >= 2 and t[0] == "p" and t[1] == self.pub_hex
                       for t in tags):
                return False
            if not verify_event(ev):
                return False
            try:
                pt = nip04_decrypt(self.priv_hex, sender_pub_hex, ev["content"])
            except Exception:  # noqa: BLE001
                return False
            found["event"], found["plaintext"] = ev, pt
            return True

        self.pool.subscribe({"kinds": [DM_KIND], "authors": [sender_pub_hex],
                             "limit": 20},
                            duration=timeout, on_event=_match,
                            stop_on_first=False)
        return found.get("event"), found.get("plaintext")

    def save_identity(self, path: str) -> str:
        """把私钥身份落盘（0600 权限）。警告：私钥即身份，妥善备份。"""
        data = {"private_key": self.priv_hex, "public_key": self.pub_hex,
                "npub": self.npub(), "relays": self.pool.relays,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(path, 0o600)
        return path

    @staticmethod
    def load_identity(path: str, relays: list[str] | None = None,
                      friends_path: str | None = None) -> "AgentNode":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        # 默认使用身份文件里保存的中继池（即生成身份时的 valid_relays），
        # 而不是每次都读当前 valid_relays.json，避免池子漂移导致收发不一致。
        return AgentNode(priv_hex=data["private_key"],
                         relays=relays or data.get("relays") or load_relays(),
                         friends_path=friends_path)
