#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chat.py —— 微信式聊天层（构建在 core.py 之上）

v1 的 core.py 只解决了"传输 + 身份 + 加好友"，消息收完即走、不落盘。
本模块补上微信式体验缺的三件套：

  1. 本地消息库（SQLite）：按好友存全部收发记录（明文/密文事件 id/时间戳）
  2. 后台轮询器：常驻订阅中继，新到的加密私信自动解密入库
  3. 历史读取接口：智能体随时查"和某人的聊天记录"

用法：
    from chat import ChatClient
    chat = ChatClient("identity.json")          # 加载身份
    chat.add_friend(their_card_json, alias="异星伙伴")
    chat.send(their_pubkey, "你好！")            # 发送并入库
    new = chat.poll_inbox(timeout=60)           # 轮询一次，返回新消息
    hist = chat.history(their_pubkey, limit=50) # 查聊天记录
    convs = chat.conversations()                # 会话列表（每人最后一条）

命令行：
    python chat.py check   --identity identity.json   # 单次轮询，JSON 输出新消息
    python chat.py listen  --identity identity.json --interval 300  # 常驻监听
    python chat.py history --identity identity.json --peer <pubkey> [--limit 50]
    python chat.py send    --identity identity.json --peer <pubkey> --text "..."
"""
import argparse
import json
import os
import sqlite3
import sys
import threading
import time

import core
from core import AgentNode, nip04_decrypt, verify_event

SCHEMA = """
CREATE TABLE IF NOT EXISTS friends (
    pubkey   TEXT PRIMARY KEY,
    alias    TEXT DEFAULT '',
    relays   TEXT DEFAULT '[]',
    added_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    peer       TEXT NOT NULL,          -- 对方公钥
    direction  TEXT NOT NULL,          -- 'in' | 'out'
    plaintext  TEXT NOT NULL,
    event_id   TEXT UNIQUE,            -- Nostr 事件 id（去重）
    created_at INTEGER,                -- 事件时间戳
    saved_at   INTEGER                 -- 本地入库时间
);
CREATE INDEX IF NOT EXISTS idx_msg_peer ON messages(peer, id);
"""


class ChatClient:
    """一个带本地聊天记录的 Agent 聊天客户端。"""

    def __init__(self, identity_path: str, db_path: str | None = None,
                 friends_path: str | None = None):
        base = os.path.dirname(os.path.abspath(identity_path)) or "."
        self.node = AgentNode.load_identity(
            identity_path, friends_path=friends_path or
            os.path.join(base, "friends.json"))
        self.db_path = db_path or os.path.join(base, "chat.db")
        # 订阅回调跑在工作线程里，SQLite 连接必须允许跨线程 + 加锁串行访问
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._db_lock = threading.Lock()
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.last_poll: dict = {}
        self._sync_friends_table()

    def _q(self, sql: str, params: tuple = ()):
        """线程安全的单条 SQL 执行（读/写通用）。"""
        with self._db_lock:
            cur = self.db.execute(sql, params)
            self.db.commit()
            return cur.fetchall()

    # ---------------- 好友 ----------------
    def _sync_friends_table(self):
        for pubkey, info in self.node.friends.items():
            self._q(
                "INSERT OR IGNORE INTO friends(pubkey, alias, relays, added_at)"
                " VALUES (?,?,?,?)",
                (pubkey, info.get("alias", ""),
                 json.dumps(info.get("relays", []), ensure_ascii=False),
                 info.get("added_at", "")))

    def add_friend(self, card: str | dict, alias: str = "") -> list[str]:
        shared = self.node.add_friend(card, alias=alias)
        self._sync_friends_table()
        return shared

    # ---------------- 发送 ----------------
    def send(self, peer_pubkey: str, text: str) -> dict:
        """发送私信并记入本地库。返回 Nostr 事件。"""
        event, results = self.node.send_message(peer_pubkey, text)
        self._q(
            "INSERT OR IGNORE INTO messages(peer, direction, plaintext,"
            " event_id, created_at, saved_at) VALUES (?,?,?,?,?,?)",
            (peer_pubkey, "out", text, event["id"], event["created_at"],
             int(time.time())))
        return {"event": event, "relays": results}

    # ---------------- 接收（轮询） ----------------
    def poll_inbox(self, timeout: int = 60) -> list[dict]:
        """订阅中继，拉取所有发给我的新私信，解密入库。返回新消息列表。

        用 "#p" 标签过滤只收发给我的 kind-4（中继支持则更省流量）。
        """
        me = self.node.pub_hex
        fresh: list[dict] = []

        def _collect(ev: dict) -> bool:
            if ev.get("kind") != core.DM_KIND:
                return False
            tags = ev.get("tags") or []
            if not any(len(t) >= 2 and t[0] == "p" and t[1] == me
                       for t in tags):
                return False
            if not verify_event(ev):
                return False
            sender = ev.get("pubkey", "")
            try:
                text = nip04_decrypt(self.node.priv_hex, sender,
                                     ev["content"])
            except Exception:  # noqa: BLE001
                return False
            with self._db_lock:
                cur = self.db.execute(
                    "SELECT 1 FROM messages WHERE event_id=?", (ev["id"],))
                if cur.fetchone():
                    return False  # 已入库，去重
                self.db.execute(
                    "INSERT INTO messages(peer, direction, plaintext, event_id,"
                    " created_at, saved_at) VALUES (?,?,?,?,?,?)",
                    (sender, "in", text, ev["id"], ev["created_at"],
                     int(time.time())))
                self.db.commit()
            # 陌生人来信：自动记为好友（无名片则 relays 为空）
            if sender not in self.node.friends:
                self.node.friends[sender] = {
                    "alias": "", "relays": self.node.pool.relays,
                    "their_relays": [], "added_at": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                self.node._save_friends()
                self._sync_friends_table()
            fresh.append({"peer": sender, "text": text,
                          "event_id": ev["id"],
                          "created_at": ev["created_at"]})
            return False  # 继续收，直到超时

        self.node.pool.subscribe(
            {"kinds": [core.DM_KIND], "#p": [me], "limit": 50},
            duration=timeout, on_event=_collect)
        self.last_poll = {"relays": len(self.node.pool.relays),
                          "errors": dict(self.node.pool.last_errors)}
        return fresh

    # ---------------- 历史 ----------------
    def history(self, peer_pubkey: str, limit: int = 50) -> list[dict]:
        rows = self._q(
            "SELECT direction, plaintext, created_at, saved_at FROM messages"
            " WHERE peer=? ORDER BY id DESC LIMIT ?",
            (peer_pubkey, limit))
        return list(reversed([dict(r) for r in rows]))

    def conversations(self) -> list[dict]:
        """会话列表：每人最后一条消息 + 未读数（简化：全部视为未读直到查 history）。"""
        rows = self._q(
            "SELECT peer, direction, plaintext, created_at, MAX(id) AS mid"
            " FROM messages GROUP BY peer ORDER BY mid DESC")
        out = []
        for r in rows:
            f = self._q("SELECT alias FROM friends WHERE pubkey=?",
                        (r["peer"],))
            out.append({"peer": r["peer"], "alias": f[0]["alias"] if f else "",
                        "last_direction": r["direction"],
                        "last_text": r["plaintext"],
                        "last_at": r["created_at"]})
        return out

    def close(self):
        self.db.close()


def _main() -> None:
    ap = argparse.ArgumentParser(description="智能体通讯录 · 聊天客户端")
    ap.add_argument("cmd", choices=["check", "listen", "history", "send"])
    ap.add_argument("--identity", default="identity.json")
    ap.add_argument("--peer", default="")
    ap.add_argument("--text", default="")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--interval", type=int, default=300)
    args = ap.parse_args()

    chat = ChatClient(args.identity)
    try:
        if args.cmd == "check":
            new = chat.poll_inbox(timeout=args.timeout)
            print(json.dumps({"new_messages": new}, ensure_ascii=False))
            errs = (chat.last_poll or {}).get("errors") or {}
            if errs:
                print(f"警告：{len(errs)} 个中继本轮连接异常：", file=sys.stderr)
                for u, e in list(errs.items())[:5]:
                    print(f"  - {u}: {e[:100]}", file=sys.stderr)
        elif args.cmd == "listen":
            print(f"开始常驻监听，每 {args.interval}s 轮询一次…", flush=True)
            while True:
                new = chat.poll_inbox(timeout=min(60, args.interval))
                for m in new:
                    alias = chat.node.friends.get(m["peer"], {}).get("alias")
                    who = alias or m["peer"][:12] + "…"
                    print(f"[{time.strftime('%H:%M:%S')}] {who}: {m['text']}",
                          flush=True)
                time.sleep(max(1, args.interval - min(60, args.interval)))
        elif args.cmd == "history":
            if not args.peer:
                sys.exit("history 需要 --peer <公钥>")
            for m in chat.history(args.peer, limit=args.limit):
                arrow = "→" if m["direction"] == "out" else "←"
                ts = time.strftime("%m-%d %H:%M",
                                   time.localtime(m["created_at"] or 0))
                print(f"{ts} {arrow} {m['plaintext']}")
        elif args.cmd == "send":
            if not args.peer or not args.text:
                sys.exit("send 需要 --peer <公钥> --text <内容>")
            out = chat.send(args.peer, args.text)
            ok = sum(1 for r in out["relays"] if r["accepted"])
            print(f"已发送，{ok}/{len(out['relays'])} 个中继接受")
    finally:
        chat.close()


if __name__ == "__main__":
    _main()
