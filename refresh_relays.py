#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
refresh_relays.py —— 中继目录自助刷新工具

任意节点定期运行它，即可重建全网公开中继目录，而不依赖种子节点：
  python refresh_relays.py [--seeds wss://a,wss://b] [--workers 60] [--out .]

流程：
  1. 从种子中继抓取 kind-10002（NIP-65）事件，收获全网用户声明的中继 URL
  2. 批量探测 WSS 连通性 + 延迟
  3. 对可达中继用全新密钥真实发布 kind-4，测 DM 接受率
  4. 输出 relay_directory.json（全量分级目录）并更新 valid_relays.json（工作池）
"""
import argparse
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import core
import websocket

# 温柔模式：低并发 + 任务间抖动，避免触发出口代理/中继的扫描防护。
# （教训：70 并发扫 4000+ 主机曾导致本沙箱全部出站流量被限流数分钟。）
DEFAULT_WORKERS = 6
JITTER_SLEEP = (0, 1.5)

DEFAULT_SEEDS = [
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.snort.social",
    "wss://nostr.mom",
]


def harvest(seeds: list[str], workers: int) -> list[str]:
    found: set[str] = set()

    def _one(url: str):
        urls: set[str] = set()
        try:
            pool = core.RelayPool([url])
            for ev in pool.subscribe({"kinds": [10002], "limit": 500},
                                     duration=25):
                for tag in ev.get("tags") or []:
                    if len(tag) >= 2 and tag[0] == "r":
                        r = tag[1].strip().rstrip("/")
                        p = urlparse(r)
                        host = p.hostname or ""
                        if (r.startswith("wss://") and "." in host
                                and ".onion" not in host):
                            urls.add(f"wss://{host}"
                                     + (f":{p.port}" if p.port else "")
                                     + (p.path.rstrip("/") if p.path else ""))
        except Exception as e:  # noqa: BLE001
            print(f"  harvest {url} 失败: {e}")
        return urls

    with ThreadPoolExecutor(max_workers=len(seeds)) as ex:
        for urls in ex.map(_one, seeds):
            found |= urls
    return sorted(found)


def probe_connectivity(urls: list[str], workers: int) -> list[dict]:
    def _probe(url: str):
        time.sleep(random.uniform(*JITTER_SLEEP))
        t0 = time.monotonic()
        ws = None
        try:
            ws = websocket.create_connection(
                url, timeout=8, sslopt={"cert_reqs": 2},
                **core.proxy_kwargs())
            ws.send(json.dumps(["REQ", "p", {"kinds": [1], "limit": 1}]))
            ws.settimeout(6)
            while True:
                msg = json.loads(ws.recv())
                if msg[0] in ("EVENT", "EOSE"):
                    return {"url": url,
                            "latency_ms": round((time.monotonic() - t0) * 1000)}
                if msg[0] in ("CLOSED", "NOTICE"):
                    return None
        except Exception:  # noqa: BLE001
            return None
        finally:
            if ws:
                try:
                    ws.close()
                except Exception:  # noqa: BLE001
                    pass

    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(_probe, urls):
            if r:
                out.append(r)
    return sorted(out, key=lambda r: r["latency_ms"])


def probe_kind4(reachable: list[dict], workers: int) -> list[dict]:
    def _test(entry: dict):
        time.sleep(random.uniform(*JITTER_SLEEP))
        url = entry["url"]
        res = dict(entry)
        res.update({"kind4": False, "reason": ""})
        try:
            s_priv, _ = core.generate_keypair()
            _, r_pub = core.generate_keypair()
            ev = core.build_dm_event(s_priv, r_pub, "relay refresh probe")
            out = core.RelayPool([url]).publish(ev, timeout=12)[0]
            res["kind4"] = out["accepted"]
            res["reason"] = out["reason"]
        except Exception as e:  # noqa: BLE001
            res["reason"] = f"{type(e).__name__}: {e}"
        return res

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(_test, reachable))


def main() -> None:
    ap = argparse.ArgumentParser(description="刷新全网 Nostr 中继目录")
    ap.add_argument("--seeds", default=",".join(DEFAULT_SEEDS))
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help=f"并发数（默认 {DEFAULT_WORKERS}，温柔模式，勿调太高）")
    ap.add_argument("--pool-size", type=int, default=10,
                    help="写入 valid_relays.json 的工作池大小")
    ap.add_argument("--out", default=".")
    args = ap.parse_args()
    t0 = time.time()

    print("[1/4] 从 Nostr 网络抓取中继目录…")
    urls = harvest(args.seeds.split(","), args.workers)
    print(f"  抓到 {len(urls)} 个不重复 URL")

    print("[2/4] 批量探测连通性…")
    reachable = probe_connectivity(urls, args.workers)
    print(f"  {len(reachable)}/{len(urls)} 可达")

    print("[3/4] 探测 kind-4 DM 接受率（全新密钥真实发布）…")
    tested = probe_kind4(reachable, args.workers)
    kind4_ok = [r for r in tested if r["kind4"]]
    print(f"  {len(kind4_ok)}/{len(tested)} 接受 kind-4")

    print("[4/4] 写出目录…")
    directory = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_harvested": len(urls),
        "reachable": len(reachable),
        "kind4_accepting": len(kind4_ok),
        "relays": [
            {"url": r["url"], "latency_ms": r["latency_ms"],
             "kind4": r["kind4"], "reason": r["reason"][:120]}
            for r in tested
        ],
    }
    with open(f"{args.out}/relay_directory.json", "w") as f:
        json.dump(directory, f, indent=1, ensure_ascii=False)

    pool = [r["url"] for r in kind4_ok[:args.pool_size]]
    with open(f"{args.out}/valid_relays.json", "w") as f:
        json.dump({"relays": pool,
                   "note": "由 refresh_relays.py 实测生成：可达且接受陌生公钥 kind-4，"
                           "按延迟排序。完整分级目录见 relay_directory.json。",
                   "generated_at": directory["generated_at"]},
                  f, indent=2, ensure_ascii=False)

    print(f"  relay_directory.json：{len(tested)} 条记录")
    print(f"  valid_relays.json：工作池 {len(pool)} 个")
    print(f"总用时 {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
