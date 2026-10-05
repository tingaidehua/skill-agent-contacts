#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_setup_and_test.py —— 通用版一键装配与自测脚本

任意 Agent 沙箱接入流程：
  1. pip install -r requirements.txt
  2. python agent_setup_and_test.py [--identity-out identity.json]

脚本将：
  [0] 本地密码学自检（离线）：密钥生成 / ECDH 对称性 / NIP-04 加解密往返 / 签名验签
  [1] 生成双节点 Node_A / Node_B，并打印双方的「二维码名片」JSON
  [2] A -> B：经真实 Nostr 公共中继发送 NIP-04 加密私信
  [3] B 监听、解密、校验明文
  [4] B -> A：回复 Ack
  [5] A 监听、解密、校验明文
  [6] 自测通过后销毁 Node_B；如指定 --identity-out，则把 Node_A 身份落盘（0600）

退出码：0 = 全部通过；非 0 = 某一步失败（见输出）。
"""
import argparse
import sys
import time

import core
from core import AgentNode, nip04_encrypt, nip04_decrypt, nip04_shared_secret, \
    generate_keypair, verify_event, build_signed_event, load_relays

STEP = 0


def step(msg: str):
    global STEP
    STEP += 1
    print(f"\n===== [{STEP}] {msg} =====", flush=True)


def fail(msg: str) -> "sys.NoReturn":
    print(f"\n❌ 自测失败：{msg}", flush=True)
    sys.exit(1)


def ok(msg: str):
    print(f"✅ {msg}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="通用 Agent 通讯节点装配与自测")
    ap.add_argument("--identity-out", default="",
                    help="自测通过后，把 Node_A 的永久身份保存到该路径（0600 权限）")
    ap.add_argument("--wait-timeout", type=int, default=120,
                    help="每方向等待对方消息的最长秒数（默认 120）")
    args = ap.parse_args()

    t_all = time.time()
    relays = load_relays()
    print(f"中继池（{len(relays)}）：")
    for r in relays:
        print(f"  - {r}")

    # ---------------------------------------------------------------- [0] 本地自检
    step("本地密码学自检（离线，不经过网络）")
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    assert len(a_pub) == 64 and len(b_pub) == 64
    ok(f"密钥生成正常：A={a_pub[:12]}… B={b_pub[:12]}…")

    s1 = nip04_shared_secret(a_priv, b_pub)
    s2 = nip04_shared_secret(b_priv, a_pub)
    assert s1 == s2 and len(s1) == 32, "ECDH 共享密钥不对称！"
    ok("ECDH 密钥协商对称（A_priv×B_pub == B_priv×A_pub，32 字节）")

    msg = "Hello from Node A, verifying E2EE network. 你好，端到端加密测试 🌍"
    ct = nip04_encrypt(a_priv, b_pub, msg)
    assert ct != msg and "?iv=" in ct
    pt = nip04_decrypt(b_priv, a_pub, ct)
    assert pt == msg, "NIP-04 加解密往返不一致！"
    ok(f"NIP-04 加解密往返一致（密文 {len(ct)} 字符，明文正确还原）")

    ev = build_signed_event(a_priv, 4, [["p", b_pub]], ct)
    assert verify_event(ev), "事件签名校验失败！"
    ok("Nostr 事件构造 + BIP-340 Schnorr 签名验签通过")

    # 互操作：npub/nsec 编解码
    assert core.npub_to_pubkey(core.pubkey_to_npub(a_pub)) == a_pub
    ok("npub/nsec（bech32）编解码正常")

    # ---------------------------------------------------------------- [1] 双子星
    step("创建虚拟双子星 Node_A / Node_B")
    node_a = AgentNode(priv_hex=a_priv, relays=relays)
    node_b = AgentNode(priv_hex=b_priv, relays=relays)
    card_a = node_a.contact_card()
    card_b = node_b.contact_card()
    print("Node_A 名片 JSON：")
    print(card_a)
    print("Node_B 名片 JSON：")
    print(card_b)
    ok("双节点身份就绪（双方已记录对方公钥）")

    # ---------------------------------------------------------------- [2] A -> B
    step("A -> B：经真实 Nostr 中继发送加密私信")
    hello = "Hello from Node A, verifying E2EE network."
    event_ab, pub_results = node_a.send_message(b_pub, hello)
    accepted = [r for r in pub_results if r["accepted"]]
    print(f"事件 id：{event_ab['id'][:16]}…")
    for r in pub_results:
        mark = "✓" if r["accepted"] else "✗"
        print(f"  {mark} {r['relay']}: {r['reason'][:80]}")
    if not accepted:
        fail("没有任何中继接受该事件（全部被拒或连接失败）")
    ok(f"{len(accepted)}/{len(pub_results)} 个中继接受事件，密文已上网")

    # ---------------------------------------------------------------- [3] B 接收
    step("B 监听中继并解密")
    t0 = time.time()
    ev_b, pt_b = node_b.wait_for_message(a_pub, timeout=args.wait_timeout)
    if ev_b is None:
        fail(f"B 在 {args.wait_timeout}s 内没有收到 A 的消息")
    print(f"  耗时 {time.time() - t0:.1f}s，事件 id {ev_b['id'][:16]}…")
    print(f"  B 解密得到明文：{pt_b}")
    if pt_b != hello:
        fail("B 解密出的明文与 A 发送的不一致！")
    ok("B 成功解密并校验明文（端到端加密链路打通）")

    # ---------------------------------------------------------------- [4] B -> A (Ack)
    step("B -> A：回复 Ack 确认消息")
    ack = "Ack from Node B: E2EE roundtrip verified. 收到，加密往返确认 ✅"
    event_ba, pub_results2 = node_b.send_message(a_pub, ack)
    accepted2 = [r for r in pub_results2 if r["accepted"]]
    for r in pub_results2:
        mark = "✓" if r["accepted"] else "✗"
        print(f"  {mark} {r['relay']}: {r['reason'][:80]}")
    if not accepted2:
        fail("B 的 Ack 没有任何中继接受")
    ok(f"{len(accepted2)}/{len(pub_results2)} 个中继接受 Ack 事件")

    # ---------------------------------------------------------------- [5] A 接收
    step("A 监听中继并解密 Ack")
    t0 = time.time()
    ev_a, pt_a = node_a.wait_for_message(b_pub, timeout=args.wait_timeout)
    if ev_a is None:
        fail(f"A 在 {args.wait_timeout}s 内没有收到 B 的 Ack")
    print(f"  耗时 {time.time() - t0:.1f}s，事件 id {ev_a['id'][:16]}…")
    print(f"  A 解密得到明文：{pt_a}")
    if pt_a != ack:
        fail("A 解密出的 Ack 与 B 发送的不一致！")
    ok("A 成功解密 Ack（双向加密往返全部通过）")

    # ---------------------------------------------------------------- [6] 清理与保留
    step("清理现场：销毁 Node_B")
    del node_b, b_priv, b_pub
    ok("Node_B 已销毁（内存引用释放）")

    if args.identity_out:
        node_a.save_identity(args.identity_out)
        ok(f"Node_A 永久身份已保存到 {args.identity_out}（0600 权限，请备份）")
        print("Node_A 名片（本沙箱永久通讯身份）：")
        print(card_a)
        # 生成二维码名片
        try:
            from qr import make_qr_png, make_qr_ascii
            import os as _os
            png_path = _os.path.join(_os.path.dirname(
                _os.path.abspath(args.identity_out)), "contact_card.png")
            make_qr_png(card_a, png_path)
            ok(f"二维码名片已生成：{png_path}（扫码即得名片 JSON）")
            print("终端二维码（手机扫码加好友）：")
            print(make_qr_ascii(card_a))
        except SystemExit as e:
            print(f"  （跳过二维码：{e}）")
    else:
        print("（未指定 --identity-out，Node_A 私钥仅存在于本次进程内存）")

    print(f"\n🎉 全部自测通过，总耗时 {time.time() - t_all:.1f}s")
    print("协议结论：DID 身份 / NIP-04 E2EE / 中继路由 / 双向握手 —— 全部可用。")


if __name__ == "__main__":
    main()
