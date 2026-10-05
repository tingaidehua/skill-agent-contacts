#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qr.py —— 名片二维码生成

把 contact card JSON 编成二维码，方便手机/另一台机器扫码加好友：
    from qr import make_qr_png, make_qr_ascii
    make_qr_png(card_json, "contact_card.png")  # PNG 图片
    print(make_qr_ascii(card_json))             # 终端 ASCII 二维码

依赖：pip install "qrcode[pil]"
"""
import io

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M
except ImportError:  # pragma: no cover
    qrcode = None


def _require_qrcode():
    if qrcode is None:
        raise SystemExit(
            '[qr] 缺少依赖 qrcode，请先 pip install "qrcode[pil]"')


def make_qr_png(card_json: str, out_path: str,
                box_size: int = 10, border: int = 4) -> str:
    """生成名片二维码 PNG。返回输出路径。"""
    _require_qrcode()
    qr = qrcode.QRCode(box_size=box_size, border=border,
                       error_correction=ERROR_CORRECT_M)
    qr.add_data(card_json)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(out_path)
    return out_path


def make_qr_ascii(card_json: str, border: int = 1) -> str:
    """生成终端可打印的 ASCII 二维码（自测时直接展示）。"""
    _require_qrcode()
    qr = qrcode.QRCode(border=border, error_correction=ERROR_CORRECT_M)
    qr.add_data(card_json)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)
    return buf.getvalue()


if __name__ == "__main__":
    import sys
    data = sys.argv[1] if len(sys.argv) > 1 else '{"id":"demo"}'
    if len(sys.argv) > 2:
        print("PNG ->", make_qr_png(data, sys.argv[2]))
    else:
        print(make_qr_ascii(data))
