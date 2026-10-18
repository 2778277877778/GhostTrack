#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostTrackGUI v4 — GhostTrack + Seeker 图形界面
查询: IP / 号码 / 用户名 / Web 指纹 / 批量 IP / 端口检测 / 本机网络
其他: 历史持久化(双击回填) · CSV 导出 · Seeker 捕获结果内嵌查看
性能: 日志批处理+上限、智能滚动、HTTP 会话重试、全网络后台线程
美化: 深色标题栏、自绘图标、渐变线、斑马纹、空状态、悬浮提示、呼吸灯
仅用于合法授权的安全测试与学习研究。
"""

import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ================================================================ 路径与环境
WORKSPACE = Path(__file__).resolve().parent
GHOST_DIR = WORKSPACE / "GhostTrack"
SEEKER_DIR = WORKSPACE / "seeker"
HIST_FILE = WORKSPACE / ".ghosttrack_history.json"

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def refresh_windows_path():
    """从注册表刷新 PATH, 保证从资源管理器启动时也能找到 php。"""
    if os.name != "nt":
        return
    try:
        import winreg
        chunks = []
        for root, sub in (
            (winreg.HKEY_LOCAL_MACHINE,
             r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
            (winreg.HKEY_CURRENT_USER, r"Environment"),
        ):
            try:
                with winreg.OpenKey(root, sub) as key:
                    val, _ = winreg.QueryValueEx(key, "Path")
                    if val:
                        chunks.append(val)
            except OSError:
                pass
        if chunks:
            os.environ["PATH"] = ";".join(chunks) + ";" + os.environ.get("PATH", "")
    except Exception:
        pass


refresh_windows_path()


def enable_high_dpi():
    """Windows 高 DPI 支持 —— 必须在创建 Tk 之前调用。
    不启用时 Windows 会对整个窗口位图拉伸, 高分屏上文字发虚。"""
    if os.name != "nt":
        return
    try:
        import ctypes
        # Per-Monitor V2 (Win10 1703+): 原生分辨率渲染, 最清晰
        try:
            if ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
                return
        except (AttributeError, OSError):
            pass
        # System Aware (Win8.1+)
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
            return
        except (AttributeError, OSError):
            pass
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def get_scale() -> float:
    """获取系统 DPI 缩放系数 (96 DPI = 1.0, 144 DPI = 1.5)。"""
    if os.name != "nt":
        return 1.0
    try:
        import ctypes
        dpi = ctypes.windll.user32.GetDpiForSystem()
        if dpi:
            return dpi / 96.0
    except Exception:
        pass
    try:
        import ctypes
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
        ctypes.windll.user32.ReleaseDC(0, hdc)
        if dpi:
            return dpi / 96.0
    except Exception:
        pass
    return 1.0


enable_high_dpi()
SCALE = get_scale()


def S(px: int) -> int:
    """像素值按系统 DPI 缩放 (字体用 point 单位无需缩放, Tk 自动换算)。"""
    return int(round(px * SCALE))


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def make_session() -> requests.Session:
    """带自动重试的 HTTP 会话 (429/5xx 重试 2 次, 指数退避)。"""
    sess = requests.Session()
    retry = Retry(total=2, backoff_factor=0.4,
                  status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["GET"])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


HTTP = make_session()


# ================================================================ 查询逻辑 (与 GhostTR.py 相同的 API)
FIELD_LABELS_IP = [
    ("type", "IP 类型"), ("country", "国家"), ("country_code", "国家代码"),
    ("city", "城市"), ("continent", "大洲"), ("continent_code", "大洲代码"),
    ("region", "地区"), ("region_code", "地区代码"),
    ("latitude", "纬度"), ("longitude", "经度"),
    ("is_eu", "欧盟成员"), ("postal", "邮编"), ("calling_code", "国际区号"),
    ("capital", "首都"), ("borders", "接壤国家"),
]


def query_ip(ip: str):
    """返回 (rows, maps_url, error)。"""
    ip = ip.strip()
    try:
        resp = HTTP.get(f"http://ipwho.is/{ip}", timeout=(5, 15))
        data = resp.json()
    except Exception as exc:
        return [], None, f"请求失败: {exc}"
    if data.get("success") is False:
        return [], None, f"查询失败: {data.get('message', '无效的 IP 或域名')}"
    rows = [(label, data.get(key, "")) for key, label in FIELD_LABELS_IP]
    rows.append(("国旗", (data.get("flag") or {}).get("emoji", "")))
    conn = data.get("connection") or {}
    rows += [("ASN", conn.get("asn", "")), ("机构", conn.get("org", "")),
             ("ISP", conn.get("isp", "")), ("域名", conn.get("domain", ""))]
    tz = data.get("timezone") or {}
    rows += [("时区 ID", tz.get("id", "")), ("时区缩写", tz.get("abbr", "")),
             ("夏令时", tz.get("is_dst", "")), ("UTC 偏移", tz.get("offset", "")),
             ("UTC", tz.get("utc", "")), ("当前时间", tz.get("current_time", ""))]
    lat, lon = data.get("latitude"), data.get("longitude")
    maps = None
    if lat is not None and lon is not None:
        maps = f"https://www.google.com/maps/@{lat},{lon},8z"
        rows.append(("地图", maps))
    return rows, maps, None


def query_own_ip() -> str:
    resp = HTTP.get("https://api.ipify.org/", timeout=(5, 15))
    resp.raise_for_status()
    return resp.text.strip()


PHONE_TYPE_MAP = {
    phonenumbers.PhoneNumberType.MOBILE: "手机号码",
    phonenumbers.PhoneNumberType.FIXED_LINE: "固定电话",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "固话或手机",
    phonenumbers.PhoneNumberType.TOLL_FREE: "免费电话",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "增值号码",
}


def analyze_phone(text: str, region: str):
    """返回 (rows, error)。中国大陆号码叠加本地归属地库 (城市级)。"""
    text = text.strip().replace(" ", "")
    if not text:
        return [], "请输入号码"
    try:
        parsed = phonenumbers.parse(text, region or None)
    except Exception as exc:
        return [], f"号码解析失败: {exc}"
    ntype = phonenumbers.number_type(parsed)
    rows = [
        ("归属位置", geocoder.description_for_number(parsed, "zh") or "未知"),
        ("地区代码", phonenumbers.region_code_for_number(parsed) or ""),
        ("运营商", carrier.name_for_number(parsed, "zh") or "未知"),
        ("时区", ", ".join(pn_timezone.time_zones_for_number(parsed))),
        ("号码有效", phonenumbers.is_valid_number(parsed)),
        ("号码可能存在", phonenumbers.is_possible_number(parsed)),
        ("国际格式", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)),
        ("拨号格式", phonenumbers.format_number_for_mobile_dialing(parsed, region or "CN", with_formatting=True)),
        ("E.164 格式", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)),
        ("国家区号", parsed.country_code),
        ("国内号码", parsed.national_number),
        ("号码类型", PHONE_TYPE_MAP.get(ntype, "其他类型")),
    ]
    # ---- 国内归属地库增强 (city-level, 双库融合) ----
    if parsed.country_code == 86:
        national = str(parsed.national_number)
        if len(national) >= 7 and national.startswith("1"):
            prefix7 = national[:7]
            xe = ls = None
            errs = []
            # 主库: XEngine (2025-08, 覆盖最全)
            try:
                xe = get_xe_db().find(prefix7)
            except FileNotFoundError:
                errs.append("XEngine 库缺失")
            except Exception as exc:
                errs.append(f"XEngine 读取失败: {exc}")
            # 补充库: ls0f/phone (独家邮编)
            try:
                ls = get_cn_db().find(prefix7)
            except FileNotFoundError:
                errs.append("ls0f 库缺失")
            except Exception as exc:
                errs.append(f"ls0f 读取失败: {exc}")
            if xe or ls:
                cn_rows = []
                # 归属地: 优先 XEngine (数据新), 其次 ls0f
                prov = (xe and xe["province"]) or (ls and ls["province"]) or ""
                city = (xe and xe["city"]) or (ls and ls["city"]) or ""
                area = (xe and xe["area_code"]) or (ls and ls["area_code"]) or ""
                cn_rows += [("归属省份", prov or "未知"), ("归属城市", city or "未知"),
                            ("长途区号", area or "—")]
                if ls and ls.get("zip"):
                    cn_rows.append(("邮政编码", ls["zip"]))
                # 运营商: XEngine 码表更细 (区分虚拟/座机/卫星/物联网)
                if xe:
                    cn_rows.append(("运营商 (XEngine)", xe["op_name"]))
                if ls:
                    cn_rows.append(("运营商 (ls0f)", ls["card_type"]))
                # 携号转网 (XEngine 格式支持, 当前数据基本为空)
                if xe and xe["ported"]:
                    cn_rows.append(("⚠ 携号转网", f"原运营商: {xe['original_op']} → 现: {xe['op_name']}"))
                elif xe:
                    cn_rows.append(("携号转网", "无转网记录"))
                cn_rows.append(("号段前7位", prefix7))
                # 数据源标注
                srcs = []
                if xe:
                    srcs.append(f"XEngine {getattr(get_xe_db(), 'version', '?')}")
                if ls:
                    srcs.append("ls0f 2023-12")
                cn_rows.append(("数据源", " + ".join(srcs) if srcs else "—"))
                if not xe and ls:
                    cn_rows.append(("提示", "该号段较新, 仅 ls0f 库有记录"))
                # 虚拟运营商/广电提示
                op_name = (xe and xe["op_name"]) or (ls and ls["card_type"]) or ""
                if any(k in op_name for k in ("虚拟", "广电", "卫星", "物联网", "座机")):
                    cn_rows.append(("提示", f"{op_name}号段, 非三大运营商实体手机卡"))
                rows = cn_rows + rows
            else:
                rows.append(("⚠ 归属地", f"两个库均无此号段 (可能为极新分配); 库位置: "
                                         f"{PHONE_DAT.parent}"))
                if errs:
                    rows.append(("⚠ 库状态", " · ".join(errs)))
    return rows, None


UA = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
}

SOCIAL_SITES = [
    ("Facebook", "https://www.facebook.com/{}"),
    ("Twitter", "https://www.twitter.com/{}"),
    ("Instagram", "https://www.instagram.com/{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
    ("GitHub", "https://www.github.com/{}"),
    ("Pinterest", "https://www.pinterest.com/{}"),
    ("Tumblr", "https://www.tumblr.com/{}"),
    ("YouTube", "https://www.youtube.com/{}"),
    ("SoundCloud", "https://www.soundcloud.com/{}"),
    ("Snapchat", "https://www.snapchat.com/add/{}"),
    ("TikTok", "https://www.tiktok.com/@{}"),
    ("Behance", "https://www.behance.net/{}"),
    ("Medium", "https://www.medium.com/@{}"),
    ("Quora", "https://www.quora.com/profile/{}"),
    ("Flickr", "https://www.flickr.com/people/{}"),
    ("Twitch", "https://www.twitch.tv/{}"),
    ("Dribbble", "https://www.dribbble.com/{}"),
    ("Ello", "https://www.ello.co/{}"),
    ("Product Hunt", "https://www.producthunt.com/@{}"),
    ("Telegram", "https://www.telegram.me/{}"),
    ("We Heart It", "https://www.weheartit.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("Pinterest(IN)", "https://in.pinterest.com/{}"),
    ("GitHub Gist", "https://gist.github.com/{}"),
]


def check_username(username: str, put):
    """并发检测用户名, put(('row'|'progress'|'done', ...)) 回传结果。
    使用线程本地 Session 复用连接。"""
    total = len(SOCIAL_SITES)
    done_count = 0
    lock = threading.Lock()
    tls = threading.local()

    def session():
        s = getattr(tls, "sess", None)
        if s is None:
            s = make_session()
            tls.sess = s
        return s

    def one(item):
        nonlocal done_count
        name, tpl = item
        url = tpl.format(username)
        try:
            r = session().get(url, headers=UA, timeout=(5, 8), allow_redirects=True)
            code = r.status_code
            if code == 200:
                status, ok = f"HTTP {code} · 可能存在", True
            else:
                status, ok = f"HTTP {code} · 未找到/被拦截", False
        except requests.Timeout:
            status, ok = "请求超时", False
        except Exception as exc:
            status, ok = f"错误: {type(exc).__name__}", False
        with lock:
            done_count += 1
            n = done_count
        put(("row", name, status, url, ok))
        put(("progress", n, total))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(one, SOCIAL_SITES))
    put(("done",))


# ================================================================ 扩展查询逻辑
def _ssl_cert_info(host: str, port: int = 443, timeout: float = 6):
    """获取 TLS 证书摘要。返回 dict 或 None。"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        return {
            "subject": subject.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "san_count": len(san),
            "san_sample": ", ".join(san[:5]),
            "protocol": ssock.version() if ssock else "",
            "cipher": cipher[0] if cipher else "",
        }
    except Exception:
        return None


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR_RE = re.compile(rb'<meta[^>]+name=["\']generator["\']+[^>]+content=["\']([^"\']+)', re.I)


def web_fingerprint(url: str):
    """被动 Web 指纹: 状态/重定向/响应头/标题/技术线索/SSL 证书。返回 (rows, error)。"""
    url = url.strip()
    if not url:
        return [], "请输入 URL 或域名"
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = HTTP.get(url, headers=UA, timeout=(5, 15), allow_redirects=True)
    except requests.exceptions.SSLError:
        url = url.replace("https://", "http://", 1)
        try:
            resp = HTTP.get(url, headers=UA, timeout=(5, 15), allow_redirects=True)
        except Exception as exc:
            return [], f"请求失败: {exc}"
    except Exception as exc:
        return [], f"请求失败: {exc}"

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    rows = [
        ("最终 URL", resp.url),
        ("HTTP 状态", resp.status_code),
        ("响应耗时", f"{resp.elapsed.total_seconds():.2f}s"),
        ("内容类型", hdrs.get("content-type", "")),
        ("内容长度", hdrs.get("content-length", "")),
    ]
    chain = " → ".join(f"{h.status_code} {h.url}" for h in resp.history)
    rows.append(("重定向链", chain if chain else "无"))
    # 关键响应头
    for key, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"),
                       ("via", "Via"), ("cf-ray", "Cloudflare Ray"),
                       ("x-generator", "X-Generator"), ("strict-transport-security", "HSTS")):
        if key in hdrs:
            rows.append((label, hdrs[key]))
    cookies = re.findall(r"([^=,;\s]+)=", resp.headers.get("Set-Cookie", ""))
    if cookies:
        rows.append(("Cookie 名", ", ".join(dict.fromkeys(cookies))[:200]))
    # 页面标题 + 技术线索
    body = resp.content[:300000]
    m = _TITLE_RE.search(body)
    title = m.group(1).decode("utf-8", "replace").strip() if m else ""
    rows.append(("页面标题", title[:120]))
    hints = []
    srv = hdrs.get("server", "").lower()
    for kw, name in (("nginx", "Nginx"), ("apache", "Apache"), ("cloudflare", "Cloudflare"),
                     ("microsoft-iis", "IIS"), ("litespeed", "LiteSpeed"), ("gws", "Google")):
        if kw in srv:
            hints.append(name)
    xp = hdrs.get("x-powered-by", "").lower()
    for kw, name in (("php", "PHP"), ("asp.net", "ASP.NET"), ("express", "Express"),
                     ("next.js", "Next.js")):
        if kw in xp:
            hints.append(name)
    ck = resp.headers.get("Set-Cookie", "")
    if "PHPSESSID" in ck:
        hints.append("PHP(会话)")
    if "JSESSIONID" in ck:
        hints.append("Java(会话)")
    if "ASP.NET_SessionId" in ck:
        hints.append("ASP.NET(会话)")
    if b"wp-content" in body or b"WordPress" in body:
        hints.append("WordPress")
    if b"__NEXT_DATA__" in body:
        hints.append("Next.js")
    if b"Drupal.settings" in body:
        hints.append("Drupal")
    gm = _GENERATOR_RE.search(body)
    if gm:
        hints.append("generator:" + gm.group(1).decode("utf-8", "replace")[:40])
    if hdrs.get("server", "").lower().find("cloudflare") >= 0 or "cf-ray" in hdrs:
        hints.append("Cloudflare CDN")
    rows.append(("技术线索", " · ".join(dict.fromkeys(hints)) if hints else "未识别"))
    # SSL 证书
    if resp.url.lower().startswith("https://"):
        host = re.sub(r"^https?://", "", resp.url).split("/")[0].split(":")[0]
        info = _ssl_cert_info(host)
        if info:
            rows += [
                ("证书主体 CN", info["subject"]),
                ("证书颁发者", f'{info["issuer_org"]} ({info["issuer_cn"]})'.strip()),
                ("有效期至", info["not_after"]),
                ("SAN 数量", info["san_count"]),
                ("SAN 示例", info["san_sample"]),
                ("TLS 协议", info["protocol"]),
                ("加密套件", info["cipher"]),
            ]
        else:
            rows.append(("TLS 证书", "获取失败 / 不支持"))
    return rows, None


def batch_lookup_one(item: str):
    """批量查询单个 IP/域名。返回 (输入, 国家, 城市, ISP, 机构, 纬度, 经度, 状态)。"""
    item = item.strip()
    try:
        resp = HTTP.get(f"http://ipwho.is/{item}", timeout=(5, 12))
        d = resp.json()
    except Exception as exc:
        return (item, "", "", "", "", "", "", f"错误: {type(exc).__name__}")
    if d.get("success") is False:
        return (item, "", "", "", "", "", "", f"失败: {d.get('message', '')}"[:60])
    conn = d.get("connection") or {}
    return (item, d.get("country", ""), d.get("city", ""), conn.get("isp", ""),
            conn.get("org", ""), d.get("latitude", ""), d.get("longitude", ""), "OK")


def parse_ports(text: str) -> list[int]:
    """解析逗号/空格分隔的端口列表, 去重排序, 上限 200。"""
    parts = re.split(r"[,\s;]+", text.strip())
    ports = sorted({int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 65535})
    return ports[:200]


def check_port(host: str, port: int) -> tuple[int, bool, float]:
    """TCP connect 探测。返回 (端口, 是否开放, 耗时秒)。"""
    t0 = datetime.now()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return port, True, (datetime.now() - t0).total_seconds()
    except Exception:
        return port, False, (datetime.now() - t0).total_seconds()


def local_network_info():
    """本机网络信息: 公网 IP+归属 / 本机 IPv4 / MAC。返回 (rows, error)。"""
    rows = []
    try:
        pub = query_own_ip()
        rows.append(("公网 IP", pub))
        try:
            d = HTTP.get(f"http://ipwho.is/{pub}", timeout=(5, 12)).json()
            if d.get("success"):
                rows.append(("公网归属", f'{d.get("country", "")} {d.get("city", "")}'.strip()))
                rows.append(("运营商", (d.get("connection") or {}).get("isp", "")))
        except Exception:
            pass
    except Exception as exc:
        rows.append(("公网 IP", f"获取失败: {exc}"))
    try:
        import psutil
        ips, macs = [], []
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    ips.append(f"{a.address} ({name})")
                elif a.family == psutil.AF_LINK and a.address and a.address != "00:00:00:00:00:00":
                    macs.append(f"{a.address} ({name})")
        rows.append(("本机 IPv4", " · ".join(ips) if ips else "无"))
        rows.append(("MAC 地址", " · ".join(macs) if macs else "无"))
    except Exception as exc:
        rows.append(("本机接口", f"读取失败: {exc}"))
    return rows, None


def load_history() -> list[dict]:
    try:
        data = json.loads(HIST_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


# ================================================================ 国内号码归属地库 (ls0f/phone, MIT)
PHONE_DAT = WORKSPACE / "phonedata" / "phone" / "phone.dat"

CN_CARD_TYPES = {
    1: "中国移动", 2: "中国联通", 3: "中国电信",
    4: "中国电信虚拟运营商", 5: "中国联通虚拟运营商", 6: "中国移动虚拟运营商",
    7: "中国广电", 8: "中国广电虚拟运营商",
}

_cn_db = None


class CNPhoneDB:
    """phone.dat 解析: 头部(版本+索引起始), 索引区 <iiB> 前7位/记录偏移/卡类型,
    记录区 省份|城市|邮编|长途区号\\0。前 7 位二分查找。"""

    def __init__(self, path):
        import struct
        self.buf = Path(path).read_bytes()
        self.version, self.first_offset = struct.unpack_from("<Ii", self.buf, 0)
        self.count = (len(self.buf) - self.first_offset) // 9
        self._entry = struct.Struct("<iiB")

    @property
    def version_date(self) -> str:
        """版本号若为 unix 时间戳则转日期。"""
        v = self.version
        if 1420070400 <= v <= 2208988800:  # 2015-01-01 ~ 2040-01-01
            return datetime.fromtimestamp(v).strftime("%Y-%m-%d")
        return str(v)

    def find(self, phone7: str):
        """按前 7 位查询, 返回 dict 或 None。"""
        target = int(str(phone7)[:7])
        lo, hi = 0, self.count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            off = self.first_offset + mid * 9
            cur, rec_off, ctype = self._entry.unpack_from(self.buf, off)
            if cur == target:
                end = self.buf.find(b"\x00", rec_off)
                parts = self.buf[rec_off:end].decode("utf-8", "replace").split("|")
                if len(parts) < 4:
                    return None
                return {"province": parts[0], "city": parts[1], "zip": parts[2],
                        "area_code": parts[3],
                        "card_type": CN_CARD_TYPES.get(ctype, f"未知({ctype})")}
            if cur < target:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


def get_cn_db():
    """懒加载归属地库 (ls0f/phone, 提供邮编)。"""
    global _cn_db
    if _cn_db is None:
        if not PHONE_DAT.exists():
            raise FileNotFoundError(PHONE_DAT)
        _cn_db = CNPhoneDB(PHONE_DAT)
    return _cn_db


# ================================================================ XEngine 号码库 (libxengine/XEngine_PhoneData)
# 数据 2025-08, 517,259 条, 完全覆盖 ls0f 并多出 1.7 万新号段; 格式支持携号转网/座机/物联网/卫星
XENGINE_DAT = WORKSPACE / "phonedata" / "xengine_phone_utf.dat"

XENG_OPS = {
    0: "未知", 1: "中国移动", 2: "中国联通", 3: "中国电信", 4: "中国广电",
    10: "中国电信虚拟", 11: "中国联通虚拟", 12: "中国移动虚拟",
    20: "中国电信座机", 21: "中国联通座机", 22: "中国移动座机",
    30: "卫星通信", 31: "物联网",
}

_xe_db = None


class XEnginePhoneDB:
    """XEngine phone_utf.dat 解析: 分区协议头(14B magic + type + size)。
    分区3=位置(区号-省份-城市, 空格分隔); 分区4=号码索引(前缀-区号-运营商码-携转标志[-原运营商码], \\n分隔,
    size 字段为条数而非字节数, 负载延伸到文件尾)。"""

    _MAGIC = bytes.fromhex("11000000000000000000c8000000")

    def __init__(self, path):
        import struct
        data = Path(path).read_bytes()
        # 遍历分区头
        pos, parts = 0, []
        while True:
            i = data.find(self._MAGIC, pos)
            if i < 0:
                break
            ptype, psize = struct.unpack_from("<II", data, i + 14)
            parts.append((i, ptype, psize))
            pos = i + 1
        # 版本 (分区1)
        self.version = "?"
        for off, ptype, psize in parts:
            if ptype == 1:
                self.version = data[off + 30: off + 30 + psize].decode("ascii", "replace")
                break
        # 位置分区 (分区3): 区号 -> (省, 市)
        self.area_map: dict[str, tuple[str, str]] = {}
        for off, ptype, psize in parts:
            if ptype == 3:
                text = data[off + 30: off + 30 + psize].decode("utf-8", "replace")
                for ent in text.split(" "):
                    f = ent.split("-")
                    if len(f) >= 3:
                        self.area_map[f[0]] = (f[1], "-".join(f[2:]))
                break
        # 号码分区 (分区4): 前缀 -> (区号, 运营商码, 携转标志, 原运营商码)
        self.prefix_map: dict[int, tuple[str, int, int, int]] = {}
        self.count = 0
        self.ported_count = 0
        for off, ptype, _ in parts:
            if ptype == 4:
                for ln in data[off + 30:].split(b"\n"):
                    if not ln:
                        continue
                    f = ln.split(b"-")
                    if len(f) < 4:
                        continue
                    try:
                        prefix = int(f[0])
                        op = int(f[2])
                        fl = int(f[3])
                        orig = int(f[4]) if len(f) > 4 else 0
                    except ValueError:
                        continue
                    self.prefix_map[prefix] = (f[1].decode("ascii", "replace"), op, fl, orig)
                    self.count += 1
                    if fl == 1:
                        self.ported_count += 1
                break
        self.data = None  # 释放原始字节

    def find(self, phone7: str):
        """按前 7 位查询。返回 dict 或 None。"""
        v = self.prefix_map.get(int(str(phone7)[:7]))
        if v is None:
            return None
        area, op, fl, orig = v
        prov, city = self.area_map.get(area, ("", ""))
        return {
            "province": prov, "city": city, "area_code": area,
            "op_code": op, "op_name": XENG_OPS.get(op, f"未知({op})"),
            "ported": fl == 1,
            "original_op": XENG_OPS.get(orig, f"未知({orig})") if fl == 1 else None,
        }


def get_xe_db():
    """懒加载 XEngine 号码库。"""
    global _xe_db
    if _xe_db is None:
        if not XENGINE_DAT.exists():
            raise FileNotFoundError(XENGINE_DAT)
        _xe_db = XEnginePhoneDB(XENGINE_DAT)
    return _xe_db


# ================================================================ 新增 OSINT 逻辑
def dns_lookup(domain: str, rtype: str):
    """通过 dns.google 公共 DNS JSON API 被动查询。返回 (rows, error)。"""
    domain = domain.strip().rstrip(".")
    if not domain or " " in domain:
        return [], "请输入有效域名"
    try:
        resp = HTTP.get("https://dns.google/resolve",
                        params={"name": domain, "type": rtype}, timeout=(5, 15))
        data = resp.json()
    except Exception as exc:
        return [], f"查询失败: {exc}"
    st = data.get("Status")
    if st == 3:
        return [], "NXDOMAIN — 域名不存在"
    if st != 0:
        return [], f"DNS 错误码 {st}"
    rows = []
    for section in ("Answer", "Authority", "Additional"):
        for ans in data.get(section) or []:
            t = ans.get("type")
            tname = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS",
                     16: "TXT", 6: "SOA", 33: "SRV", 35: "NAPTR"}.get(t, str(t))
            rows.append((f"{section[:3]}. {ans.get('name', '')}", tname,
                         ans.get("data", "")))
    if not rows:
        return [], "无记录"
    return rows, None


def rdap_lookup(domain: str):
    """RDAP 查询 (rdap.org 转发到对应注册局)。返回 (rows, error)。"""
    domain = domain.strip().rstrip(".").lower()
    if not domain or " " in domain or "/" in domain:
        return [], "请输入有效域名"
    try:
        resp = HTTP.get(f"https://rdap.org/domain/{domain}",
                        headers={"Accept": "application/rdap+json"},
                        timeout=(5, 20), allow_redirects=True)
        if resp.status_code == 404:
            return [], "RDAP 无数据 (域名不存在或该后缀未接入 RDAP)"
        if resp.status_code != 200:
            return [], f"RDAP HTTP {resp.status_code}"
        d = resp.json()
    except Exception as exc:
        return [], f"查询失败: {exc}"
    rows = [
        ("域名", d.get("ldhName", domain)),
        ("Handle", d.get("handle", "")),
        ("状态", ", ".join(d.get("status") or [])),
        ("对象类", d.get("objectClassName", "")),
    ]
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events") or []}
    for key, label in (("registration", "注册时间"), ("expiration", "到期时间"),
                       ("last changed", "最近变更"), ("last update of RDAP data", "RDAP 更新")):
        if key in events:
            rows.append((label, events[key]))
    ns = [x.get("ldhName", "") for x in d.get("nameservers") or []]
    rows.append(("Nameservers", ", ".join(ns) if ns else "—"))
    for ent in d.get("entities") or []:
        roles = ent.get("roles") or []
        handle = ent.get("handle", "")
        vcard = ""
        for item in ent.get("vcardArray")[1] if ent.get("vcardArray") else []:
            if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "email", "tel", "org"):
                vcard += f"{item[0]}={item[3]}; "
        rows.append((f"实体 [{','.join(roles)}]", f"{handle}  {vcard}".strip()))
    return rows, None


def crtsh_lookup(domain: str, put):
    """crt.sh 证书透明度子域名枚举。put(('crtsh_row'|'crtsh_done', ...))。"""
    domain = domain.strip().rstrip(".").lower()
    if not domain or " " in domain:
        put(("crtsh_done", 0, "请输入有效域名"))
        return
    try:
        resp = HTTP.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                        timeout=(10, 60), headers=UA)
        if resp.status_code != 200:
            put(("crtsh_done", 0, f"crt.sh HTTP {resp.status_code}"))
            return
        items = resp.json()
    except Exception as exc:
        put(("crtsh_done", 0, f"查询失败: {exc}"))
        return
    names = {}
    for it in items:
        nv = (it.get("name_value") or "").strip()
        for nm in nv.splitlines():
            nm = nm.strip().lower().lstrip("*.")
            if nm.endswith(domain):
                names.setdefault(nm, (it.get("issuer_name", "") or "", it.get("not_before", "")))
    for nm, (issuer, nb) in sorted(names.items()):
        put(("crtsh_row", nm, issuer[:60], nb))
    put(("crtsh_done", len(names), ""))


_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def email_intel(email: str):
    """邮箱情报: 格式/域名提供商/一次性邮箱/MX/Gravatar。返回 (rows, error)。"""
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        return [], "邮箱格式不正确"
    local, domain = email.split("@", 1)
    rows = [
        ("邮箱", email),
        ("用户名部分", local),
        ("邮件域名", domain),
        ("格式校验", "✅ 通过"),
        ("邮箱提供商", MAIL_PROVIDERS.get(domain, "未知 / 自定义域名")),
        ("一次性邮箱", "⚠ 是" if domain in DISPOSABLE_DOMAINS else "否"),
    ]
    # MX 记录
    try:
        resp = HTTP.get("https://dns.google/resolve",
                        params={"name": domain, "type": "MX"}, timeout=(5, 12))
        d = resp.json()
        ans = d.get("Answer") or []
        mx = []
        for a in ans:
            if a.get("type") == 15:
                data = str(a.get("data", ""))
                parts = data.split(" ", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    mx.append(f"{parts[0]} {parts[1].rstrip('.')}")
                else:
                    mx.append(data.rstrip("."))
        rows.append(("MX 记录", " · ".join(mx) if mx else "无"))
    except Exception:
        rows.append(("MX 记录", "查询失败"))
    # Gravatar
    h = hashlib.md5(email.encode("utf-8")).hexdigest()
    rows.append(("Gravatar 哈希", h))
    rows.append(("Gravatar 主页", f"https://cn.gravatar.com/{h}"))
    rows.append(("默认头像", f"https://cn.gravatar.com/avatar/{h}?d=retro"))
    # 本地部分启发式
    if re.fullmatch(r"\d{5,}", local):
        rows.append(("本地部分线索", "纯数字 — 可能是手机号邮箱"))
    elif re.match(r"^[a-z]+\.[a-z]+", local):
        rows.append(("本地部分线索", "形如 姓.名 — 可能是实名格式"))
    return rows, None


def identify_hash(value: str):
    """本地哈希类型识别。返回 (rows, error)。"""
    value = value.strip()
    if not value:
        return [], "请输入哈希值"
    if len(value) < 8:
        return [], "输入过短, 无法识别"
    rows = [("输入长度", f"{len(value)} 字符")]
    lowered = value.lower()
    rows.append(("字符集", "十六进制" if re.fullmatch(r"[0-9a-f]+", lowered) else "混合/base64/crypt"))
    matched = []
    for pat, names in HASH_PATTERNS:
        if re.match(pat, value) or re.match(pat, lowered):
            matched.extend(names)
    if not matched:
        # 按长度启发
        if re.fullmatch(r"[0-9a-f]+", lowered):
            L = len(lowered)
            bits = {32: "128-bit", 40: "160-bit", 56: "224-bit", 64: "256-bit",
                    96: "384-bit", 128: "512-bit"}.get(L)
            matched = [f"未知哈希 ({bits})" if bits else "未知哈希"]
        else:
            matched = ["未能识别 — 可能是加密数据或非标准编码"]
    rows.append(("可能类型", " / ".join(dict.fromkeys(matched))))
    rows.append(("是否十六进制", "是" if re.fullmatch(r"[0-9a-fA-F]+", value) else "否"))
    rows.append(("本地部分线索", f"首字符 {value[0]!r} · 尾字符 {value[-1]!r}"))
    return rows, None


def ping_host(host: str, count: int = 4, timeout: int = 3):
    """ICMP ping, 返回 (rows, error)。"""
    host = host.strip()
    if not host:
        return [], "请输入主机"
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=count * timeout + 5,
                           creationflags=CREATE_NO_WINDOW)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return [], "ping 超时"
    except Exception as exc:
        return [], f"ping 失败: {exc}"
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if any(k in low for k in ("ttl=", "time=", "字节=", "时间=", "往返", "packets")):
            rows.append(("回复", line))
    if not rows:
        rows.append(("输出", out.strip()[:800] or "无输出"))
    # 提取统计 (兼容中英文 + 全角括号)
    m = re.search(r"[（(](\d+)%\s*(?:loss|丢失|packet|丢包)", out, re.I)
    if not m:
        m = re.search(r"(\d+)%\s*(?:loss|丢失)", out, re.I)
    if m:
        rows.append(("丢包率", f"{m.group(1)}%"))
    ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", out)
    if ips:
        rows.append(("解析到 IP", ips[0]))
    return rows, None


def traceroute_host(host: str, max_hops: int = 20, timeout: int = 2000):
    """路由追踪, 返回 (rows, error)。Windows tracert / Unix traceroute。"""
    host = host.strip()
    if not host:
        return [], "请输入主机"
    if os.name == "nt":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout // 1000 or 1), host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=max_hops * (timeout / 1000) + 15,
                           creationflags=CREATE_NO_WINDOW)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return [], "路由追踪超时"
    except Exception as exc:
        return [], f"路由追踪失败: {exc}"
    rows = []
    for line in out.splitlines():
        s = line.rstrip()
        if s and not s.startswith("Trace") and "tracing" not in s.lower():
            rows.append((f"hop {len(rows)+1}", s.strip()))
        if len(rows) >= max_hops:
            break
    if not rows:
        rows.append(("输出", out.strip()[:800] or "无输出"))
    return rows, None


def reverse_dns(ip: str):
    """PTR 反向解析。返回 (rows, error)。"""
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return [], "请输入有效 IP 地址"
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        rows = [("PTR 记录", host), ("别名", ", ".join(aliases) if aliases else "—")]
        return rows, None
    except socket.herror:
        return [], "无 PTR 记录"
    except Exception as exc:
        return [], f"查询失败: {exc}"


def whois_port43(domain: str):
    """备用: 通过 whois.iana.org 查询后缀注册信息 (轻量)。返回 (rows, error)。"""
    domain = domain.strip().rstrip(".").lower()
    suffix = domain.rsplit(".", 1)[-1]
    if not suffix or "." not in domain:
        return [], "请输入完整域名"
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=8) as s:
            s.sendall(f"n {suffix}\r\n".encode())
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b.decode("utf-8", "replace"))
        text = "".join(chunks)
    except Exception as exc:
        return [], f"whois 查询失败: {exc}"
    rows = []
    for line in text.splitlines():
        if ":" in line and not line.startswith("%"):
            k, v = line.split(":", 1)
            k = k.strip().lower()
            if k in ("domain name", "organisation", "organization", "contact",
                     "address", "name server", "status", "creation date",
                     "source", "whois", "remarks"):
                rows.append((k.title(), v.strip()))
        if len(rows) > 60:
            break
    return (rows or [("原始输出", text.strip()[:1000])]), None


# ================================================================ Seeker 模板参数
PARAM_SPEC = {
    "nearyou": [],
    "gdrive": ["REDIRECT"],
    "whatsapp": ["TITLE", "IMAGE"],
    "whatsapp_redirect": ["TITLE", "IMAGE", "REDIRECT"],
    "telegram": ["TITLE", "IMAGE", "DESC", "MEM_NUM", "ONLINE_NUM"],
    "zoom": [],
    "captcha": ["REDIRECT", "DISPLAY_URL"],
    "custom_og_tags": ["REDIRECT", "SITENAME", "TITLE", "IMAGE", "DESC"],
}

PARAM_LABELS = {
    "TITLE": "页面标题",
    "IMAGE": "图片 (本地路径或 URL)",
    "REDIRECT": "跳转目标 URL",
    "DESC": "描述文字",
    "MEM_NUM": "显示的成员数",
    "ONLINE_NUM": "显示的在线数",
    "SITENAME": "站点名称",
    "DISPLAY_URL": "显示的 URL 文本",
}

PARAM_HINTS = {
    "IMAGE": "群头像 / 预览图, 可点「浏览」选择本地文件",
    "REDIRECT": "访问者点击后真实跳转的地址",
    "DISPLAY_URL": "页面上显示的地址文本",
}

SEEKER_CSV_COLS = [
    "OS", "平台", "CPU核", "RAM", "GPU厂商", "GPU", "分辨率", "浏览器", "公网IP",
    "大洲", "国家", "地区", "城市", "机构", "ISP",
    "纬度", "经度", "精度", "海拔", "方向", "速度",
]


def load_templates():
    p = SEEKER_DIR / "template" / "templates.json"
    return json.loads(p.read_text(encoding="utf-8"))["templates"]


# ================================================================ 主题
C = {
    "bg": "#0d0d15", "panel": "#161622", "panel2": "#1f1f30",
    "field": "#252538", "row_odd": "#191926", "row_even": "#20202f",
    "accent": "#89b4fa", "accent2": "#b4befe", "green": "#a6e3a1",
    "red": "#f38ba8", "yellow": "#f9e2af", "mauve": "#cba6f7",
    "fg": "#cdd6f4", "dim": "#8f96b0", "line": "#2e2e42",
}

FONT = ("Microsoft YaHei UI", 10)
FONT_SM = ("Microsoft YaHei UI", 9)
FONT_MONO = ("Consolas", 9)
FONT_TITLE = ("Segoe UI Variable Display", 15, "bold")
FONT_TAB = ("Microsoft YaHei UI", 10)

LOG_KEEP = 2000
LOG_TRIM_TO = 1400
HIST_KEEP = 500

PH_IP = "8.8.8.8  或留空查本机"
PH_PHONE = "+8613800138000"
PH_USER = "要检测的用户名"
PH_WEB = "example.com  或  https://example.com/path"
PH_BATCH = "每行一个 IP / 域名\n8.8.8.8\n1.1.1.1"
PH_PORTS = "21,22,53,80,443,3389,8080"
PH_PHOST = "目标主机 (IP 或域名)"
PH_EMAIL = "someone@example.com"
PH_DOMAIN = "example.com"
PH_HASH = "粘贴哈希值, 如 5d41402abc4b2a76b9719d911017c592"

PRESET_PORTS = "21,22,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,9200,27017"

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "temp-mail.org", "tempmail.lol",
    "guerrillamail.com", "guerrillamail.info", "10minutemail.com", "10minutemail.net",
    "yopmail.com", "yopmail.fr", "trashmail.com", "trashmail.me", "trashmail.net",
    "fakeinbox.com", "sharklasers.com", "getnada.com", "maildrop.cc",
    "dispostable.com", "mailnesia.com", "tempail.com", "tempr.email",
    "discard.email", "discardmail.com", "mailcatch.com", "throwawaymail.com",
    "linshiyouxiang.net", "24mail.chacuo.net", "bccto.me", "chacuo.net",
    "moakt.com", "mohmal.com", "kurzepost.de", "tagyouremail.com",
    "spam4.me", "mailsac.com", "etempmail.com", "tempail.com",
    "emailondeck.com", "mytemp.email", "dropmail.me", "linshiyouxiang.com",
}

MAIL_PROVIDERS = {
    "gmail.com": "Google Gmail", "googlemail.com": "Google Gmail",
    "outlook.com": "Microsoft Outlook", "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live", "msn.com": "Microsoft MSN",
    "yahoo.com": "Yahoo", "yahoo.co.jp": "Yahoo Japan", "yahoo.co.uk": "Yahoo UK",
    "qq.com": "腾讯 QQ 邮箱", "foxmail.com": "腾讯 Foxmail",
    "163.com": "网易 163", "126.com": "网易 126", "yeah.net": "网易 Yeah",
    "139.com": "中国移动邮箱", "189.cn": "中国电信天翼", "wo.com.cn": "中国联通沃邮箱",
    "aliyun.com": "阿里云邮箱", "taobao.com": "淘宝邮箱",
    "sina.com": "新浪邮箱", "sina.cn": "新浪邮箱", "sohu.com": "搜狐邮箱",
    "icloud.com": "Apple iCloud", "me.com": "Apple iCloud", "mac.com": "Apple iCloud",
    "protonmail.com": "ProtonMail", "proton.me": "ProtonMail", "protonmail.ch": "ProtonMail",
    "tutanota.com": "Tutanota", "tuta.io": "Tutanota",
    "gmx.com": "GMX", "gmx.de": "GMX", "mail.com": "GMX",
    "zoho.com": "Zoho", "zoho.com.cn": "Zoho",
    "yandex.com": "Yandex", "yandex.ru": "Yandex",
    "rambler.ru": "Rambler", "mail.ru": "Mail.ru",
}

HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$", ["MD5", "NTLM"]),
    (r"^[a-f0-9]{40}$", ["SHA-1"]),
    (r"^[a-f0-9]{56}$", ["SHA-224"]),
    (r"^[a-f0-9]{64}$", ["SHA-256", "SHA3-256", "SHA-512/256"]),
    (r"^[a-f0-9]{96}$", ["SHA-384"]),
    (r"^[a-f0-9]{128}$", ["SHA-512", "SHA3-512"]),
    (r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
    (r"^5crypt\$.*", ["sha512crypt ($6$)"]),
    (r"^\$6\$.*", ["sha512crypt ($6$)"]),
    (r"^\$5\$.*", ["sha256crypt ($5$)"]),
    (r"^\$1\$.*", ["md5crypt ($1$)"]),
    (r"^\$apr1\$.*", ["Apache apr1"]),
    (r"^\$argon2id?\$.*", ["Argon2"]),
    (r"^\$pbkdf2[-_].*", ["PBKDF2"]),
    (r"^\{SSHA\}.*", ["LDAP SSHA"]),
    (r"^\{SHA\}.*", ["LDAP SHA"]),
    (r"^[\w+/]{40}={0,2}$", ["SHA-1 base64"]),
    (r"^[\w+/]{86}==$", ["SHA-512 base64"]),
    (r"^[\w+/]{43}=$", ["SHA-256 base64"]),
]


# ================================================================ 小工具
def _lerp_hex(c1: str, c2: str, t: float) -> str:
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


class ToolTip:
    """简易悬浮提示。"""

    def __init__(self, widget, text):
        self.widget, self.text = widget, text
        self.tw = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, _event=None):
        if self.tw:
            return
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tw, text=self.text, bg=C["line"], fg=C["fg"],
                 font=FONT_SM, padx=9, pady=4).pack()

    def _hide(self, _event=None):
        if self.tw:
            self.tw.destroy()
            self.tw = None


def add_placeholder(entry: tk.Entry, text: str):
    """灰色占位提示, 聚焦自动清除。"""

    def on_in(_e):
        if entry.get() == text:
            entry.delete(0, "end")
            entry.configure(foreground=C["fg"])

    def on_out(_e):
        if not entry.get():
            entry.insert(0, text)
            entry.configure(foreground=C["dim"])

    entry.configure(foreground=C["dim"])
    entry.insert(0, text)
    entry.bind("<FocusIn>", on_in)
    entry.bind("<FocusOut>", on_out)


def add_placeholder_text(text: tk.Text, text_hint: str):
    """多行输入框占位提示。"""

    def on_in(_e):
        if text.get("1.0", "end-1c") == text_hint:
            text.delete("1.0", "end")
            text.configure(fg=C["fg"])

    def on_out(_e):
        if not text.get("1.0", "end-1c").strip():
            text.insert("1.0", text_hint)
            text.configure(fg="#4a4f66")

    text.insert("1.0", text_hint)
    text.configure(fg="#4a4f66")
    text.bind("<FocusIn>", on_in)
    text.bind("<FocusOut>", on_out)


def entry_value(entry: tk.Entry, placeholder: str) -> str:
    v = entry.get().strip()
    return "" if v == placeholder else v


def text_value(text: tk.Text, placeholder: str) -> str:
    v = text.get("1.0", "end-1c")
    return "" if v.strip() == placeholder else v


def apply_dark_titlebar(hwnd: int):
    """Windows 10/11 深色标题栏。"""
    if os.name != "nt":
        return
    try:
        import ctypes
        for attr in (20, 19):
            try:
                val = ctypes.c_int(1)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
                return
            except Exception:
                continue
    except Exception:
        pass


def make_icon_photo():
    """PIL 自绘幽灵图标 (256px 高清版, 按 DPI 缩放), 返回 PhotoImage; 失败返回 None。"""
    try:
        from PIL import Image, ImageDraw
        base = 256
        px = base / 64.0  # 原始 64px 设计稿的缩放倍率
        img = Image.new("RGBA", (base, base), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        body = (205, 214, 244, 255)
        dark = (18, 18, 26, 255)
        accent = (137, 180, 250, 255)

        def sc(*v):
            return [x * px for x in v]

        d.rounded_rectangle(sc(12, 6, 52, 54), radius=20 * px, fill=body)
        for cx in (20, 32, 44):
            d.ellipse(sc(cx - 7, 44, cx + 7, 58), fill=body)
        d.rectangle(sc(12, 40, 52, 54), fill=body)
        d.ellipse(sc(21, 22, 31, 34), fill=dark)
        d.ellipse(sc(35, 22, 45, 34), fill=dark)
        d.ellipse(sc(16, 33, 24, 39), fill=accent[:3] + (90,))
        d.ellipse(sc(42, 33, 50, 39), fill=accent[:3] + (90,))
        d.arc(sc(27, 33, 41, 45), 20, 160, fill=dark, width=int(3 * px))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return tk.PhotoImage(data=base64.b64encode(buf.getvalue()))
    except Exception:
        return None


# ================================================================ 主应用
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GhostTrack GUI · OSINT 工具套件")
        self._cfg_file = WORKSPACE / ".ghosttrack_gui.json"
        self._load_geometry()
        self.minsize(S(900), S(620))
        self.configure(bg=C["bg"])

        self.q: queue.Queue = queue.Queue()
        self.last_maps_url = None
        self.last_web_url = None
        self.seeker_proc: subprocess.Popen | None = None
        self.seeker_running = False
        self.templates = load_templates() if (SEEKER_DIR / "template" / "templates.json").exists() else []
        self.param_entries: dict[str, tk.Entry] = {}
        self._empty_labels: dict[ttk.Treeview, tk.Label] = {}
        self._busy = False
        self._status_color = C["dim"]
        self._pulse_on = True
        self.history: list[dict] = load_history()
        self._icon = make_icon_photo()
        if self._icon:
            self.iconphoto(True, self._icon)

        self._build_style()
        self._build_header()
        self._build_body()
        self._build_statusbar()
        self._poll_queue()
        self._tick_clock()
        self._pulse_loop()
        self._bind_shortcuts()

        self.after(80, lambda: apply_dark_titlebar(self.winfo_id()))

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind("<Control-q>", lambda e: self.destroy())

    def _load_geometry(self):
        """恢复上次窗口位置/大小。"""
        self.geometry(f"{S(1040)}x{S(740)}")
        try:
            cfg = json.loads(self._cfg_file.read_text(encoding="utf-8"))
            geo = cfg.get("geometry")
            if geo and re.match(r"^\d+x\d+[+-]\d+[+-]\d+$", geo):
                self.geometry(geo)
        except Exception:
            pass

    def _save_geometry(self):
        try:
            self._cfg_file.write_text(
                json.dumps({"geometry": self.geometry()}), encoding="utf-8")
        except Exception:
            pass

    def _bind_shortcuts(self):
        """Ctrl+1..9 切换标签页。"""
        tabs = self.nb.tabs()
        for i in range(1, min(9, len(tabs)) + 1):
            self.bind(f"<Control-{i}>",
                      lambda e, idx=i - 1: self.nb.select(self.nb.tabs()[idx]))

    # ---------------- 样式
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=C["bg"], foreground=C["fg"], font=FONT)
        style.configure("TFrame", background=C["bg"])
        style.configure("TLabel", background=C["bg"], foreground=C["fg"], font=FONT)
        style.configure("Dim.TLabel", background=C["bg"], foreground=C["dim"], font=FONT_SM)
        style.configure("Warn.TLabel", background=C["bg"], foreground=C["yellow"], font=FONT_SM)
        # 按钮: 细边框 + 悬停发光, 更像暗色 web 卡片按钮
        style.configure("TButton", background=C["panel2"], foreground=C["fg"],
                        borderwidth=1, relief="solid", focusthickness=0,
                        padding=(15, 6), font=FONT)
        style.map("TButton",
                  background=[("active", C["line"]), ("disabled", C["panel"])],
                  foreground=[("disabled", "#4a4f66"), ("active", C["accent2"])],
                  bordercolor=[("focus", C["accent"]), ("active", C["accent"])])
        style.configure("Accent.TButton", background=C["accent"], foreground="#0a0a12",
                        font=("Microsoft YaHei UI", 10, "bold"), padding=(18, 6),
                        borderwidth=1, relief="solid")
        style.map("Accent.TButton",
                  background=[("active", "#9dc0ff"), ("disabled", C["panel"])],
                  foreground=[("disabled", "#4a4f66")],
                  bordercolor=[("focus", "#c7dbff"), ("active", "#c7dbff")])
        style.configure("Danger.TButton", background="#5e2231", foreground="#f5d7de",
                        borderwidth=1, relief="solid", padding=(15, 6), font=FONT)
        style.map("Danger.TButton",
                  background=[("active", C["red"]), ("disabled", C["panel"])],
                  foreground=[("disabled", "#4a4f66")],
                  bordercolor=[("focus", C["red"]), ("active", C["red"])])
        # 输入框: 聚焦时边框发光 (accent2)
        style.configure("TEntry", fieldbackground=C["field"], foreground=C["fg"],
                        insertcolor=C["fg"], borderwidth=1, padding=5)
        style.map("TEntry",
                  bordercolor=[("focus", C["accent2"])],
                  lightcolor=[("focus", C["accent2"])])
        # 下拉: 暗色弹出列表
        style.configure("TCombobox", fieldbackground=C["field"], foreground=C["fg"],
                        background=C["field"], padding=5, arrowcolor=C["dim"],
                        borderwidth=1, lightcolor=C["line"], darkcolor=C["line"])
        style.map("TCombobox",
                  bordercolor=[("focus", C["accent2"])],
                  fieldbackground=[("readonly", C["field"])],
                  foreground=[("readonly", C["fg"])],
                  selectbackground=[("readonly", C["field"])],
                  selectforeground=[("readonly", C["fg"])])
        try:
            self.tk.call("set ::tk::combobox::listboxBackground", C["panel2"])
            self.tk.call("set ::tk::combobox::listboxForeground", C["fg"])
            self.tk.call("set ::tk::combobox::listboxActiveBackground", C["accent"])
            self.tk.call("set ::tk::combobox::listboxActiveForeground", "#0a0a12")
        except tk.TclError:
            pass
        # 标签页: 悬停变色 + 选中项发光 (底边强调线用 Canvas 画)
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["panel"], foreground=C["dim"],
                        padding=(15, 9), font=FONT_TAB, borderwidth=1)
        style.map("TNotebook.Tab",
                  background=[("selected", C["panel2"]), ("active", C["line"])],
                  foreground=[("selected", C["accent2"]), ("active", C["fg"])],
                  padding=[("selected", (15, 11))])
        # 表格: 选中行发光强调
        style.configure("Treeview", background=C["row_odd"], foreground=C["fg"],
                        fieldbackground=C["row_odd"], borderwidth=0, rowheight=S(30), font=FONT)
        style.configure("Treeview.Heading", background=C["panel"], foreground=C["accent"],
                        font=("Microsoft YaHei UI", 10, "bold"), borderwidth=0, padding=(10, 7))
        style.map("Treeview",
                  background=[("selected", "#2c3550")],
                  foreground=[("selected", C["fg"])])
        # 滚动条: 更细 + 圆角把手
        style.configure("Vertical.TScrollbar", background=C["line"], troughcolor=C["bg"],
                        bordercolor=C["bg"], arrowcolor=C["dim"], relief="flat",
                        borderwidth=0, width=11)
        style.map("Vertical.TScrollbar",
                  background=[("active", C["accent"])],
                  arrowcolor=[("active", C["accent"])])
        style.configure("Horizontal.TProgressbar", background=C["accent"],
                        troughcolor=C["panel2"], borderwidth=0, thickness=10)

    # ---------------- 头部品牌栏
    def _build_header(self):
        head = tk.Frame(self, bg=C["panel"])
        head.pack(fill="x")
        inner = tk.Frame(head, bg=C["panel"])
        inner.pack(fill="x", padx=18, pady=(12, 10))
        tk.Label(inner, text="👻", bg=C["panel"],
                 font=("Segoe UI Emoji", 22)).pack(side="left", padx=(0, 10))
        left = tk.Frame(inner, bg=C["panel"])
        left.pack(side="left")
        tk.Label(left, text="GhostTrack GUI", bg=C["panel"], fg=C["fg"],
                 font=FONT_TITLE).pack(anchor="w")
        tk.Label(left, text="OSINT 工具套件 · GhostTrack + Seeker", bg=C["panel"],
                 fg=C["dim"], font=FONT_SM).pack(anchor="w")
        seeker_ver = "?"
        try:
            seeker_ver = json.loads((SEEKER_DIR / "metadata.json").read_text()).get("version", "?")
        except Exception:
            pass
        tk.Label(inner, text=f"v4  ·  Seeker {seeker_ver}",
                 bg=C["panel"], fg=C["dim"], font=FONT_SM).pack(side="right", padx=4)
        # 辉光分隔线: 顶部亮线 + 向下 2px 渐变, 两侧淡出
        glow = tk.Frame(self, bg=C["panel"], height=4)
        glow.pack(fill="x")
        glow.pack_propagate(False)
        self._draw_glow_line(glow)

    def _draw_glow_line(self, frame):
        """头部底边发光强调线: 一条亮线 + 向下渐隐, 两侧淡出。"""
        cv = tk.Canvas(frame, height=S(4), bg=C["panel"], highlightthickness=0)
        cv.pack(fill="both", expand=True)

        def paint(event=None):
            w = cv.winfo_width()
            if w <= 1:
                # withdraw/未映射时宽度可能为 1, 用请求值兜底以便预绘制
                w = S(400)
            if w <= 1:
                return
            cv.delete("all")
            bright = S(2)   # 主亮线高度
            fade1, fade2 = S(1), max(S(1), 1)  # 渐隐层
            # 两侧淡出的水平渐变: 左 accent -> 中 mauve -> 右 accent, 中间更亮
            segs = max(w // S(6), 2)
            for i in range(segs):
                t = i / (segs - 1)
                # 距中心越远越暗 (两端接近背景色)
                edge = 1 - abs(t - 0.5) * 2          # 0..1, 中间为 1
                glow = 0.25 + 0.75 * edge            # 亮度包络
                base = _lerp_hex(C["accent"], C["mauve"], t)
                col = _lerp_hex(C["panel"], base, glow)
                cv.create_rectangle(i * w / segs, 0, (i + 1) * w / segs + 1, bright,
                                    fill=col, width=0)
            # 向下渐隐 (模拟辉光扩散)
            for yy, fade in ((bright, 0.35), (bright + fade1, 0.15)):
                for i in range(segs):
                    t = i / (segs - 1)
                    edge = 1 - abs(t - 0.5) * 2
                    glow = (0.25 + 0.75 * edge) * fade
                    base = _lerp_hex(C["accent"], C["mauve"], t)
                    col = _lerp_hex(C["panel"], base, glow)
                    cv.create_rectangle(i * w / segs, yy, (i + 1) * w / segs + 1, yy + fade2,
                                        fill=col, width=0)

        cv.bind("<Configure>", paint)
        paint()

    # ---------------- 主体 + 状态栏
    def _build_body(self):
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=(10, 0))
        self.nb = ttk.Notebook(body)
        self.nb.pack(fill="both", expand=True)

        self.tab_ip = ttk.Frame(self.nb, padding=16)
        self.tab_phone = ttk.Frame(self.nb, padding=16)
        self.tab_user = ttk.Frame(self.nb, padding=16)
        self.tab_email = ttk.Frame(self.nb, padding=16)
        self.tab_domain = ttk.Frame(self.nb, padding=16)
        self.tab_web = ttk.Frame(self.nb, padding=16)
        self.tab_batch = ttk.Frame(self.nb, padding=16)
        self.tab_net = ttk.Frame(self.nb, padding=16)
        self.tab_seeker = ttk.Frame(self.nb, padding=16)
        self.tab_hist = ttk.Frame(self.nb, padding=16)
        self.tab_about = ttk.Frame(self.nb, padding=20)
        for tab, label in (
            (self.tab_ip, "  🌍 IP  "),
            (self.tab_phone, "  📞 号码  "),
            (self.tab_user, "  🔍 用户名  "),
            (self.tab_email, "  ✉ 邮箱  "),
            (self.tab_domain, "  🏷 域名  "),
            (self.tab_web, "  🌐 Web  "),
            (self.tab_batch, "  ⚡ 批量  "),
            (self.tab_net, "  🛠 工具  "),
            (self.tab_seeker, "  🎯 Seeker  "),
            (self.tab_hist, "  🕘 历史  "),
            (self.tab_about, "  ℹ 关于  "),
        ):
            self.nb.add(tab, text=label)

        self._build_ip_tab()
        self._build_phone_tab()
        self._build_username_tab()
        self._build_email_tab()
        self._build_domain_tab()
        self._build_web_tab()
        self._build_batch_tab()
        self._build_net_tab()
        self._build_seeker_tab()
        self._build_history_tab()
        self._build_about_tab()

    def _build_statusbar(self):
        # 顶部细分隔线
        tk.Frame(self, bg=C["line"], height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self, bg=C["panel"])
        bar.pack(fill="x", side="bottom")
        self.dot = tk.Label(bar, text="●", bg=C["panel"], fg=C["dim"],
                            font=("Segoe UI", 8), padx=12)
        self.dot.pack(side="left")
        self.status_lbl = tk.Label(bar, text="就绪", bg=C["panel"], fg=C["dim"],
                                   font=FONT_SM)
        self.status_lbl.pack(side="left")
        self.hist_lbl = tk.Label(bar, text="", bg=C["panel"], fg="#5b6078", font=FONT_SM)
        self.hist_lbl.pack(side="right", padx=(0, 10))
        self.clock_lbl = tk.Label(bar, text="", bg=C["panel"], fg=C["dim"],
                                  font=FONT_MONO, padx=12)
        self.clock_lbl.pack(side="right")
        # 主题标签点缀
        tk.Label(bar, text="🌙 Dark", bg=C["panel"], fg="#565f89",
                 font=("Microsoft YaHei UI", 8), padx=10).pack(side="right")
        self._update_hist_count()

    def set_status(self, text, color=None):
        self.status_lbl.configure(text=text, fg=color or C["dim"])
        self._status_color = color or C["dim"]
        self._busy = bool(color) and color != C["dim"]
        if not self._busy:
            self.dot.configure(fg=self._status_color)

    def _tick_clock(self):
        self.clock_lbl.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _pulse_loop(self):
        if self._busy:
            self._pulse_on = not self._pulse_on
            self.dot.configure(fg=self._status_color if self._pulse_on else C["line"])
        self.after(550, self._pulse_loop)

    # ---------------- 通用小部件
    def _card(self, parent, title=None):
        """带 1px 细边框 + 左侧渐变强调竖条的卡片容器。返回内容 Frame。"""
        holder = tk.Frame(parent, bg=C["line"], highlightthickness=0)
        holder.pack(fill="x", pady=(0, 12))
        card = tk.Frame(holder, bg=C["panel"], highlightthickness=0)
        card.pack(fill="x", padx=1, pady=1)
        # 左侧渐变竖条: Canvas 三段纵向渐变 (accent -> accent2 -> mauve)
        bar = tk.Canvas(card, width=S(3), bg=C["panel"], highlightthickness=0)
        bar.pack(side="left", fill="y")

        def paint_bar(event=None):
            h = bar.winfo_height()
            if h <= 1:
                # withdraw/未映射时高度可能为 1, 用请求值兜底以便预绘制
                h = S(40)
            if h <= 1:
                return
            bar.delete("all")
            w = S(3)
            third = max(h // 3, 1)
            for i, (c1, c2) in enumerate(((C["accent"], C["accent2"]),
                                          (C["accent2"], C["mauve"]),
                                          (C["mauve"], C["red"]))):
                steps = max(third, 2)
                for s in range(steps):
                    col = _lerp_hex(c1, c2, s / (steps - 1))
                    y0 = i * third + s * third / steps
                    y1 = i * third + (s + 1) * third / steps
                    bar.create_rectangle(0, y0, w, y1 + 1, fill=col, width=0)
            # 补齐底部可能的空隙
            bar.create_rectangle(0, 3 * third, w, h, fill=C["red"], width=0)

        bar.bind("<Configure>", paint_bar)
        paint_bar()
        inner = tk.Frame(card, bg=C["panel"])
        inner.pack(fill="x", padx=(12, 14), pady=12)
        if title:
            row = tk.Frame(inner, bg=C["panel"])
            row.pack(fill="x", anchor="w", pady=(0, 8))
            # 标题前的小方块装饰
            tk.Frame(row, bg=C["mauve"], width=8, height=8).pack(side="left", padx=(0, 7))
            tk.Label(row, text=title, bg=C["panel"], fg=C["fg"],
                     font=("Microsoft YaHei UI", 10, "bold")).pack(side="left")
        return inner

    def _make_tree(self, parent, columns, widths, empty_text, height=None):
        wrap = ttk.Frame(parent)
        kw = {} if height is None else {"height": height}
        tree = ttk.Treeview(wrap, columns=columns, show="headings",
                            selectmode="extended", **kw)
        for col, (head, width) in zip(columns, widths):
            tree.heading(col, text=head)
            tree.column(col, width=width, anchor="w")
        tree.tag_configure("even", background=C["row_even"])
        tree.tag_configure("odd", background=C["row_odd"])
        tree.tag_configure("ok", foreground=C["green"])
        tree.tag_configure("bad", foreground=C["red"])
        tree.tag_configure("warn", foreground=C["yellow"])
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        wrap.pack(fill="both", expand=True)
        empty = tk.Label(wrap, text=f"◌  {empty_text}", bg=C["row_odd"], fg="#565f89",
                         font=FONT_SM)
        empty.place(relx=0.5, rely=0.42, anchor="center")
        self._empty_labels[tree] = empty
        return tree

    def _sync_empty(self, tree):
        lbl = self._empty_labels.get(tree)
        if lbl is None:
            return
        if tree.get_children():
            lbl.place_forget()
        else:
            lbl.place(relx=0.5, rely=0.42, anchor="center")

    def fill_tree(self, tree, rows):
        tree.delete(*tree.get_children())
        for i, (k, v) in enumerate(rows):
            tree.insert("", "end", values=(k, v),
                        tags=("even" if i % 2 == 0 else "odd",))
        self._sync_empty(tree)

    def copy_tree(self, tree):
        lines = [f"{k}: {v}" for k, v in
                 (tree.item(i, "values") for i in tree.get_children())]
        if lines:
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))
            self.set_status("结果已复制到剪贴板", C["green"])

    def export_tree_csv(self, tree, default_name="results.csv"):
        if not tree.get_children():
            messagebox.showinfo("提示", "没有可导出的数据")
            return
        path = filedialog.asksaveasfilename(
            title="导出 CSV", defaultextension=".csv", initialfile=default_name,
            filetypes=[("CSV 文件", "*.csv")])
        if not path:
            return
        cols = list(tree["columns"])
        heads = [tree.heading(c)["text"] for c in cols]
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(heads)
                for i in tree.get_children():
                    w.writerow(list(tree.item(i, "values")))
            self.set_status(f"已导出 {len(tree.get_children())} 行 → {Path(path).name}", C["green"])
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))

    # ---------------- 历史记录
    def _update_hist_count(self):
        self.hist_lbl.configure(text=f"历史 {len(self.history)} 条")

    def add_history(self, kind: str, q: str, q2: str, summary: str):
        self.history.insert(0, {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "kind": kind, "q": q[:400], "q2": (q2 or "")[:200], "summary": summary[:200],
        })
        del self.history[HIST_KEEP:]
        self._update_hist_count()
        try:
            HIST_FILE.write_text(
                json.dumps(self.history, ensure_ascii=False, indent=None),
                encoding="utf-8")
        except Exception:
            pass
        if hasattr(self, "hist_tree"):
            self._refresh_history_tree()

    def _refresh_history_tree(self):
        t = self.hist_tree
        t.delete(*t.get_children())
        self._hist_view = []
        kw = ""
        if hasattr(self, "hist_filter"):
            kw = entry_value(self.hist_filter, "🔍 过滤关键词").lower()
        for i, h in enumerate(self.history):
            blob = f'{h.get("time", "")} {h.get("kind", "")} {h.get("q", "")} {h.get("summary", "")}'.lower()
            if kw and kw not in blob:
                continue
            self._hist_view.append(i)
            t.insert("", "end", values=(h.get("time", ""), h.get("kind", ""),
                                        h.get("q", ""), h.get("summary", "")),
                     tags=("even" if len(self._hist_view) % 2 == 1 else "odd",))
        if kw and not self._hist_view:
            t.insert("", "end", values=("", "无匹配", kw, ""),
                     tags=("odd",))
        self._sync_empty(t)

    # ============================================================ IP 查询
    def _build_ip_tab(self):
        card = self._card(self.tab_ip, "目标查询")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="IP / 域名", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.ip_entry = ttk.Entry(row, width=30)
        self.ip_entry.pack(side="left", padx=10)
        add_placeholder(self.ip_entry, PH_IP)
        ttk.Button(row, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.ip_tree, "ip_lookup.csv"))\
            .pack(side="right", padx=(6, 0))
        ttk.Button(row, text="复制", command=lambda: self.copy_tree(self.ip_tree))\
            .pack(side="right", padx=6)
        self.btn_maps = ttk.Button(row, text="🗺 打开地图", command=self.open_maps,
                                   state="disabled")
        self.btn_maps.pack(side="right", padx=6)
        ttk.Button(row, text="🔍 查询", style="Accent.TButton", command=self.do_ip_query)\
            .pack(side="right", padx=6)
        ttk.Button(row, text="清空", command=lambda: self.fill_tree(self.ip_tree, []))\
            .pack(side="right", padx=6)
        self.ip_entry.bind("<Return>", lambda e: self.do_ip_query())

        self.ip_tree = self._make_tree(self.tab_ip, ("field", "value"),
                                       (("字段", 160), ("值", 660)),
                                       "暂无数据 — 输入 IP 或留空后点击「查询」")
        self.ip_tree.bind("<Double-1>", self._open_tree_url)
        self.ip_tree.bind("<Button-3>",
                          lambda e: self._tree_menu(e, self.ip_tree, open_url_col=1))
        ToolTip(self.btn_maps, "在 Google 地图打开查询到的位置")

    def _open_tree_url(self, event):
        tree = event.widget
        sel = tree.selection()
        if sel:
            val = str(tree.item(sel[0], "values")[1])
            if val.startswith("http"):
                webbrowser.open(val)

    def open_maps(self):
        if self.last_maps_url:
            webbrowser.open(self.last_maps_url)

    def do_ip_query(self):
        ip = entry_value(self.ip_entry, PH_IP)
        self.set_status("正在查询 IP …", C["yellow"])
        self.btn_maps.configure(state="disabled")
        self.last_maps_url = None

        def work():
            target = ip
            if not target:
                try:
                    own = query_own_ip()
                    self.q.put(("ip_result", own, None, None))
                    target = own
                except Exception as exc:
                    self.q.put(("ip_error", f"获取本机 IP 失败: {exc}"))
                    return
            rows, maps, err = query_ip(target)
            self.q.put(("ip_result", target, rows, maps, err))

        threading.Thread(target=work, daemon=True).start()

    # ============================================================ 号码查询
    def _build_phone_tab(self):
        card = self._card(self.tab_phone, "号码分析")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="号码", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.ph_entry = ttk.Entry(row, width=28)
        self.ph_entry.pack(side="left", padx=10)
        add_placeholder(self.ph_entry, PH_PHONE)
        tk.Label(row, text="默认区号", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM).pack(side="left")
        self.ph_region = ttk.Combobox(
            row, values=["CN", "HK", "TW", "US", "IN", "ID", "GB", "JP", "KR", "RU"],
            width=5, state="readonly")
        self.ph_region.set("CN")
        self.ph_region.pack(side="left", padx=8)
        ttk.Button(row, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.phone_tree, "phone.csv"))\
            .pack(side="right", padx=(6, 0))
        ttk.Button(row, text="复制", command=lambda: self.copy_tree(self.phone_tree))\
            .pack(side="right", padx=6)
        ttk.Button(row, text="🔍 查询", style="Accent.TButton", command=self.do_phone_query)\
            .pack(side="right", padx=6)
        ttk.Button(row, text="清空", command=lambda: self.fill_tree(self.phone_tree, []))\
            .pack(side="right", padx=6)
        self.ph_entry.bind("<Return>", lambda e: self.do_phone_query())

        # 归属地库状态提示 (双库)
        db_hint = ttk.Label(self.tab_phone, text="", style="Dim.TLabel")
        db_hint.pack(anchor="w", pady=(0, 4))
        hint_parts = []
        try:
            xe = get_xe_db()
            hint_parts.append(f"📚 XEngine {xe.version} · {xe.count:,} 条 (主库)")
        except FileNotFoundError:
            hint_parts.append("⚠ XEngine 库缺失")
        except Exception as exc:
            hint_parts.append(f"⚠ XEngine 加载失败: {exc}")
        try:
            cn = get_cn_db()
            hint_parts.append(f"📖 ls0f 2023-12 · {cn.count:,} 条 (补邮编)")
        except FileNotFoundError:
            hint_parts.append("⚠ ls0f 库缺失")
        except Exception as exc:
            hint_parts.append(f"⚠ ls0f 加载失败: {exc}")
        db_hint.configure(text="  ·  ".join(hint_parts))

        self.phone_tree = self._make_tree(self.tab_phone, ("field", "value"),
                                          (("字段", 180), ("值", 640)),
                                          "暂无数据 — 输入号码后点击「查询」")
        self.phone_tree.bind("<Button-3>",
                             lambda e: self._tree_menu(e, self.phone_tree, open_url_col=1))

    def do_phone_query(self):
        text = entry_value(self.ph_entry, PH_PHONE)
        region = self.ph_region.get()
        self.set_status("正在分析号码 …", C["yellow"])

        def work():
            rows, err = analyze_phone(text, region)
            self.q.put(("phone_result", text, region, rows, err))

        threading.Thread(target=work, daemon=True).start()

    # ============================================================ 用户名查询
    def _build_username_tab(self):
        card = self._card(self.tab_user, "平台扫描")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="用户名", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.user_entry = ttk.Entry(row, width=28)
        self.user_entry.pack(side="left", padx=10)
        add_placeholder(self.user_entry, PH_USER)
        self.user_progress_lbl = tk.Label(row, text=f"0 / {len(SOCIAL_SITES)}",
                                          bg=C["panel"], fg=C["dim"], font=FONT_MONO)
        self.user_progress_lbl.pack(side="right", padx=(10, 0))
        self.user_progress = ttk.Progressbar(row, length=140, mode="determinate")
        self.user_progress.pack(side="right", padx=8)
        self.btn_user_go = ttk.Button(row, text="▶ 开始检测", style="Accent.TButton",
                                      command=self.do_username_query)
        self.btn_user_go.pack(side="right", padx=6)
        self.user_entry.bind("<Return>", lambda e: self.do_username_query())
        ToolTip(self.btn_user_go, f"并发检测 {len(SOCIAL_SITES)} 个平台的同名账号")

        row2 = tk.Frame(self.tab_user, bg=C["bg"])
        row2.pack(fill="x", pady=(0, 8))
        ttk.Button(row2, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.user_tree, "username.csv"))\
            .pack(side="right")
        self.user_tree = self._make_tree(
            self.tab_user, ("site", "status", "url"),
            (("平台", 150), ("状态", 250), ("主页 URL", 420)),
            "暂无数据 — 输入用户名后点击「开始检测」")
        self.user_tree.bind("<Double-1>", self._open_user_url)
        self.user_tree.bind("<Button-3>",
                            lambda e: self._tree_menu(e, self.user_tree, open_url_col=2))

    def _open_user_url(self, _event):
        sel = self.user_tree.selection()
        if sel:
            url = str(self.user_tree.item(sel[0], "values")[2])
            if url.startswith("http"):
                webbrowser.open(url)

    def do_username_query(self):
        username = entry_value(self.user_entry, PH_USER)
        if not username:
            messagebox.showinfo("提示", "请输入用户名")
            return
        self.user_tree.delete(*self.user_tree.get_children())
        self._sync_empty(self.user_tree)
        total = len(SOCIAL_SITES)
        self.user_progress.configure(maximum=total, value=0)
        self.user_progress_lbl.configure(text=f"0 / {total}")
        self.btn_user_go.configure(state="disabled")
        self.set_status(f"正在检测 “{username}” …", C["yellow"])

        def put(msg):
            self.q.put(("user",) + msg)

        def work():
            check_username(username, put)

        threading.Thread(target=work, daemon=True).start()

    # ============================================================ 邮箱情报
    def _build_email_tab(self):
        card = self._card(self.tab_email, "邮箱情报 (被动)")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="邮箱地址", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.email_entry = ttk.Entry(row, width=36)
        self.email_entry.pack(side="left", padx=10)
        add_placeholder(self.email_entry, PH_EMAIL)
        ttk.Button(row, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.email_tree, "email.csv"))\
            .pack(side="right", padx=(6, 0))
        ttk.Button(row, text="复制", command=lambda: self.copy_tree(self.email_tree))\
            .pack(side="right", padx=6)
        ttk.Button(row, text="✉ 分析", style="Accent.TButton", command=self.do_email_query)\
            .pack(side="right", padx=6)
        ttk.Button(row, text="清空", command=lambda: self.fill_tree(self.email_tree, []))\
            .pack(side="right", padx=6)
        self.email_entry.bind("<Return>", lambda e: self.do_email_query())
        ttk.Label(self.tab_email,
                  text="格式校验 / 提供商识别 / 一次性邮箱检测 / MX 记录 / Gravatar 指纹 — 全部公开数据源",
                  style="Dim.TLabel").pack(anchor="w", pady=(0, 6))
        self.email_tree = self._make_tree(self.tab_email, ("field", "value"),
                                          (("字段", 160), ("值", 660)),
                                          "暂无数据 — 输入邮箱后点击「分析」")
        self.email_tree.bind("<Button-3>",
                             lambda e: self._tree_menu(e, self.email_tree, open_url_col=1))

    def do_email_query(self):
        email = entry_value(self.email_entry, PH_EMAIL)
        if not email:
            messagebox.showinfo("提示", "请输入邮箱地址")
            return
        self.set_status("正在分析邮箱 …", C["yellow"])

        def work():
            rows, err = email_intel(email)
            self.q.put(("email_result", email, rows, err))

        threading.Thread(target=work, daemon=True).start()

    # ============================================================ 域名情报 (内嵌 DNS/WHOIS/子域名)
    def _build_domain_tab(self):
        # 顶部: 域名输入 + 主操作
        card = self._card(self.tab_domain, "域名情报")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="域名", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=8, anchor="e").pack(side="left")
        self.domain_entry = ttk.Entry(row, width=32)
        self.domain_entry.pack(side="left", padx=10)
        add_placeholder(self.domain_entry, PH_DOMAIN)
        ttk.Button(row, text="🔍 综合查询", style="Accent.TButton",
                   command=self.do_domain_all).pack(side="right")
        self.domain_entry.bind("<Return>", lambda e: self.do_domain_all())

        # 内嵌子标签: DNS / RDAP / 子域名
        self.dns_nb = ttk.Notebook(self.tab_domain)
        self.dns_nb.pack(fill="both", expand=True, pady=(10, 0))
        self.tab_dns = ttk.Frame(self.dns_nb, padding=10)
        self.tab_rdap = ttk.Frame(self.dns_nb, padding=10)
        self.tab_sub = ttk.Frame(self.dns_nb, padding=10)
        self.dns_nb.add(self.tab_dns, text="  DNS 记录  ")
        self.dns_nb.add(self.tab_rdap, text="  RDAP / 注册信息  ")
        self.dns_nb.add(self.tab_sub, text="  子域名 (crt.sh)  ")

        # --- DNS 子页
        r = tk.Frame(self.tab_dns, bg=C["bg"])
        r.pack(fill="x", pady=(0, 8))
        ttk.Label(r, text="记录类型:").pack(side="left")
        self.dns_type = ttk.Combobox(
            r, values=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"],
            width=6, state="readonly")
        self.dns_type.set("A")
        self.dns_type.pack(side="left", padx=8)
        ttk.Button(r, text="查询 DNS", style="Accent.TButton",
                   command=self.do_dns_query).pack(side="right")
        ttk.Button(r, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.dns_tree, "dns.csv"))\
            .pack(side="right", padx=6)
        self.dns_tree = self._make_tree(
            self.tab_dns, ("section", "type", "data"),
            (("来源", 90), ("类型", 70), ("数据", 620)),
            "暂无数据 — 填入域名后点「综合查询」或「查询 DNS」")

        # --- RDAP 子页
        r2 = tk.Frame(self.tab_rdap, bg=C["bg"])
        r2.pack(fill="x", pady=(0, 8))
        ttk.Button(r2, text="查询 RDAP", style="Accent.TButton",
                   command=self.do_rdap_query).pack(side="right")
        ttk.Button(r2, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.rdap_tree, "rdap.csv"))\
            .pack(side="right", padx=6)
        ttk.Label(r2, text="注册局公开数据: 注册商 / 到期时间 / Nameservers / 联系实体",
                  style="Dim.TLabel").pack(side="left")
        self.rdap_tree = self._make_tree(
            self.tab_rdap, ("field", "value"),
            (("字段", 180), ("值", 620)),
            "暂无数据 — 填入域名后查询")
        self.rdap_tree.bind("<Button-3>",
                            lambda e: self._tree_menu(e, self.rdap_tree, open_url_col=1))

        # --- 子域名子页
        r3 = tk.Frame(self.tab_sub, bg=C["bg"])
        r3.pack(fill="x", pady=(0, 8))
        self.crtsh_progress_lbl = tk.Label(r3, text="", bg=C["bg"], fg=C["dim"],
                                           font=FONT_MONO)
        self.crtsh_progress_lbl.pack(side="right", padx=(10, 0))
        ttk.Button(r3, text="枚举子域名", style="Accent.TButton",
                   command=self.do_crtsh_query).pack(side="right")
        ttk.Button(r3, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.crtsh_tree, "subdomains.csv"))\
            .pack(side="right", padx=6)
        ttk.Label(r3, text="证书透明度日志 (crt.sh) — 被动数据源, 可能较慢",
                  style="Dim.TLabel").pack(side="left")
        self.crtsh_tree = self._make_tree(
            self.tab_sub, ("name", "issuer", "not_before"),
            (("子域名", 340), ("签发者", 260), ("生效时间", 140)),
            "暂无数据 — 填入域名后点「枚举子域名」")
        self.crtsh_tree.bind("<Double-1>", self._open_subdomain)

    def _domain_value(self) -> str:
        return entry_value(self.domain_entry, PH_DOMAIN)

    def do_domain_all(self):
        d = self._domain_value()
        if not d:
            messagebox.showinfo("提示", "请输入域名")
            return
        self.dns_nb.select(self.tab_dns)
        self.do_dns_query()
        self.do_rdap_query()

    def do_dns_query(self):
        d = self._domain_value()
        rtype = self.dns_type.get()
        if not d:
            messagebox.showinfo("提示", "请输入域名")
            return
        self.set_status(f"DNS {rtype} 查询 {d} …", C["yellow"])

        def work():
            rows, err = dns_lookup(d, rtype)
            self.q.put(("dns_result", d, rtype, rows, err))

        threading.Thread(target=work, daemon=True).start()

    def do_rdap_query(self):
        d = self._domain_value()
        if not d:
            messagebox.showinfo("提示", "请输入域名")
            return
        self.set_status("RDAP 查询中 …", C["yellow"])

        def work():
            rows, err = rdap_lookup(d)
            self.q.put(("rdap_result", d, rows, err))

        threading.Thread(target=work, daemon=True).start()

    def do_crtsh_query(self):
        d = self._domain_value()
        if not d:
            messagebox.showinfo("提示", "请输入域名")
            return
        self.crtsh_tree.delete(*self.crtsh_tree.get_children())
        self._sync_empty(self.crtsh_tree)
        self.crtsh_progress_lbl.configure(text="查询中 …")
        self.set_status(f"crt.sh 枚举 {d} 子域名 …", C["yellow"])

        def put(msg):
            self.q.put(("crtsh",) + msg)

        def work():
            crtsh_lookup(d, put)

        threading.Thread(target=work, daemon=True).start()

    def _open_subdomain(self, _event):
        sel = self.crtsh_tree.selection()
        if sel:
            name = str(self.crtsh_tree.item(sel[0], "values")[0])
            if name:
                webbrowser.open(f"https://{name}")

    # ============================================================ Web 指纹
    def _build_web_tab(self):
        card = self._card(self.tab_web, "目标站点")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="URL / 域名", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.web_entry = ttk.Entry(row, width=44)
        self.web_entry.pack(side="left", padx=10)
        add_placeholder(self.web_entry, PH_WEB)
        ttk.Button(row, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.web_tree, "web_fingerprint.csv"))\
            .pack(side="right", padx=(6, 0))
        ttk.Button(row, text="复制", command=lambda: self.copy_tree(self.web_tree))\
            .pack(side="right", padx=6)
        self.btn_web_open = ttk.Button(row, text="↗ 打开网站", command=self._open_web_site,
                                       state="disabled")
        self.btn_web_open.pack(side="right", padx=6)
        ttk.Button(row, text="🌐 分析", style="Accent.TButton", command=self.do_web_query)\
            .pack(side="right", padx=6)
        ttk.Button(row, text="清空", command=lambda: self.fill_tree(self.web_tree, []))\
            .pack(side="right", padx=6)
        self.web_entry.bind("<Return>", lambda e: self.do_web_query())
        ttk.Label(self.tab_web, text="被动指纹: HTTP 头 / 重定向链 / 页面标题 / TLS 证书 / 技术栈线索",
                  style="Dim.TLabel").pack(anchor="w", pady=(0, 6))

        self.web_tree = self._make_tree(self.tab_web, ("field", "value"),
                                        (("字段", 160), ("值", 660)),
                                        "暂无数据 — 输入域名或 URL 后点击「分析」")
        self.web_tree.bind("<Button-3>",
                           lambda e: self._tree_menu(e, self.web_tree, open_url_col=1))

    def do_web_query(self):
        url = entry_value(self.web_entry, PH_WEB)
        if not url:
            messagebox.showinfo("提示", "请输入 URL 或域名")
            return
        self.set_status("正在分析站点 …", C["yellow"])
        self.btn_web_open.configure(state="disabled")

        def work():
            rows, err = web_fingerprint(url)
            self.q.put(("web_result", url, rows, err))

        threading.Thread(target=work, daemon=True).start()

    def _open_web_site(self):
        if self.last_web_url:
            webbrowser.open(self.last_web_url)

    # ============================================================ 批量 IP
    def _build_batch_tab(self):
        card = self._card(self.tab_batch, "批量查询 (每行一个 IP / 域名, 上限 200)")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        self.batch_text = tk.Text(row, height=7, wrap="none",
                                  bg=C["field"], fg=C["fg"], insertbackground=C["fg"],
                                  relief="flat", font=FONT_MONO,
                                  highlightthickness=1, highlightbackground=C["line"])
        self.batch_text.pack(side="left", fill="both", expand=True)
        add_placeholder_text(self.batch_text, PH_BATCH)
        btns = tk.Frame(row, bg=C["panel"])
        btns.pack(side="right", padx=(10, 0), fill="y")
        self.btn_batch_go = ttk.Button(btns, text="⚡ 开始批量", style="Accent.TButton",
                                       command=self.do_batch_query)
        self.btn_batch_go.pack(pady=(0, 6))
        ttk.Button(btns, text="示例", command=self._batch_sample).pack(pady=(0, 6))
        ttk.Button(btns, text="清空输入",
                   command=lambda: (self.batch_text.delete("1.0", "end"),
                                    add_placeholder_text(self.batch_text, PH_BATCH))).pack()

        row2 = tk.Frame(self.tab_batch, bg=C["bg"])
        row2.pack(fill="x", pady=(0, 8))
        self.batch_progress_lbl = tk.Label(row2, text="0 / 0", bg=C["bg"], fg=C["dim"],
                                           font=FONT_MONO)
        self.batch_progress_lbl.pack(side="right", padx=(10, 0))
        self.batch_progress = ttk.Progressbar(row2, length=160, mode="determinate")
        self.batch_progress.pack(side="right", padx=8)
        ttk.Button(row2, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.batch_tree, "batch_ip.csv"))\
            .pack(side="right")
        self.batch_tree = self._make_tree(
            self.tab_batch, ("ip", "country", "city", "isp", "org", "lat", "lon", "status"),
            (("目标", 130), ("国家", 110), ("城市", 110), ("ISP", 170), ("机构", 150),
             ("纬度", 80), ("经度", 80), ("状态", 90)),
            "暂无数据 — 左侧粘贴 IP 列表后点击「开始批量」")
        self.batch_tree.bind("<Button-3>",
                             lambda e: self._tree_menu(e, self.batch_tree))

    def _batch_sample(self):
        self.batch_text.delete("1.0", "end")
        self.batch_text.insert("1.0", "8.8.8.8\n1.1.1.1\n208.67.222.222\n9.9.9.9")
        self.batch_text.configure(fg=C["fg"])

    def do_batch_query(self):
        raw = text_value(self.batch_text, PH_BATCH)
        items = [x.strip() for x in raw.splitlines() if x.strip()][:200]
        if not items:
            messagebox.showinfo("提示", "请输入至少一个 IP / 域名")
            return
        self.batch_tree.delete(*self.batch_tree.get_children())
        self._sync_empty(self.batch_tree)
        self.batch_progress.configure(maximum=len(items), value=0)
        self.batch_progress_lbl.configure(text=f"0 / {len(items)}")
        self.btn_batch_go.configure(state="disabled")
        self.set_status(f"批量查询 {len(items)} 个目标 …", C["yellow"])
        state = {"ok": 0, "n": 0}
        lock = threading.Lock()

        def one(item):
            r = batch_lookup_one(item)
            with lock:
                state["n"] += 1
                if r[7] == "OK":
                    state["ok"] += 1
                n = state["n"]
            self.q.put(("batch_row", r, n, len(items)))

        def work():
            with ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(one, items))
            self.q.put(("batch_done", len(items), state["ok"]))

        threading.Thread(target=work, daemon=True).start()

    # ============================================================ 网络工具
    def _make_scrollable(self, parent):
        """把 parent 变成可纵向滚动的容器, 返回内容 Frame。"""
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=C["bg"])
        win = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfigure(win, width=event.width)

        inner.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        # 鼠标滚轮
        def _on_wheel(event):
            if event.delta:
                canvas.yview_scroll(-1 * (event.delta // 120), "units")
        canvas.bind_all("<MouseWheel>", _on_wheel, add="+")
        return inner

    def _build_net_tab(self):
        holder = self._make_scrollable(self.tab_net)
        # 端口检测
        card = self._card(holder, "TCP 端口检测")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="目标主机", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.p_host = ttk.Entry(row, width=26)
        self.p_host.pack(side="left", padx=10)
        add_placeholder(self.p_host, PH_PHOST)
        tk.Label(row, text="端口", bg=C["panel"], fg=C["dim"], font=FONT_SM)\
            .pack(side="left", padx=(6, 0))
        self.p_ports = ttk.Entry(row, width=40)
        self.p_ports.pack(side="left", padx=8)
        self.p_ports.insert(0, PRESET_PORTS)
        self.btn_port_go = ttk.Button(row, text="▶ 检测", style="Accent.TButton",
                                      command=self.do_port_scan)
        self.btn_port_go.pack(side="right")
        ttk.Button(row, text="常用端口",
                   command=lambda: (self.p_ports.delete(0, "end"),
                                    self.p_ports.insert(0, PRESET_PORTS))).pack(side="right", padx=6)
        self.p_host.bind("<Return>", lambda e: self.do_port_scan())
        self.p_ports.bind("<Return>", lambda e: self.do_port_scan())

        row2 = tk.Frame(holder, bg=C["bg"])
        row2.pack(fill="x", pady=(0, 8))
        self.port_progress_lbl = tk.Label(row2, text="0 / 0", bg=C["bg"], fg=C["dim"],
                                          font=FONT_MONO)
        self.port_progress_lbl.pack(side="right", padx=(10, 0))
        self.port_progress = ttk.Progressbar(row2, length=160, mode="determinate")
        self.port_progress.pack(side="right", padx=8)
        ttk.Button(row2, text="复制开放端口", command=self._copy_open_ports)\
            .pack(side="right", padx=6)
        ttk.Button(row2, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.port_tree, "ports.csv"))\
            .pack(side="right")
        self.port_tree = self._make_tree(
            holder, ("port", "state", "time"),
            (("端口", 120), ("状态", 220), ("耗时", 120)),
            "暂无数据 — 输入主机与端口后点击「检测」")
        self.port_tree.bind("<Button-3>",
                            lambda e: self._tree_menu(e, self.port_tree))

        # 本机网络信息
        card2 = self._card(holder, "本机网络信息")
        row3 = tk.Frame(card2, bg=C["panel"])
        row3.pack(fill="x")
        ttk.Button(row3, text="🔄 刷新", style="Accent.TButton",
                   command=self.do_local_info).pack(side="right")
        ttk.Button(row3, text="复制", command=lambda: self.copy_tree(self.local_tree))\
            .pack(side="right", padx=6)
        ttk.Label(row3, text="公网 IP 与归属 / 本机 IPv4 / MAC 地址", background=C["panel"],
                  foreground=C["dim"], font=FONT_SM).pack(side="left")
        self.local_tree = self._make_tree(
            holder, ("field", "value"),
            (("项目", 140), ("值", 640)),
            "点击「刷新」读取本机网络信息", height=5)

        # Ping / 路由追踪 / 反向解析
        card3 = self._card(holder, "连通性诊断")
        row4 = tk.Frame(card3, bg=C["panel"])
        row4.pack(fill="x")
        tk.Label(row4, text="目标", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.diag_host = ttk.Entry(row4, width=28)
        self.diag_host.pack(side="left", padx=10)
        add_placeholder(self.diag_host, "8.8.8.8 或 example.com")
        ttk.Button(row4, text="PTR 反查", command=self.do_ptr_query).pack(side="right")
        ttk.Button(row4, text="路由追踪", command=self.do_traceroute).pack(side="right", padx=6)
        ttk.Button(row4, text="Ping", style="Accent.TButton",
                   command=self.do_ping).pack(side="right", padx=6)
        self.diag_host.bind("<Return>", lambda e: self.do_ping())
        self.diag_tree = self._make_tree(
            holder, ("field", "value"),
            (("项目", 140), ("值", 640)),
            "暂无数据 — 输入 IP 或域名后选择诊断方式", height=5)
        self.diag_tree.bind("<Button-3>",
                            lambda e: self._tree_menu(e, self.diag_tree, open_url_col=1))

        # 哈希识别
        card4 = self._card(holder, "哈希类型识别 (纯本地)")
        row5 = tk.Frame(card4, bg=C["panel"])
        row5.pack(fill="x")
        tk.Label(row5, text="哈希值", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=10, anchor="e").pack(side="left")
        self.hash_entry = ttk.Entry(row5, width=52)
        self.hash_entry.pack(side="left", padx=10)
        add_placeholder(self.hash_entry, PH_HASH)
        ttk.Button(row5, text="复制", command=lambda: self.copy_tree(self.hash_tree))\
            .pack(side="right", padx=6)
        ttk.Button(row5, text="识别", style="Accent.TButton",
                   command=self.do_hash_id).pack(side="right", padx=6)
        ttk.Button(row5, text="示例 MD5",
                   command=lambda: (self.hash_entry.delete(0, "end"),
                                    self.hash_entry.insert(0, "5d41402abc4b2a76b9719d911017c592"),
                                    self.hash_entry.configure(foreground=C["fg"]))).pack(side="right", padx=6)
        self.hash_entry.bind("<Return>", lambda e: self.do_hash_id())
        self.hash_tree = self._make_tree(
            holder, ("field", "value"),
            (("项目", 140), ("值", 640)),
            "暂无数据 — 粘贴哈希后点「识别」", height=4)
        self.hash_tree.bind("<Button-3>",
                            lambda e: self._tree_menu(e, self.hash_tree, open_url_col=1))

    def do_port_scan(self):
        host = entry_value(self.p_host, PH_PHOST)
        ports = parse_ports(self.p_ports.get())
        if not host:
            messagebox.showinfo("提示", "请输入目标主机")
            return
        if not ports:
            messagebox.showinfo("提示", "请输入有效的端口列表")
            return
        self.port_tree.delete(*self.port_tree.get_children())
        self._sync_empty(self.port_tree)
        self.port_progress.configure(maximum=len(ports), value=0)
        self.port_progress_lbl.configure(text=f"0 / {len(ports)}")
        self.btn_port_go.configure(state="disabled")
        self.set_status(f"检测 {host} 的 {len(ports)} 个端口 …", C["yellow"])
        state = {"n": 0, "open": 0}
        lock = threading.Lock()

        def one(port):
            p, is_open, secs = check_port(host, port)
            with lock:
                state["n"] += 1
                if is_open:
                    state["open"] += 1
                n = state["n"]
            self.q.put(("port_row", p, is_open, secs, n, len(ports)))

        def work():
            with ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(one, ports))
            self.q.put(("port_done", host, len(ports), state["open"]))

        threading.Thread(target=work, daemon=True).start()

    def do_local_info(self):
        self.set_status("读取本机网络信息 …", C["yellow"])

        def work():
            rows, err = local_network_info()
            self.q.put(("local_result", rows, err))

        threading.Thread(target=work, daemon=True).start()

    def _copy_open_ports(self):
        open_ports = []
        for i in self.port_tree.get_children():
            vals = self.port_tree.item(i, "values")
            if len(vals) >= 2 and "开放" in str(vals[1]):
                open_ports.append(str(vals[0]))
        if open_ports:
            self.clipboard_clear()
            self.clipboard_append(",".join(open_ports))
            self.set_status(f"已复制 {len(open_ports)} 个开放端口", C["green"])
        else:
            self.set_status("没有开放的端口可复制", C["dim"])

    def _diag_target(self) -> str:
        return entry_value(self.diag_host, "8.8.8.8 或 example.com")

    def do_ping(self):
        host = self._diag_target()
        if not host:
            messagebox.showinfo("提示", "请输入目标主机")
            return
        self.set_status(f"Ping {host} …", C["yellow"])

        def work():
            rows, err = ping_host(host)
            self.q.put(("diag_result", f"Ping {host}", rows, err))

        threading.Thread(target=work, daemon=True).start()

    def do_traceroute(self):
        host = self._diag_target()
        if not host:
            messagebox.showinfo("提示", "请输入目标主机")
            return
        self.set_status(f"路由追踪 {host} … (最多 20 跳)", C["yellow"])

        def work():
            rows, err = traceroute_host(host)
            self.q.put(("diag_result", f"Traceroute {host}", rows, err))

        threading.Thread(target=work, daemon=True).start()

    def do_ptr_query(self):
        host = self._diag_target()
        if not host:
            messagebox.showinfo("提示", "请输入 IP 地址")
            return
        self.set_status(f"PTR 反查 {host} …", C["yellow"])

        def work():
            rows, err = reverse_dns(host)
            self.q.put(("diag_result", f"PTR {host}", rows, err))

        threading.Thread(target=work, daemon=True).start()

    def do_hash_id(self):
        value = entry_value(self.hash_entry, PH_HASH)
        if not value:
            messagebox.showinfo("提示", "请输入哈希值")
            return
        rows, err = identify_hash(value)
        if err:
            self.fill_tree(self.hash_tree, [("错误", err)])
            self.set_status("识别失败", C["red"])
        else:
            self.fill_tree(self.hash_tree, rows)
            self.set_status("哈希识别完成", C["green"])

    # ============================================================ Seeker 控制台
    def _build_seeker_tab(self):
        card = self._card(self.tab_seeker, "服务配置")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="模板", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM, width=8, anchor="e").pack(side="left")
        names = [t["name"] for t in self.templates] if self.templates else ["(未找到 Seeker)"]
        self.tpl_combo = ttk.Combobox(row, values=names, state="readonly", width=20)
        self.tpl_combo.set(names[0])
        self.tpl_combo.pack(side="left", padx=10)
        self.tpl_combo.bind("<<ComboboxSelected>>", lambda e: self._rebuild_params())
        tk.Label(row, text="端口", bg=C["panel"], fg=C["dim"],
                 font=FONT_SM).pack(side="left", padx=(12, 0))
        self.port_entry = ttk.Entry(row, width=7)
        self.port_entry.insert(0, "8080")
        self.port_entry.pack(side="left", padx=8)
        self.var_debug = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="本地调试 (不强制 HTTPS)", variable=self.var_debug)\
            .pack(side="left", padx=10)
        self.btn_stop = ttk.Button(row, text="■ 停止", style="Danger.TButton",
                                   command=self.seeker_stop, state="disabled")
        self.btn_stop.pack(side="right")
        self.btn_start = ttk.Button(row, text="▶ 启动", style="Accent.TButton",
                                    command=self.seeker_start)
        self.btn_start.pack(side="right", padx=8)
        ToolTip(self.btn_start, "启动 Seeker 服务 (PHP 内置服务器)")
        ToolTip(self.btn_stop, "强制停止服务及其 PHP 子进程")

        self.param_card = self._card(self.tab_seeker, "模板参数")
        self.param_title = tk.Label(self.param_card, text="", bg=C["panel"],
                                    fg=C["dim"], font=FONT_SM)
        self.param_title.pack(anchor="w")
        self.param_body = tk.Frame(self.param_card, bg=C["panel"])
        self.param_body.pack(fill="x", pady=(6, 0))
        self._rebuild_params()

        adv = ttk.Frame(self.tab_seeker)
        adv.pack(fill="x", pady=(0, 10))
        ttk.Label(adv, text="Webhook (可选):").pack(side="left")
        self.wh_entry = ttk.Entry(adv, width=30)
        self.wh_entry.pack(side="left", padx=8)
        ttk.Button(adv, text="📂 结果目录", command=self.open_db_dir).pack(side="right")
        ttk.Button(adv, text="🌐 打开本机页面", command=self.open_local_page)\
            .pack(side="right", padx=6)
        ttk.Button(adv, text="清空日志",
                   command=lambda: self._append_seek_logs([], clear=True)).pack(side="right", padx=6)

        if shutil.which("php") is None:
            ttk.Label(self.tab_seeker, text="⚠ 未找到 PHP, Seeker 无法启动 (安装 PHP 并刷新 PATH)",
                      style="Warn.TLabel").pack(anchor="w", pady=(0, 6))
        elif not self.templates:
            ttk.Label(self.tab_seeker, text="⚠ 未找到 seeker 目录或 templates.json",
                      style="Warn.TLabel").pack(anchor="w", pady=(0, 6))

        # 捕获结果
        cap_card = self._card(self.tab_seeker, "最近捕获 (db/results.csv)")
        cap_bar = tk.Frame(cap_card, bg=C["panel"])
        cap_bar.pack(fill="x", pady=(0, 6))
        ttk.Button(cap_bar, text="🔄 刷新", command=self._load_seeker_results).pack(side="right")
        ttk.Label(cap_bar, text="新数据落盘后自动刷新 · 最多显示最近 50 条",
                  background=C["panel"], foreground="#5b6078", font=FONT_SM).pack(side="left")
        cap_wrap = ttk.Frame(cap_card)
        cap_wrap.pack(fill="x")
        self.cap_tree = ttk.Treeview(cap_wrap, columns=("c1", "c2", "c3", "c4", "c5", "c6"),
                                     show="headings", height=5)
        for col, head, w in (("c1", "OS", 90), ("c2", "浏览器", 140), ("c3", "公网IP", 120),
                             ("c4", "国家/城市", 130), ("c5", "经纬度", 150), ("c6", "ISP", 180)):
            self.cap_tree.heading(col, text=head)
            self.cap_tree.column(col, width=w, anchor="w")
        self.cap_tree.tag_configure("even", background=C["row_even"])
        self.cap_tree.tag_configure("odd", background=C["row_odd"])
        vsb = ttk.Scrollbar(cap_wrap, orient="vertical", command=self.cap_tree.yview)
        self.cap_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.cap_tree.pack(fill="x")
        self.cap_tree.bind("<Double-1>", self._open_cap_url)

        # 日志
        log_card = self._card(self.tab_seeker, "输出日志")
        self.seeker_log = scrolledtext.ScrolledText(
            log_card, wrap="word", font=FONT_MONO, height=11,
            bg="#0f0f18", fg=C["fg"], insertbackground=C["fg"],
            relief="flat", highlightthickness=1, highlightbackground=C["line"])
        self.seeker_log.pack(fill="both", expand=True)
        self.seeker_log.tag_configure("time", foreground=C["dim"])
        self.seeker_log.tag_configure("ok", foreground=C["green"])
        self.seeker_log.tag_configure("err", foreground=C["red"])
        self.seeker_log.tag_configure("info", foreground=C["accent"])
        self.seeker_log.configure(state="disabled")
        self._load_seeker_results()

    def _load_seeker_results(self):
        """读取 seeker/db/results.csv 展示最近捕获。"""
        path = SEEKER_DIR / "db" / "results.csv"
        rows = []
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    rows = list(csv.reader(f))[-50:]
            except Exception:
                rows = []
        self.cap_tree.delete(*self.cap_tree.get_children())
        for i, r in enumerate(rows):
            r = (r + [""] * 21)[:21]
            self.cap_tree.insert("", "end", values=(r[7] or "-", r[1] or "-",
                                                    r[8] or "-",
                                                    f"{r[10]} {r[12]}".strip() or "-",
                                                    f"{r[15]}, {r[16]}".strip(", ") or "-",
                                                    r[14] or "-"),
                                 tags=("even" if i % 2 == 0 else "odd",))

    def _open_cap_url(self, _event):
        sel = self.cap_tree.selection()
        if sel:
            ip = str(self.cap_tree.item(sel[0], "values")[2])
            if ip and ip != "-":
                webbrowser.open(f"https://www.google.com/maps/search/{ip}")

    def _rebuild_params(self):
        for w in self.param_body.winfo_children():
            w.destroy()
        self.param_entries.clear()
        if not self.templates:
            return
        idx = self.tpl_combo.current()
        tpl = self.templates[idx]
        keys = PARAM_SPEC.get(tpl["dir_name"], [])
        self.param_title.configure(text=f"{tpl['name']} · " + (
            "无需参数, 直接启动" if not keys else f"共 {len(keys)} 项"))
        if not keys:
            return
        self.param_body.columnconfigure(1, weight=1)
        r = 0
        for key in keys:
            tk.Label(self.param_body, text=PARAM_LABELS.get(key, key), bg=C["panel"],
                     fg=C["dim"], font=FONT_SM, width=18, anchor="e").grid(
                row=r, column=0, sticky="e", pady=4, padx=(0, 10))
            ent = ttk.Entry(self.param_body)
            ent.grid(row=r, column=1, sticky="ew", pady=4)
            self.param_entries[key] = ent
            if key == "IMAGE":
                ttk.Button(self.param_body, text="浏览…",
                           command=lambda e=ent: self.browse_image(e)).grid(
                    row=r, column=2, padx=(8, 0), pady=4)
            hint = PARAM_HINTS.get(key)
            if hint:
                r += 1
                tk.Label(self.param_body, text="↳ " + hint, bg=C["panel"], fg="#5b6078",
                         font=FONT_SM).grid(row=r, column=1, sticky="w", pady=(0, 4))
            r += 1

    def browse_image(self, ent: tk.Entry):
        path = filedialog.askopenfilename(
            title="选择图片",
            filetypes=[("图片", "*.png *.jpg *.jpeg *.gif *.webp *.svg"), ("所有文件", "*.*")])
        if path:
            ent.delete(0, "end")
            ent.insert(0, path)

    def _append_seek_logs(self, batch, clear=False):
        tv = self.seeker_log
        tv.configure(state="normal")
        if clear:
            tv.delete("1.0", "end")
        if batch:
            at_bottom = tv.yview()[1] >= 0.99
            ts = datetime.now().strftime("%H:%M:%S")
            for text, tag in batch:
                tv.insert("end", f"[{ts}] ", ("time",))
                tv.insert("end", text + "\n", tag or ())
            count = int(float(tv.index("end-1c")))
            if count > LOG_KEEP:
                tv.delete("1.0", f"{count - LOG_TRIM_TO}.0")
            if at_bottom:
                tv.see("end")
        tv.configure(state="disabled")

    def seeker_log_write(self, text, tag=None):
        self._append_seek_logs([(text, tag)])

    def open_local_page(self):
        port = self.port_entry.get().strip() or "8080"
        webbrowser.open(f"http://127.0.0.1:{port}/index.html")

    def open_db_dir(self):
        db = SEEKER_DIR / "db"
        db.mkdir(exist_ok=True)
        if os.name == "nt":
            os.startfile(db)
        else:
            subprocess.Popen(["xdg-open", str(db)])

    def seeker_start(self):
        if self.seeker_running:
            return
        if shutil.which("php") is None:
            messagebox.showerror("缺少 PHP", "未找到 php 命令, 无法启动 Seeker 服务。")
            return
        if not self.templates:
            messagebox.showerror("缺少 Seeker", "未找到 seeker 目录。")
            return
        idx = self.tpl_combo.current()
        tpl = self.templates[idx]
        keys = PARAM_SPEC.get(tpl["dir_name"], [])
        params = {k: e.get().strip() for k, e in self.param_entries.items()}
        missing = [k for k in keys if not params.get(k)]
        if missing:
            names = ", ".join(PARAM_LABELS.get(k, k) for k in missing)
            messagebox.showwarning("参数不完整", f"请先填写: {names}")
            return
        img = params.get("IMAGE", "")
        if img and not img.lower().startswith(("http://", "https://")):
            if not Path(img).is_file():
                messagebox.showwarning("图片无效", f"本地文件不存在:\n{img}")
                return
        port = self.port_entry.get().strip() or "8080"
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            messagebox.showwarning("端口无效", "端口应为 1-65535 的数字")
            return

        env = os.environ.copy()
        env["TEMPLATE"] = str(idx)
        env["PORT"] = str(port)
        env["DEBUG_HTTP"] = "1" if self.var_debug.get() else "0"
        env["TELEGRAM"] = ""
        env["WEBHOOK"] = self.wh_entry.get().strip()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        for k, v in params.items():
            env[k] = v

        self.seeker_log_write(f"启动: 模板 {tpl['name']} (#{idx}), 端口 {port}, "
                              f"调试={'开' if self.var_debug.get() else '关'}", "info")
        if self.var_debug.get():
            self.seeker_log_write(f"本机测试地址: http://127.0.0.1:{port}/index.html", "info")
        try:
            self.seeker_proc = subprocess.Popen(
                [sys.executable, "seeker.py", "-p", str(port)],
                cwd=str(SEEKER_DIR), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
                errors="replace", bufsize=1, creationflags=CREATE_NO_WINDOW)
        except Exception as exc:
            self.seeker_log_write(f"启动失败: {exc}", "err")
            return
        self.seeker_running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.set_status(f"Seeker 运行中 — {tpl['name']} @ {port}", C["green"])
        threading.Thread(target=self._seeker_reader, daemon=True).start()

    def _seeker_reader(self):
        proc = self.seeker_proc
        try:
            for raw in proc.stdout:
                line = strip_ansi(raw.rstrip("\n")).strip()
                if not line:
                    continue
                tag = "err" if ("[-]" in line or "Exception" in line or "✘" in line) else \
                      ("ok" if ("✔" in line or "[+]" in line) else None)
                self.q.put(("seeker_log", line, tag))
        finally:
            self.q.put(("seeker_exit", proc.wait()))

    def seeker_stop(self):
        proc = self.seeker_proc
        if proc and proc.poll() is None:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                                   capture_output=True, creationflags=CREATE_NO_WINDOW)
                else:
                    proc.terminate()
            except Exception as exc:
                self.seeker_log_write(f"停止失败: {exc}", "err")
        pid_file = SEEKER_DIR / "pid"
        try:
            if pid_file.exists():
                pid_file.unlink()
        except OSError:
            pass
        self.seeker_log_write("已停止 Seeker", "err")

    # ============================================================ 历史记录
    def _build_history_tab(self):
        card = self._card(self.tab_hist, "查询历史 (双击回填到对应页面)")
        row = tk.Frame(card, bg=C["panel"])
        row.pack(fill="x")
        ttk.Button(row, text="🗑 删除选中", command=self._hist_delete).pack(side="right")
        ttk.Button(row, text="清空全部", command=self._hist_clear).pack(side="right", padx=6)
        ttk.Button(row, text="导出 CSV",
                   command=lambda: self.export_tree_csv(self.hist_tree, "history.csv"))\
            .pack(side="right", padx=6)
        self.hist_filter = ttk.Entry(row, width=22)
        self.hist_filter.pack(side="right", padx=8)
        add_placeholder(self.hist_filter, "🔍 过滤关键词")
        self.hist_filter.bind("<KeyRelease>", lambda e: self._refresh_history_tree())
        ttk.Label(row, text=f"最多保留 {HIST_KEEP} 条 · {HIST_FILE.name}",
                  background=C["panel"], foreground="#5b6078", font=FONT_SM).pack(side="left")
        self.hist_tree = self._make_tree(
            self.tab_hist, ("time", "kind", "q", "summary"),
            (("时间", 150), ("类型", 80), ("查询", 300), ("摘要", 300)),
            "暂无历史 — 各页面的查询会自动记录到这里")
        self.hist_tree.bind("<Double-1>", self._hist_rerun)
        self.hist_tree.bind("<Button-3>", self._hist_menu)
        self._hist_view: list[int] = []

    def _hist_menu(self, event):
        iid = self.hist_tree.identify_row(event.y)
        if iid and iid not in self.hist_tree.selection():
            self.hist_tree.selection_set(iid)
        if not self.hist_tree.selection():
            return
        menu = tk.Menu(self, tearoff=0, bg=C["panel2"], fg=C["fg"],
                       activebackground=C["accent"], activeforeground="#0d0d15",
                       borderwidth=0, font=FONT_SM)
        menu.add_command(label="⤴ 回填重查", command=lambda: self._hist_rerun(None))
        menu.add_command(label="🗑 删除选中", command=self._hist_delete)
        menu.tk_popup(event.x_root, event.y_root)

    def _hist_delete(self):
        sel = self.hist_tree.selection()
        if not sel:
            return
        view_idx = sorted((self.hist_tree.index(i) for i in sel), reverse=True)
        real = sorted((self._hist_view[i] for i in view_idx
                       if i < len(self._hist_view)), reverse=True)
        for i in real:
            del self.history[i]
        self._save_history_file()
        self._refresh_history_tree()
        self._update_hist_count()

    def _hist_clear(self):
        if not self.history:
            return
        if messagebox.askyesno("确认", "清空全部历史记录?"):
            self.history.clear()
            self._save_history_file()
            self._refresh_history_tree()
            self._update_hist_count()

    def _save_history_file(self):
        try:
            HIST_FILE.write_text(
                json.dumps(self.history, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def _hist_rerun(self, _event):
        sel = self.hist_tree.selection()
        if not sel:
            return
        view_i = self.hist_tree.index(sel[0])
        if view_i >= len(self._hist_view):
            return
        h = self.history[self._hist_view[view_i]]
        kind, q, q2 = h.get("kind", ""), h.get("q", ""), h.get("q2", "")
        if kind == "IP":
            self.nb.select(self.tab_ip)
            self.ip_entry.delete(0, "end")
            self.ip_entry.insert(0, q)
            self.ip_entry.configure(foreground=C["fg"])
            self.do_ip_query()
        elif kind == "号码":
            self.nb.select(self.tab_phone)
            self.ph_entry.delete(0, "end")
            self.ph_entry.insert(0, q)
            self.ph_entry.configure(foreground=C["fg"])
            if q2:
                self.ph_region.set(q2)
            self.do_phone_query()
        elif kind == "用户名":
            self.nb.select(self.tab_user)
            self.user_entry.delete(0, "end")
            self.user_entry.insert(0, q)
            self.user_entry.configure(foreground=C["fg"])
            self.do_username_query()
        elif kind == "Web":
            self.nb.select(self.tab_web)
            self.web_entry.delete(0, "end")
            self.web_entry.insert(0, q)
            self.web_entry.configure(foreground=C["fg"])
            self.do_web_query()
        elif kind == "批量":
            self.nb.select(self.tab_batch)
            self.batch_text.delete("1.0", "end")
            self.batch_text.insert("1.0", q)
            self.batch_text.configure(fg=C["fg"])
        elif kind == "端口":
            self.nb.select(self.tab_net)
            parts = q.split("|", 1)
            self.p_host.delete(0, "end")
            self.p_host.insert(0, parts[0])
            self.p_host.configure(foreground=C["fg"])
            if len(parts) > 1:
                self.p_ports.delete(0, "end")
                self.p_ports.insert(0, parts[1])
            self.do_port_scan()
        elif kind == "邮箱":
            self.nb.select(self.tab_email)
            self.email_entry.delete(0, "end")
            self.email_entry.insert(0, q)
            self.email_entry.configure(foreground=C["fg"])
            self.do_email_query()
        elif kind == "DNS":
            self.nb.select(self.tab_domain)
            self.dns_nb.select(self.tab_dns)
            self.domain_entry.delete(0, "end")
            self.domain_entry.insert(0, q)
            self.domain_entry.configure(foreground=C["fg"])
            if q2:
                self.dns_type.set(q2)
            self.do_dns_query()
        elif kind == "RDAP":
            self.nb.select(self.tab_domain)
            self.dns_nb.select(self.tab_rdap)
            self.domain_entry.delete(0, "end")
            self.domain_entry.insert(0, q)
            self.domain_entry.configure(foreground=C["fg"])
            self.do_rdap_query()
        elif kind == "子域名":
            self.nb.select(self.tab_domain)
            self.dns_nb.select(self.tab_sub)
            self.domain_entry.delete(0, "end")
            self.domain_entry.insert(0, q)
            self.domain_entry.configure(foreground=C["fg"])
            self.do_crtsh_query()

    # ============================================================ 关于
    def _build_about_tab(self):
        card = self._card(self.tab_about, "环境信息")
        seeker_ver = "?"
        try:
            seeker_ver = json.loads((SEEKER_DIR / "metadata.json").read_text()).get("version", "?")
        except Exception:
            pass
        info = [
            ("GhostTrack 目录", str(GHOST_DIR)),
            ("Seeker 目录", str(SEEKER_DIR)),
            ("Seeker 版本", seeker_ver),
            ("PHP", shutil.which("php") or "未安装"),
            ("Python", sys.version.split()[0]),
            ("历史文件", str(HIST_FILE)),
        ]
        # 国内归属地库状态 (双库)
        try:
            xe = get_xe_db()
            info.append(("XEngine 号码库", f"{xe.version} · {xe.count:,} 条 · libxengine (主库)"))
        except FileNotFoundError:
            info.append(("XEngine 号码库", f"未找到 ({XENGINE_DAT.name})"))
        except Exception as exc:
            info.append(("XEngine 号码库", f"加载失败: {exc}"))
        try:
            db = get_cn_db()
            info.append(("ls0f 归属地库", f"{db.count:,} 条号段 · ls0f/phone (补邮编)"))
        except FileNotFoundError:
            info.append(("ls0f 归属地库", f"未找到 phone.dat ({PHONE_DAT.parent})"))
        except Exception as exc:
            info.append(("ls0f 归属地库", f"加载失败: {exc}"))
        for k, v in info:
            row = tk.Frame(card, bg=C["panel"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=k, bg=C["panel"], fg=C["accent"], font=FONT_SM,
                     width=16, anchor="e").pack(side="left", padx=(0, 12))
            tk.Label(row, text=str(v), bg=C["panel"], fg=C["fg"], font=FONT_SM,
                     anchor="w").pack(side="left")

        card2 = self._card(self.tab_about, "功能一览")
        notes = [
            "🌍 IP 查询 · 📞 号码归属 · 🔍 用户名检测 (24 平台并发) — 与 GhostTR.py 相同数据源",
            "✉ 邮箱情报 — 格式/提供商/一次性邮箱库/MX 记录/Gravatar 指纹",
            "📞 号码归属 — 双库融合: XEngine 51.7万号段 (2025-08, 覆盖最全) + ls0f 49.9万 (补邮编); 支持携转/虚拟/广电识别",
            "🏷 域名情报 — DNS 记录 (dns.google) · RDAP 注册信息 · crt.sh 子域名枚举",
            "🌐 Web 指纹 — HTTP 头 / 重定向链 / 页面标题 / TLS 证书 / 技术栈线索 (被动)",
            "⚡ 批量 IP — 最多 200 个目标并发查询, 支持 CSV 导出",
            "🛠 网络工具 — TCP 端口检测 · 本机网络信息 · Ping / 路由追踪 / PTR 反查 · 哈希类型识别",
            "🎯 Seeker 控制台 — 模板参数 / 启停 / 日志 / 捕获结果内嵌查看",
            "🕘 历史 — 所有查询自动持久化, 双击即可回填重查 (支持关键词过滤)",
        ]
        for n in notes:
            tk.Label(card2, text=n, bg=C["panel"], fg=C["dim"], font=FONT_SM,
                     wraplength=800, justify="left").pack(anchor="w", pady=3)

        tk.Label(self.tab_about,
                 text="⚠ 仅用于合法授权的安全测试与学习研究; 未经同意收集他人位置或号码信息可能违法。",
                 bg=C["bg"], fg=C["yellow"], font=FONT_SM,
                 wraplength=800, justify="left").pack(anchor="w", pady=(6, 0))

    # ============================================================ 消息泵
    def _poll_queue(self):
        log_batch = []
        user_rows, batch_rows, port_rows = [], [], []
        user_prog = batch_prog = port_prog = None
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "ip_result":
                    if len(msg) == 5:
                        _, ip, rows, maps, err = msg
                        if err:
                            self.fill_tree(self.ip_tree, [("错误", err)])
                            self.set_status("查询失败", C["red"])
                        else:
                            self.fill_tree(self.ip_tree, rows)
                            self.last_maps_url = maps
                            self.btn_maps.configure(state="normal" if maps else "disabled")
                            self.set_status(f"IP {ip} 查询完成 · {len(rows)} 项", C["green"])
                            d = {k: v for k, v in rows}
                            self.add_history("IP", ip, "",
                                             f'{d.get("国家", "")} {d.get("城市", "")} · {d.get("ISP", "")}')
                    else:
                        self.fill_tree(self.ip_tree, [("本机公网 IP", msg[1])])
                elif kind == "ip_error":
                    self.fill_tree(self.ip_tree, [("错误", msg[1])])
                    self.set_status("查询失败", C["red"])
                elif kind == "phone_result":
                    _, qnum, qregion, rows, err = msg
                    if err:
                        self.fill_tree(self.phone_tree, [("错误", err)])
                        self.set_status("号码解析失败", C["red"])
                    else:
                        self.fill_tree(self.phone_tree, rows)
                        self.set_status("号码分析完成", C["green"])
                        d = {k: v for k, v in rows}
                        self.add_history("号码", qnum, qregion,
                                         f'{d.get("运营商", "")} · {d.get("归属位置", "")}')
                elif kind == "user":
                    sub = msg[1]
                    if sub == "row":
                        _, _, name, status, url, ok = msg
                        user_rows.append((name, status, url, ok))
                    elif sub == "progress":
                        _, _, n, total = msg
                        user_prog = (n, total)
                    elif sub == "done":
                        self.btn_user_go.configure(state="normal")
                        ok_n = sum(1 for i in self.user_tree.get_children()
                                   if "ok" in self.user_tree.item(i, "tags"))
                        self.set_status(f"检测完成 · {ok_n} 个平台可能注册", C["green"])
                        uname = entry_value(self.user_entry, PH_USER)
                        if uname:
                            self.add_history("用户名", uname, "",
                                             f"{len(SOCIAL_SITES)} 平台 · {ok_n} 可能存在")
                elif kind == "web_result":
                    _, url, rows, err = msg
                    if err:
                        self.fill_tree(self.web_tree, [("错误", err)])
                        self.set_status("分析失败", C["red"])
                        self.last_web_url = None
                        self.btn_web_open.configure(state="disabled")
                    else:
                        self.fill_tree(self.web_tree, rows)
                        self.set_status("Web 指纹分析完成", C["green"])
                        d = {k: v for k, v in rows}
                        final = str(d.get("最终 URL", "") or url)
                        self.last_web_url = final if final.startswith("http") else None
                        self.btn_web_open.configure(
                            state="normal" if self.last_web_url else "disabled")
                        self.add_history("Web", url, "",
                                         f'{d.get("HTTP 状态", "")} · {d.get("Server", "")} · {str(d.get("页面标题", ""))[:40]}')
                elif kind == "batch_row":
                    _, r, n, total = msg
                    batch_rows.append((r, n))
                    batch_prog = (n, total)
                elif kind == "batch_done":
                    _, total, ok = msg
                    self.btn_batch_go.configure(state="normal")
                    self.set_status(f"批量完成 · {ok}/{total} 成功", C["green"])
                    raw = text_value(self.batch_text, PH_BATCH)
                    if raw.strip():
                        self.add_history("批量", "\n".join(
                            x.strip() for x in raw.splitlines() if x.strip())[:400],
                            "", f"{total} 个目标 · 成功 {ok}")
                elif kind == "port_row":
                    _, p, is_open, secs, n, total = msg
                    port_rows.append((p, is_open, secs, n))
                    port_prog = (n, total)
                elif kind == "port_done":
                    _, host, total, open_n = msg
                    self.btn_port_go.configure(state="normal")
                    self.set_status(f"端口检测完成 · {open_n}/{total} 开放", C["green"])
                    ports_str = self.p_ports.get().strip()[:200]
                    self.add_history("端口", f"{host}|{ports_str}", "",
                                     f"{total} 端口 · 开放 {open_n}")
                elif kind == "local_result":
                    rows, err = msg
                    self.fill_tree(self.local_tree, rows)
                    self.set_status("本机网络信息已更新" if not err else err, C["green"])
                elif kind == "email_result":
                    _, email, rows, err = msg
                    if err:
                        self.fill_tree(self.email_tree, [("错误", err)])
                        self.set_status("邮箱分析失败", C["red"])
                    else:
                        self.fill_tree(self.email_tree, rows)
                        self.set_status("邮箱分析完成", C["green"])
                        d = {k: v for k, v in rows}
                        self.add_history("邮箱", email, "",
                                         f'{d.get("邮箱提供商", "")} · 一次性: {d.get("一次性邮箱", "")}')
                elif kind == "dns_result":
                    _, domain, rtype, rows, err = msg
                    if err:
                        self.fill_tree(self.dns_tree, [("错误", "", err)])
                        self.set_status("DNS 查询失败", C["red"])
                    else:
                        self.fill_tree(self.dns_tree, rows)
                        self.set_status(f"DNS {rtype} {domain} · {len(rows)} 条", C["green"])
                        self.add_history("DNS", domain, rtype, f"{rtype} · {len(rows)} 条记录")
                elif kind == "rdap_result":
                    _, domain, rows, err = msg
                    if err:
                        self.fill_tree(self.rdap_tree, [("错误", err)])
                        self.set_status("RDAP 查询失败", C["red"])
                    else:
                        self.fill_tree(self.rdap_tree, rows)
                        self.set_status(f"RDAP {domain} · {len(rows)} 项", C["green"])
                        d = {k: v for k, v in rows}
                        self.add_history("RDAP", domain, "",
                                         f'到期: {d.get("到期时间", "—")}')
                elif kind == "crtsh":
                    sub = msg[1]
                    if sub == "crtsh_row":
                        _, _, name, issuer, nb = msg
                        n = len(self.crtsh_tree.get_children())
                        self.crtsh_tree.insert("", "end", values=(name, issuer, nb),
                                               tags=("even" if n % 2 == 0 else "odd",))
                        self._sync_empty(self.crtsh_tree)
                        self.crtsh_progress_lbl.configure(text=f"{n} 条 …")
                    elif sub == "crtsh_done":
                        _, _, count, err = msg
                        if err:
                            self.set_status(f"crt.sh: {err}", C["red"])
                            self.crtsh_progress_lbl.configure(text=err)
                        else:
                            self.set_status(f"子域名枚举完成 · {count} 个", C["green"])
                            self.crtsh_progress_lbl.configure(text=f"共 {count} 个")
                            d = self._domain_value()
                            if d and count:
                                self.add_history("子域名", d, "", f"{count} 个子域名")
                elif kind == "diag_result":
                    _, title, rows, err = msg
                    if err:
                        self.fill_tree(self.diag_tree, [("错误", err)])
                        self.set_status(err, C["red"])
                    else:
                        self.fill_tree(self.diag_tree, rows)
                        self.set_status(f"{title} 完成 · {len(rows)} 行", C["green"])
                elif kind == "seeker_log":
                    log_batch.append((msg[1], msg[2]))
                elif kind == "seeker_exit":
                    self.seeker_running = False
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    log_batch.append((f"Seeker 进程已退出 (code={msg[1]})", "err"))
                    self.set_status("Seeker 已停止", C["dim"])
        except queue.Empty:
            pass
        # 批量插入行 (每轮一次, 避免逐行 O(n²))
        if user_rows:
            base = len(self.user_tree.get_children())
            for i, (name, status, url, ok) in enumerate(user_rows):
                par = "even" if (base + i) % 2 == 0 else "odd"
                st = "ok" if ok else ("warn" if "超时" in status else "bad")
                self.user_tree.insert("", "end", values=(name, status, url),
                                      tags=(par, st))
            self._sync_empty(self.user_tree)
        if user_prog:
            self.user_progress.configure(maximum=user_prog[1], value=user_prog[0])
            self.user_progress_lbl.configure(text=f"{user_prog[0]} / {user_prog[1]}")
        if batch_rows:
            for r, n in batch_rows:
                self.batch_tree.insert("", "end", values=r,
                                       tags=("even" if n % 2 == 1 else "odd",
                                             "ok" if r[7] == "OK" else "bad"))
            self._sync_empty(self.batch_tree)
        if batch_prog:
            self.batch_progress.configure(maximum=batch_prog[1], value=batch_prog[0])
            self.batch_progress_lbl.configure(text=f"{batch_prog[0]} / {batch_prog[1]}")
        if port_rows:
            for p, is_open, secs, n in port_rows:
                state_txt = "✅ 开放" if is_open else "○ 关闭"
                self.port_tree.insert("", "end", values=(p, state_txt, f"{secs*1000:.0f} ms"),
                                      tags=("even" if n % 2 == 1 else "odd",
                                            "ok" if is_open else "odd"))
            self._sync_empty(self.port_tree)
        if port_prog:
            self.port_progress.configure(maximum=port_prog[1], value=port_prog[0])
            self.port_progress_lbl.configure(text=f"{port_prog[0]} / {port_prog[1]}")
        if log_batch:
            self._append_seek_logs(log_batch)
            if any("Data Saved" in t for t, _ in log_batch):
                self._load_seeker_results()
        self.after(100, self._poll_queue)

    def on_close(self):
        self._save_geometry()
        self.seeker_stop()
        self.destroy()

    # ---------------- 右键菜单
    def _tree_menu(self, event, tree, open_url_col=None, extra=None):
        """通用结果表右键菜单: 复制行/复制全部/导出 CSV/[打开链接]。"""
        iid = tree.identify_row(event.y)
        if iid and iid not in tree.selection():
            tree.selection_set(iid)
        if not tree.get_children():
            return
        menu = tk.Menu(self, tearoff=0, bg=C["panel2"], fg=C["fg"],
                       activebackground=C["accent"], activeforeground="#0d0d15",
                       borderwidth=0, font=FONT_SM)
        sel = tree.selection()

        def copy_sel():
            lines = [" | ".join(map(str, tree.item(i, "values"))) for i in sel]
            if lines:
                self.clipboard_clear()
                self.clipboard_append("\n".join(lines))
                self.set_status(f"已复制 {len(lines)} 行", C["green"])

        if sel:
            menu.add_command(label=f"复制选中 ({len(sel)})", command=copy_sel)
            if open_url_col is not None and sel:
                vals = tree.item(sel[0], "values")
                if open_url_col < len(vals) and str(vals[open_url_col]).startswith("http"):
                    url = str(vals[open_url_col])
                    menu.add_command(label="🌐 在浏览器打开",
                                     command=lambda: webbrowser.open(url))
        menu.add_command(label="复制全部", command=lambda: self.copy_tree(tree))
        menu.add_command(label="导出 CSV…",
                         command=lambda: self.export_tree_csv(tree))
        if extra:
            menu.add_separator()
            for label, cmd in extra:
                menu.add_command(label=label, command=cmd)
        menu.tk_popup(event.x_root, event.y_root)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
