"""Read-only Hako runtime evidence, projected to public hosts and transport types."""
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time

PAYMENT_HOSTS = ("js.stripe.com", "api.stripe.com", "m.stripe.network")
TRANSPORTS = {"vless", "vmess", "trojan", "shadowsocks", "shadowsocksr", "socks5",
              "http", "wireguard", "hysteria", "hysteria2", "tuic", "snell", "ssh"}


class HakoRuntime:
    """No controller discovery, tokens, writes, remote sockets or raw state in reports."""
    def __init__(self, home=None):
        self.path = (Path(home) if home is not None else Path.home()) / (
            "Library/Group Containers/group.com.hako.network/clash.sock")

    def read(self, endpoint):
        if endpoint not in {"/configs", "/proxies", "/connections"}:
            raise ValueError("unsupported read-only endpoint")
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("untrusted local controller socket")
        connection = http.client.HTTPConnection("localhost", timeout=.5)
        try:
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.sock.settimeout(.5)
            connection.sock.connect(str(self.path))
            connection.request("GET", endpoint)
            response = connection.getresponse()
            data = response.read(4 * 1024 * 1024 + 1)
            if response.status != 200 or len(data) > 4 * 1024 * 1024:
                raise OSError("local controller response unavailable or too large")
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ValueError("invalid local controller response")
            return result
        finally:
            connection.close()

    def tun_state(self):
        try:
            tun = self.read("/configs").get("tun") or {}
            return {"enabled": tun.get("enable") is True,
                    "packet_flow": tun.get("device") == "clash-packet-flow"}
        except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
            return {}


def classify_payment_route(connection, proxies):
    """Never copy node names, addresses, process paths or identifiers to the result."""
    chains = connection.get("chains") or []
    if not isinstance(chains, list) or not chains or not all(isinstance(n, str) for n in chains):
        return {"status": "INFO", "label": "未取得支付路由证据"}
    types = [str((proxies.get(name) or {}).get("type", "")).lower() for name in chains]
    if any(name.upper() == "DIRECT" for name in chains) or "direct" in types:
        return {"status": "FAIL", "label": "支付接口正在直连", "transport": "DIRECT"}
    if any(name.upper().startswith("REJECT") for name in chains) or any(t.startswith("reject") for t in types):
        return {"status": "FAIL", "label": "支付接口被规则阻断", "transport": "REJECT"}
    transports = sorted({t for t in types if t in TRANSPORTS})
    if transports:
        transport = "/".join(t.upper() for t in transports)
        return {"status": "PASS", "label": "实时路由：代理 " + transport,
                "transport": transport, "evidence": "live_connection"}
    return {"status": "INFO", "label": "路由类型未知，未确认代理接管"}


class PaymentRouteObserver:
    """Watch only new Stripe connections during this scan; stop after bounded sampling."""
    def __init__(self, runtime=None):
        self.runtime = runtime or HakoRuntime()
        self.routes = {}
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        try:
            self.proxies = self.runtime.read("/proxies").get("proxies") or {}
            self.existing_ids = {row.get("id") for row in
                                 self.runtime.read("/connections").get("connections", [])}
        except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
            return self
        self.thread = threading.Thread(target=self._watch, name="payment-route-audit", daemon=True)
        self.thread.start()
        return self

    def sample(self):
        for row in self.runtime.read("/connections").get("connections", []):
            host = (row.get("metadata") or {}).get("host", "")
            if host not in PAYMENT_HOSTS or not row.get("id") or row["id"] in self.existing_ids:
                continue
            result = classify_payment_route(row, self.proxies)
            previous = self.routes.get(host, {})
            # A subsequent successful request must not erase an observed bypass.
            if previous.get("status") != "FAIL":
                self.routes[host] = result

    def _watch(self):
        deadline = time.monotonic() + 12
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            try:
                self.sample()
            except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
                break
            if self.stop_event.wait(.12):
                break

    def finish(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(1)
        return dict(self.routes)


def payment_route_check(routes):
    rows = [routes.get(host, {"status": "INFO", "label": "本次未捕获实时连接"})
            for host in PAYMENT_HOSTS]
    failed = any(row["status"] == "FAIL" for row in rows)
    passed = sum(row["status"] == "PASS" for row in rows)
    return {"id": "payment_proxy_route", "title": "支付接口 VPN / 代理实时分流",
            "status": "FAIL" if failed else ("PASS" if passed == len(rows) else "INFO"),
            "severity": "high" if failed else "low",
            "observed": f"{passed}/{len(rows)} 已观察经代理" + ("；发现直连/阻断" if failed else ""),
            "detail": "；".join(host + "：" + row["label"] for host, row in zip(PAYMENT_HOSTS, rows)) +
                      "。仅为本次连接路由证据，不代表支付获批或各域名公网出口相同。",
            "fix_advice": "检查 Stripe 专用分流规则。" if failed else "", "fix_cmd": ""}
