# Region Guard · 地区与防风控全景监测台

一个纯本地、零第三方依赖的 macOS + 浏览器全景地区一致性和防泄漏监测工具，弥补在线 IP 检测网站只查单一数据源、看不到本机系统指纹与历史残留的短板。

## 核心检测维度

1. **10 大 GeoIP 库 + WHOIS/BGP/rDNS 交叉验真**
   - 同步探测 Cloudflare (`claude.ai/cdn-cgi/trace`)、IPinfo、ip-api、ipwho.is、ip2location.io、api.ip.sb、db-ip、geojs.io、ifconfig.co、RIPE MaxMind。
   - 自动识别 IPXO 广播租赁段 (`geofeed`)、WHOIS 隐私马甲实体、跨国注册国家冲突、商业共享 ASN、无 rDNS 以及代理信誉库标记 (`blackbox` / `proxycheck`)。
2. **全域名分流、DNS/EDNS、IPv6、UDP/STUN 与断流风险**
   - 并行检测 `claude.ai`、`api.anthropic.com`、`a-api.anthropic.com`、`console.anthropic.com`、`platform.claude.com`、`code.claude.com`、`challenges.cloudflare.com` 是否同口同区，并与国内探测点 (`myip.ipip.net` / `ip.3322.net`) 对比。
   - 实测 `edns.ip-api.com` DNS 出口、IPv6 直连测试、UDP STUN 穿透测试、本机时钟偏差，以及物理网卡第二默认路由/Scoped 私网 DNS（休眠唤醒瞬断风险）。
3. **Clash / VPN 配置脱敏体检**
   - 仅读取代理模式 (`global`/`rule`)、DNS 上游（识别 `system` 隐患）、直连监听端口与组名；不读取节点密码、UUID 或订阅 URL。
4. **macOS 系统环境与指纹**
   - 核查系统级 `GlobalPreferences Country`、用户级 `AppleLocale` / `AppleLanguages` / `NSLinguisticDataAssetsRequested`、`/etc/localtime` 与开机时间对比（是否改过时区但未重启）、自动时区开关、定位服务 (`locationd` / `geod`)、中文电脑名/主机名、激活输入法与 Wi-Fi 802.11d 国家码。
5. **Claude & Safari 指纹残留（纯只读元数据）**
   - 检查 Claude Desktop 本地路径、`ant-did`、Cookies 追踪键名（绝不读取 Cookie 明文）、日志中的 `region_blocked` / `account_banned` 计数、钥匙串凭证存在性、Claude Code CLI 与 Safari 痕迹。
6. **浏览器实时实测 + 持续防断流监控**
   - 实时读取浏览器真实发送的 HTTP `Accept-Language`、`navigator.languages`、JS 时区与出口 IP 时区对齐、WebRTC ICE Candidate 实测防泄漏、Geolocation 权限状态，并支持 15s / 30s / 60s 持续轮询监控 IP 跳变与断流告警。

## 启动与停止

```zsh
# 启动（默认监听 127.0.0.1:8765）
/Users/anson/Documents/1/region-guard/start.sh

# 指定端口启动
/Users/anson/Documents/1/region-guard/start.sh 8899
```

启动后在浏览器访问：`http://127.0.0.1:8765`

停止服务：在终端按 `Ctrl + C`，或执行 `pkill -f "region-guard/server.py"`。
