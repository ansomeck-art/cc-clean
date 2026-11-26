# Region Guard · 地区与防风控全景监测台 (Windows / macOS)

一个纯本地、零第三方依赖的 **Windows + macOS + 浏览器** 全景地区一致性和防风控监测工具，严格绑定 `127.0.0.1`、纯只读且绝不读取/暴露任何密码、Token 或 Cookie 明文。

## 核心检测维度

1. **11 大 GeoIP 库 + WHOIS/RDAP/BGP/rDNS + 滥用信誉交叉验真**
   - 同步探测 Cloudflare (`claude.ai/cdn-cgi/trace` 含 `colo` 跨区 PoP 与 `WARP` 识别)、IPinfo、ip-api、**ipapi.is（机房/VPN/Proxy/Tor/滥用评分）**、ipwho.is、ip2location.io、api.ip.sb、db-ip、geojs.io、ifconfig.co、RIPE MaxMind。
   - 自动识别 IPXO 广播租赁段 (`geofeed`)、WHOIS 隐私马甲实体、跨国注册国家冲突、60+ 机房/VPS/机场商用共享 ASN、机房特征 rDNS、DNSBL 黑名单 (`Spamhaus` / `DroneBL` / `Barracuda` / `UCEPROTECT`)、Mullvad VPN 池与代理信誉库 (`blackbox` / `proxycheck`)。
2. **全域名分流、AI 组 vs 默认组双出口分裂、Fake-IP 分叉、DNS/EDNS、IPv6、UDP/STUN 与断流风险**
   - 并行检测 `claude.ai`、`api.anthropic.com`、`a-api.anthropic.com`、`console.anthropic.com`、`platform.claude.com`、`code.claude.com`、`releases.claude.com`、`sandbox.claudemcpcontent.com`、`challenges.cloudflare.com` 是否同口同区，并验证 `downloads.claude.ai`（后台高频轮询模型目录）、`www.claudeusercontent.com`、`mcp-proxy.anthropic.com`、`m.stripe.network` (Stripe Radar)、`statsig.anthropic.com`、`api.hcaptcha.com`、`claude.com`、`appleid.apple.com`、`accounts.google.com` 等关键接口。
   - **AI 专属组 vs 默认海外组双出口分裂检测（致命红线）**：比对 `claude.ai` 出口 IP 与 `ipinfo.io` / `ip-api.com` / `ifconfig.co` / `ipleak.net` 出口 IP，精准捕获 Rule 模式下“AI 走节点 A、Stripe/hCaptcha/OAuth 走节点 B”的双出口分裂。
   - **本地 DNS 污染、系统 DNS 缓存 (`displaydns`) 与 Fake-IP 分叉检测**：核查 `downloads.claude.ai`、`www.claudeusercontent.com`、`o1158394.ingest.us.sentry.io`、`m.stripe.network`、`statsig.anthropic.com`、`api.hcaptcha.com` 是否被 `fake-ip-filter` 或去广告规则误放行/劫持。
   - 实测 `edns.ip-api.com` DNS 出口、IPv6 直连测试、UDP STUN 穿透测试、本机时钟偏差、**Windows 默认路由 Metric 优先级与 IPv6 默认路由**，以及物理网卡备用默认路由/私网 DNS（休眠唤醒瞬断风险）。
3. **Clash / Mihomo / VPN 配置脱敏体检（Windows & macOS）**
   - 自动发现 Clash Verge Rev / Mihomo Party / Clash Party / FlClash / Clash Nyanpasu / Clash for Windows / macOS Clash 配置，检查代理模式 (`global`/`rule`)、DNS 上游 (`system`/国内 DNS)、`tun.auto-route` / `tun.strict-route` / `tun.auto-detect-interface`、`fake-ip-filter` 与 `DIRECT` 规则冲突、**`PROCESS-NAME` 子进程直连误伤 (`cowork-svc` / `node` / `ssh` / `git` / `curl`)**、**`REJECT` 硬拦遥测引发离线队列积压副作用**、Windows WinINET/WinHTTP 代理与 `ProxyOverride` 绕过列表；绝不读取节点密码、UUID 或订阅 URL。
4. **Windows & macOS 系统环境、官方遥测隐私开关与指纹**
   - **Windows**：GeoID 国家代码、显示语言/区域格式/非 Unicode 代码页/安装 SKU、时区 (`tzutil`) 与**改时区后是否已重启校验** (`TimeZoneInformation` vs 系统开机时间)、自动时区 (`tzautoupdate`)、定位服务 (`ConsentStore` + `lfsvc`)、计算机名与中文用户目录名、TSF 中文输入法、**Claude 开机自启抢跑代理 (Boot-Leak)**、Modern Standby (S0) 与快速启动、IPv4/IPv6 网卡国内 DNS、hosts 劫持与遥测黑洞副作用、MITM 抓包根证书、WSL2 提醒，以及 **Claude 官方遥测抑制环境变量 (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` / `DISABLE_TELEMETRY` / `DO_NOT_TRACK`) 与 GPO 策略状态**。
   - **macOS**：`GlobalPreferences Country`、`AppleLocale`/`AppleLanguages`/`NSLinguisticDataAssetsRequested`、`/etc/localtime` 与开机时间对比、自动时区、定位服务 (`locationd`/`geod`)、主机名/NetBIOS、输入法、Wi-Fi 802.11d、Power Nap、Claude 开机自启、MITM 根证书、官方遥测隐私环境变量与 MDM 策略状态。
5. **Claude 深度遥测产物 (`sentry/scope_v3.json` / `fcache`) & 浏览器全路径指纹残留（纯只读元数据）**
   - **第三方中转站 / 本地转发桥 / 套壳 Harness 检测（致命红线）**：核查 `ANTHROPIC_BASE_URL`（环境变量 / `.claude/settings*.json`）、`apiKeyHelper` 与 `cc-switch` / `claude-code-router` 等转发工具。
   - **Windows**：同时扫描传统 `%APPDATA%\Claude` **与官方 MSIX 虚拟化容器 `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\{Roaming,Local}\`** 及 `Claude-3p`/`Claude-Data`；深度解析 **`sentry\scope_v3.json`（捕获启动瞬间未登录即落盘的 `zh-CN` / `Asia/Shanghai` 环境快照与设备 UUID）**、**`sentry\queue` 离线积压包**、**`fcache`（解压 `CLF+Gzip` 核验残留 `orgUuid` 与实验分组）**；检测新版 **`cowork-svc.exe` 虚拟机后台服务**与 SSH/MCP 辅助进程；扫描 `ant-did`、`Network\Cookies`（WAL 感知 + 进程锁检测）、`Preferences`/`Local State`、`config.json`、`logs`（含 `Batch flush FAILED` / `Claude-Login-Ended-By` / `bad_device_id`）；扫描 Claude Code CLI（含 MSIX 内置 `Local\claude-cli-nodejs`）、Git 全局身份（脱敏）、Windows 凭据管理器 (`cmdkey /list`)、虚拟机 BIOS 与杀软 HTTPS 扫描进程，以及全浏览器（含 `claudeusercontent.com` / `claudemcpcontent.com` 沙箱域）的 Cookies、**IndexedDB**、**Network Persistent State**、**Chromium DIPS 追踪库**、History 域名、DoH 与代理扩展。
   - **macOS**：Desktop 10 类路径、`ant-did`、Cookies 追踪键、钥匙串全量脱敏检索、`~/Library` 12 子目录通配、Safari WebsiteData / ITP / DeviceIdHashSalts / Private Relay 与第三方浏览器扫描。
6. **浏览器实时指纹实测 + 后台防断流守护**
   - 浏览器直出 IPv4/IPv6 (`api6.ipify.org`) 泄漏检测与后端通道一致性对比。
   - HTTP `Accept-Language` 与 `navigator.language` 一致性、JS 时区防穿帮数学校验（含中文 `中国标准时间` 识别）、WebRTC ICE 实测、Geolocation 权限、深度 `Intl` (`Date`/`Number`/`Collator`/`RelativeTimeFormat`)、**`speechSynthesis.getVoices()` 隐藏中文系统语音泄漏检测**、**Canvas 中文字体指纹探测**、**Canvas/AudioContext 稳定性防随机加噪穿帮检测**、**WebGPU vs WebGL 交叉核验**、hCaptcha 多权限面板、自动化/Hook 篡改/WebGL 虚拟显卡/UA-CH 一致性检测。
   - 支持 15s / 30s / 60s 后台 Python 守护线程持续监控 IP 跳变与休眠唤醒断流。

## 快速启动

### Windows（双击或终端启动）

需要 **Python 3.9+**（标准库零依赖，无需 `pip install`）：

- **方式一（推荐）**：直接双击项目根目录的 `start.bat`（自动启动服务并打开浏览器 `http://127.0.0.1:8765`）。
- **方式二（PowerShell / 指定端口）**：
  ```powershell
  .\start.ps1
  .\start.ps1 -Port 8899
  ```
- **方式三（命令行直接运行）**：
  ```powershell
  py -3 server.py --host 127.0.0.1 --port 8765 --open
  ```

### 打包成 Windows 单文件便携版 `.exe`（拷贝到其他电脑免装 Python）

在已安装 Python 3.9+ 的 Windows 电脑上执行一次：

```powershell
.\build-windows-exe.ps1
```

构建完成后会生成单文件 `dist\RegionGuard.exe`（已内置全部 `static/` 前端资源）。直接将该 `.exe` 复制到其他 Windows 10/11 电脑双击运行即可自动启动监测台并打开浏览器，无需目标电脑安装 Python。

### 纯只读检测与打分规则

- 全程 **100% 纯只读**，不修改任何系统设置，不删除任何本地文件或缓存。
- 综合打分（0–100 分，含后端系统/网络 + 浏览器实时检测）：
  - 致命红线（真实 IP/DNS/IPv6/WebRTC 泄漏、黑名单、受限地区暴露）：**-30 分/项**
  - 高危 FAIL（目标国家/时区/语言冲突、未开 TUN、残留指纹）：**-15 分/项**
  - 高风险 WARN（改时区未重启、休眠断流风险、语音指纹泄漏等）：**-6 分/项**
  - 轻度 WARN（次要配置优化项）：**-2 分/项**

### macOS / Linux

```bash
# 默认监听 127.0.0.1:8765
./start.sh

# 指定端口启动
./start.sh 8899
```

启动后在浏览器访问：`http://127.0.0.1:8765`。停止服务请在终端按 `Ctrl + C`。
