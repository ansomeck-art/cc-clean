# Region Guard

本地地区、路由与浏览器环境检测工具。macOS 3.5.0 build 12 保留已授权的 Claude Desktop 进程保护：网络守护继续采用独立严格策略；文件保护仅在受检字段出现明确中国大陆标记时强退。缺少 Sentry culture、locale、timezone，核验中、格式未知或结果陈旧都只提示待观察，不凭这些文件未知状态强退。强退可能丢失未保存内容，恢复后不会自动重开 Claude。Windows 保留现有 CLI、只读审计和 EXE 打包入口。

3.5.0 新增后台持续连接观察：独立线程随后台监控启动和停止，不依赖网页或全面扫描。原生读取默认约 500ms，限定 PID 的 lsof 回退有效周期至少 2000ms，界面约每 1 秒显示缓存。两组分别报告当前 socket/匹配/未知、最近样本增量和本次监控历史累计；入站证据、控制器 DIRECT 选择与真实目的 IP 的内核路由分别显示。只有已确认的公网目的路由绕过 TUN 正向事件可交由既有身份保护处理；普通未知与 DIRECT 本身不触发。短连接、已结束连接和采样间隙仍可能读不到，不检查上传正文。

3.4.0（2026-11-27）退役软件内 HTTPS 正文解密。页面移除准备服务、证书信任和经筛选启动入口，产品接口拒绝重新启用；不检查上传正文，不安装或移除已有证书，不修改系统代理或 Claude 启动参数。Claude 可按正常方式打开。历史计数仅供历史参考，不代表当前接入、PID 归属或全流量覆盖。已有证书信任不会因退役自动消失，完整说明见 [HTTPS 退役与只读观察说明](docs/TELEMETRY_FILTER.md)。

八组文件来源继续列出：Sentry 文化与地区、Sentry 离线队列、应用配置、Electron 偏好、桌面/MCP 配置、Cookie 存储、安装与设备标识、Claude 日志码。其中可检查地区字段的来源为 Sentry scope、应用配置和 Electron 偏好；队列、桌面/MCP、Cookie、标识仅观察元数据，日志只显示固定分类计数。缺字段为黄色待观察，不能解释为所有地区信号已安全。完整清单见 [进程保护说明](docs/PROTECTION.md)。

已观察到的明确中国大陆字段风险连同固定来源保留至守护线程处理。已确认的文件 CN 风险或连接绕行事件处理/解除后需要新的公网复核；普通未知、核验中或陈旧恢复不因此触发强退。日志中的服务地区拒绝、权限拒绝、IP 限制、验证挑战、封禁、超时及原因未明的 403 分开显示，仅作排查提示。客户端版本变化轻提醒，不因更新强退。仅有中文语言、英文设备名、Cookie 写入或零错误计数都不证明实际所在地或服务资格。

后台公网 Pulse 周期或全面扫描取得合法版本缓存后，版本变化提醒可由用户点击“已复核版本变化”确认，仅更新 RegionGuard 自身基线；后台确认成功才撤下对应提醒，旧版本确认不能清除新版本提醒，也不影响保护判定。

3.1.1 修正诊断误报，并增加「支付接口 VPN / 代理实时分流」：在本次扫描期间通过当前用户的 Hako 本地 Unix socket，只读核对 Stripe JS、API 与 Radar 新连接使用的传输类型。HTTP 可达与代理接管分别报告；未捕获路由不算通过。报告不会输出节点名、服务器地址、连接标识或其他应用的访问记录。

Hako 的原生 Packet Tunnel 不以 Mihomo YAML 的 `auto-route` / `strict-route` 字段判断。正常安装标识、无组织绑定的 CLF 缓存、普通 Sentry 状态、输入法/语言资源、Safari 仅 ITP/历史元数据和定位权限 `prompt` 作为 INFO；实际错误、敏感权限已授权、站点存储和读取受限仍分别保留原有风险或未知状态。没有提供 Cloudflare trace 的 HTTP 响应不能证明出口一致。

旧版 `statsig.anthropic.com` 不再作为支付必达项；失败时额外查公共 DNS，只有 NXDOMAIN 才标注为旧域名不可解析，DNS 未确认仍保留警告。当前核心与桌面网络域名参见 [Anthropic 官方网络要求](https://code.claude.com/docs/en/network-config#network-access-requirements)。IP 信誉、真实高延迟、网络唤醒、日志错误和未验证的系统级断隧道阻断不会通过修改评分或清理数据消除。

## macOS 启动

```bash
./start.sh                    # CLI，默认端口 8765
./start.sh 8899               # 指定端口
python3 server.py --open      # CLI 并打开真实浏览器
./start.sh --tray             # 原生菜单栏，需项目虚拟环境内的 PyObjC
./start.sh --tray --silent    # 后台启动，不主动打开网页
```

菜单栏模式可关闭网页后继续守护。再次启动会打开已有实例的监测台。端口占用时尝试 8766–8799，再请求内核分配；实际 URL 以终端或运行状态为准。使用「退出 Region Guard」正常关闭；CLI 使用 Ctrl+C。

菜单栏显示正常、复核、异常、暂停四种状态；网页与菜单栏同步目标、通知和保护偏好。macOS 保护需要“后台持续监控”和“异常时自动强制退出 Claude”同时开启。可选本地检测周期为 50/100/250/500ms，默认 100ms；公网出口复核仍为 15/30/60 秒，默认 30 秒。原生路由和文件变化事件可提前触发复核；文件读取由独立线程处理。唤醒时先进入严格保护，再进行公网补测。

网络守护开启后，启动、唤醒、重要 TUN 路由变化或公网结果过期时，网络未确认安全仍可能强制退出 Claude。文件守护只因明确中国大陆字段触发，缺失、未知、核验中或陈旧均仅提示待观察。暂停监控或关闭自动退出开关后，不再终止进程。关闭通知开关只静音，不会关闭保护；软件不会自动重新启动 Claude。

升级应用时先正常退出旧 RegionGuard，再打开新应用；运行中的旧实例不会因替换磁盘文件自动热升级。

## 构建独立应用

独立应用构建需要 macOS、Python 3.12+、Node.js 及提供 clang/macOS SDK 的 Xcode 或 Command Line Tools。脚本在项目内编译只读连接库和创建构建虚拟环境，打包后无需另装 Python 或编译器。当前应用不打包 mitmproxy、旧 worker、证书操作模块或筛选策略资源；现有标准库扫描 CLI 保持 Python 3.9+ 兼容。

```bash
./build-macos-app.sh
# 如构建 Python 和所有依赖同时包含两种架构，可生成 Universal 2：
REGIONGUARD_BUILD_ARCH=universal2 ./build-macos-app.sh
```

产物：

- `dist/RegionGuard.app`：无终端窗口、无 Dock 图标的 AppKit Agent。
- `dist/RegionGuard-macOS.dmg`：包含应用与 Applications 拖拽链接。
- `dist/RegionGuard-macOS.dmg.sha256`：镜像摘要。

构建依次运行全部 Python/Node 单测、语法检查、隔离的真实 AppKit 冒烟测试，以及仅终止自有测试子进程的快速保护冒烟测试，再打包、Ad-hoc 签名、严格验签和生成镜像。无图形会话的 CI 可显式设置 `REGIONGUARD_SKIP_UI_SMOKE=1`，此时不能声称已完成 UI/实际信号验收。默认构建当前架构；Ad-hoc 签名不等同于 Apple Developer 公证。

## 检测、进程保护与隐私边界

- 常规体检和网络读取保持只读；不删除用户文件/缓存，不写系统 plist、注册表、hosts 或防火墙规则，不解包或修改 Claude 客户端。HTTPS 解密已退役，不提供启用或证书操作入口，也不自动卸载历史证书信任。
- macOS 进程保护是用户明确授权的例外：只对路径、Bundle ID、UID、PID 和启动时间确认的 Claude Desktop 主程序/Helper 发送单 PID `SIGKILL`，不使用宽泛的进程名批量终止，不提权、不改权限。Helper 包含两处标准 Claude.app 根目录内精确的 `Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler`；其他浏览器同名进程、其他应用、外部 Claude Code CLI、全局 node/ssh 不属于范围。
- 只读配置解析仅保留白名单状态，不输出密码、Token、Cookie、节点或账号标识原文；数据库审计仅查询域名元数据。多源文件守护只输出固定来源/字段类型、状态、分类码计数和数值证据；Cookie、安装标识、MCP 与队列来源仅观察文件元数据。当前版本不解密 HTTPS，不检查上传正文；只读连接来源与服务响应分类不能证明全部流量已覆盖。
- SQLite 复制数据库及 WAL/SHM 到自己的临时目录，再以只读模式查询；源数据库不写入。权限拒绝、数据库变化或扫描受限不算通过。
- Safari 只扫描固定沙箱子路径和 Default/Custom Profiles；不会盲目枚举 Containers、Group Containers 或废纸篓。TCC 拒绝明确显示未读取，用户可自行授予完全磁盘访问权限或在 Safari 内核对。
- 所有系统优化仅以报告/可审阅说明呈现。方案中的自动写入 LaunchAgent 与核心只读约束冲突，因此菜单栏只显示自启状态，并提供系统「登录项与扩展」的手动配置说明。
- 持久写入仅包含 RegionGuard 自己的运行状态、偏好、最近 500 条 Pulse 和最近 100 条保护事件；`protection-events.jsonl` 记录状态和强退指令统计，不保存敏感原文。打包构建与临时快照只清理自身生成的文件。退出只移除自己的运行标记，不移除实例锁 inode。

macOS 运行数据位于 `~/Library/Application Support/RegionGuard/`（目录 0700，文件 0600），始终位于 `.app`/镜像外。Windows 使用 `%LOCALAPPDATA%\RegionGuard`；其他平台使用 `~/.local/share/region-guard`。无法创建时回退私有临时目录。

## 检测范围

- 多库 GeoIP、WHOIS/RDAP/BGP、信誉与出口一致性；Cloudflare 域名矩阵含 assets/downloads，DNS 核验覆盖 bridge/config/pivot/Datadog。
- macOS：AppleLanguages 完整栈、时区、启动项、主机名语言状态、输入法、无线国家码、电源唤醒、DNS、证书信任参考和硬件标识隐私边界。
- 全面体检交叉核对内核 `scutil --nwi` 首选接口与默认/分裂路由，提示物理国内 IPv6、系统代理 ExceptionsList 风险。快速保护通过进程内 `sysctl`/`getifaddrs` 读取相关路由和接口，并只接收 PF_ROUTE 事件；不以每 100ms 启动 curl/ifconfig/netstat 的方式检测。公网探测 curl 禁用 curlrc 并移除代理环境变量。
- 后台连接观察：仅对已验证 Claude 主程序/Helper 的当前已建立 TCP、有对端 UDP 与 Hako 记录做只读关联，独立线程不制造测试流量。逐真实公网目的 IP 读取内核路由，区分 TUN、物理绕行、阻断、本地与未知；DIRECT 只是控制器选择，不等于物理直连或中国出口。未知、停止、API 断联/超时、陈旧撤销当前证明，历史仅供历史参考。
- 本地多源文件守护：独立线程在八组固定来源中分别检查白名单地区字段、仅元数据或固定日志码，使用文件事件加周期检查；未知、过期、缺失分别报告。有界的文件数/字节/截断范围会明确标记。队列正文、内存 EventLogging、上传正文和其他未列来源不在地区字段核验范围内。
- Stash/Hako、Clash Verge Rev、Mihomo/Clash Party、FlClash、Nyanpasu、ClashX/Mihomo、Surge、Sing-box 配置发现；只检查 DNS、TUN、严格路由和风险规则。修改时间不代表配置正在生效。
- Claude v6：版本/Rosetta、ant-device-registry/key-generation/key-read、ant-did、bridge-state、Sentry、CLF 绑定状态与日志分类计数；每文件最多尾部 4MB，每行至多计入一个类别。
- Safari/Orion 的 WebKit/ITP；Chromium 家族的 WAL、Cookie 主机列、DIPS、IndexedDB、国内 DoH、代理扩展；Firefox/Zen 的站点目录、Cookie 主机列和 TRR/语言设置。
- 真实浏览器检查出口、WebRTC、语言/Intl、默认语音、字体与图形 API。Canvas/Audio 两次样本只作为信息证据，浏览器内置隐私加噪不会因此被判高危。

检查结果是环境观测和排查线索；本地评分不能预测第三方服务的账号或准入决定。后端观测不等同于真实浏览器结果。100ms 是本地接口与受检文件的检查配置周期，受系统调度、文件变化、采样和终止调用耗时影响，不是响应硬上限或公网国家/IP 的 100ms 判定承诺，也不能保证首次异常请求或已排队的数据包一定被阻止。

## 本地 API

仅监听 loopback；Host 必须为本地地址且端口匹配。Origin 如存在须与请求同源，跨站 Fetch 被拒绝；所有 POST 必须携带 `X-Region-Guard: 1`。同一目标的并发扫描合并为一次执行。

- `GET /api/scan?target=US`、`GET /api/pulse?target=US`
- `GET /api/monitor/status`、`POST /api/monitor/start`、`POST /api/monitor/stop`
- `GET /api/history`、`POST /api/history/clear`（仅清空自身 Pulse 历史）
- `GET/POST /api/prefs`：`target`、`interval_sec`、`auto_start_monitor`、`notify_enabled`、`protection_enabled`、`local_interval_ms`；返回只读 `run_mode`。
- `GET /api/monitor/status` 的 `traffic` 返回后台连接观察状态、实际周期、新鲜阈值、两组当前证据及本次监控历史累计；`all_traffic_covered` 固定为 false。`action_reason_codes` 的绕行码只表示已观察待处理事件，独立于当前样本，不能冒充当下新鲜证明。暂停保留历史，下次启动重置。
- `GET /api/monitor/status` 的 `protection` 返回本地保护状态、采样耗时、失败原因和强退指令累计。统计中的成功次数表示已成功发出强退信号，不保证该进程在信号返回瞬间已完全消失。
- `protection.telemetry` 返回文件观察汇总、固定八组 `sources`、锁存的 `risk_source_ids`、`field_types`、原因码、观察年龄/耗时、检查次数和事件序号；`telemetry_backend_available` 表示观察后端是否可用。每组分列 `mode`、变化次数、文件数/总大小、`limited` 和可选固定 `diagnostics`，不包含路径或原值。旧后台缺少来源状态时显示尚未验证。
- `GET /api/telemetry/status` 只读返回退役状态；历史或兼容计数不作为当前流量证据。原 `start`、`trust`、`launch` 产品接口拒绝启用；保留 `stop` 仅供清理，页面没有操作按钮。
- 扫描项 `service_response_diagnostics`、`claude_traffic_coverage`、`client_version_review` 分别显示服务响应分类、只读连接来源与版本复核提示。TUN / Global 和已观察连接不能证明所有组件必无直连。

默认目标 US、公网复核 30 秒、本地检测 100ms；菜单栏自动开始监控和通知均开启。macOS 默认 `protection_enabled=true`（升级时缺少该偏好也使用此默认值），只有监控运行时才执行保护；其他平台不启用自动终止。通知采用边缘触发与 300 秒同异常抑制，静音和通知失败不阻塞保护动作。正文使用独立 argv 传递给 osascript，失败时尝试原生通知；实际展示受系统通知权限/专注模式控制。

## 测试与验收

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
node tests/test_fingerprint_checks.cjs
node tests/test_locale_checks.cjs
node tests/test_monitor_alerts.cjs
node tests/test_preferences.cjs
node tests/test_guard_ui.cjs
node tests/test_diagnostic_rows.cjs
node tests/test_telemetry_filter.cjs
python3 -m py_compile server.py mac_platform.py win_platform.py tray_app.py audit_common.py protection.py mac_guard.py
node --check static/app.js
.venv-macos/bin/python tests/smoke_macos_ui.py
.venv-macos/bin/python tests/smoke_fast_protection.py
.venv-macos/bin/python tests/smoke_entrypoint.py
.venv-macos/bin/python tests/smoke_packaged_macos.py
```

单测使用临时目录、模拟系统命令/信号与 loopback HTTP，不请求外网、不改系统。快速保护冒烟测试读取真实内核并对故障状态做逻辑注入，只向其自己创建的可丢弃子进程发送实际终止信号，不终止真实 Claude、不改变网络。结果写入 `build/fast-protection-smoke.json`。Shell/真实包冒烟使用自身隔离状态目录，不改动用户正在运行的旧实例或偏好；会运行所构建的应用和真实浏览器，不切断系统网络。历史和本轮验收范围见 [验收记录](docs/ACCEPTANCE.md)。

## Windows 保持兼容

```powershell
.\start.bat
.\start.ps1 -Port 8899
py -3 server.py --host 127.0.0.1 --port 8765 --open
.\build-windows-exe.ps1
```

`win_platform.py`、`RegionGuard.spec` 和 Windows 启动/打包脚本保留；本轮自动强退仅在 macOS 提供，Windows 保持只读监测。共享解析器、Sentry 状态和日志计数同步修复；Windows 托盘为可选后续能力（需要 pystray/Pillow），现有 CLI/EXE 不依赖 AppKit。

原生 API 参考：[Apple 唤醒通知](https://developer.apple.com/documentation/AppKit/NSWorkspace/didWakeNotification)、[Accessory 模式](https://developer.apple.com/documentation/appkit/nsapplication/activationpolicy-swift.enum/accessory)、[PyObjC 安装](https://pyobjc.readthedocs.io/en/latest/install.html)。
