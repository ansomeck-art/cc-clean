# RegionGuard macOS 验收记录

日期：2026-11-26 起。以下 Milestone 1–5、61 项测试和包验证是 **3.0 只读观测版本的历史验收**，不能直接作为后续版本的最终验收。用户随后明确授权快速检测、终止 Claude 进程及独立遥测上传筛选，随后采纳只读方向退役解密；当前 **3.5.0 build 12** 的后台连续连接观察与补盲验收见文末。

3.0 按桌面开发方案 Phase 1 → Phase 5 顺序执行；每阶段单测通过后才进入下一阶段。保留原有未跟踪的浏览器模块与测试，未覆盖其既有内容。

| 阶段 | 验收内容 | 已执行的门禁与结果 |
| --- | --- | --- |
| Milestone 1 | 私有数据目录；loopback/Host/Origin/Fetch/POST 守卫；同目标 Singleflight；注入式物理网卡 IPv6；浏览器模块接线；扫描/监控告警隔离；共享日志与 Sentry 修复 | 17 项 Python 测试通过；原有 3 组 Node 测试通过。原有 IPv6 9/9 恢复。 |
| Milestone 2 | AppleLanguages；NWI/IPv6/系统代理；多客户端发现；ant-device 元数据；Safari TCC/Custom Profiles；Chromium WAL/DIPS/IndexedDB/DoH/扩展；Firefox/Zen/Orion | `test_mac_audits.py` 覆盖方案要求的 10 组；当阶段全量 40 项 Python 测试及原有 Node 测试通过。 |
| Milestone 3 | 监听器总线；双时钟与唤醒补测；动态端口；0600 原子偏好；网页模式/通知控件；跨端同步；旧目标扫描结果隔离 | 当阶段全量 50 项 Python 测试通过；新增偏好 Node 测试通过。 |
| Milestone 4 | flock/运行标记/重复启动；Accessory AppKit Agent；主线程四态与菜单勾选；Workspace 唤醒；参数化通知和去重；退出清理 | 当阶段 57 项 Python、4 组 Node 测试通过；真实 AppKit 冒烟测试通过。实际 `./start.sh --tray --silent` 启动及正常信号退出清理通过。 |
| Milestone 5 | 全门禁构建；Universal 2 App/DMG；Ad-hoc 深度签名及严格验签；只读挂载；浏览器与偏好；重复启动；扫描中正常退出 | 最终 61 项 Python、4 组 Node、Python/JS/Bash 语法、真实 AppKit 全部通过。最终包冒烟结果全部为 true。 |

3.0 历史构建命令：

```bash
REGIONGUARD_BUILD_ARCH=universal2 ./build-macos-app.sh
.venv-macos/bin/python tests/smoke_entrypoint.py
.venv-macos/bin/python tests/smoke_packaged_macos.py
```

产物：`dist/RegionGuard.app`、`dist/RegionGuard-macOS.dmg`、`dist/RegionGuard-macOS.dmg.sha256`。入口 Mach-O 经 `lipo -archs` 验证同时包含 `x86_64 arm64`；`codesign --verify --deep --strict` 通过。完整构建门禁见 `build-macos-app.sh`。

## 3.0 历史真实包验证

- 以 `hdiutil attach -readonly` 挂载镜像，验证文件系统 `ST_RDONLY`，从镜像内运行应用成功。
- Info.plist 的 `LSUIElement`、`NSHighResolutionCapable` 为 true；真实 AppKit 运行策略为 Accessory。
- `/api/headers` 报告原生就绪，`/api/prefs` 报告 menubar。通过 API 切换 JP/15 秒后，监控状态同步；隔离 AppKit 测试确认目标子菜单勾选同步。
- 再次启动同一应用退出码 0，运行标记内容及端口/PID 未改变；真实 Safari 自动打开已有监测台，观测到菜单栏运行模式、JP 目标和实际扫描矩阵。
- 使用应用的正常退出路径关闭，退出码 0；运行标记移除、监听端口关闭。退出时会终止自己启动的探测子进程，扫描任务不再继续拉起新命令；无 RegionGuard 进程残留。
- 使用后再次严格验签通过，证明运行数据没有写入 `.app`。正常卸载测试镜像；自身偏好恢复。机器可读结果保存在 `dist/package-smoke-result.json`。

## 3.0 历史边界与规格冲突处理

- 没有修改系统网络、代理、hosts、证书、系统 plist、注册表或 Claude 包体；没有清理用户文件/浏览器缓存。只有 RegionGuard 自己的数据、构建输出和临时快照可写入/清理。
- 不查询 Cookie value/encrypted_value，不解密凭据；UUID、公钥、组织绑定与订阅/节点字段不进入报告。夹具回归断言敏感哨兵字符串不出现在序列化结果中。
- Windows WinINET/PAC 改为只查询注册表类型/长度，不读取代理地址/链接字节；WinHTTP 与绕过列表报告只保留状态/风险类型。原有 Windows 入口、打包配置和平台调度保留。
- 第零章禁止写系统 plist 优先于第四阶段的 LaunchAgent 自动写入要求。因此“登录时自动启动”只检查状态并提供系统设置说明，不写入/删除 LaunchAgent。这是明确的只读约束处理。
- 僵死实例锁不通过删除锁 inode 或杀死其他进程接管：死进程的 flock 自动释放；仍持锁但不响应时安全报告并要求稍后重试，避免出现双实例。

## 3.0 历史验收范围与实际限制

- 没有切断真实网络、关闭代理或强制合盖休眠；断流/地区/IP 跳变由故障夹具验证，四态由真实 AppKit 控件验证；系统唤醒通知通过 Workspace 原生通知中心投递验证，双时钟及补测时序由单测验证。
- 参数化 osascript 通知投递实际返回成功；通知去重、恢复、静音和注入防护经过测试。可见横幅受系统通知权限和专注模式影响，本次未更改这些系统设置，也未声称人工确认横幅展示。
- 本机为 Intel macOS 14.8.9，实际执行的是 x86_64 分支；arm64 已包含并通过通用包签名校验，未在独立 Apple Silicon 真机运行。产物为本地 Ad-hoc 签名，未进行 Apple Developer 公证。
- Windows 经过导入、编译、共享语义及代理隐私回归；本轮没有 Windows 真机验收。Windows 托盘打包仍属于 Phase 6，不计入此次交付。
- 外部 GeoIP/DNS 服务可返回限频或不可用；报告会保留未知/失败状态，不把接口失败当作通过。浏览器 API 采样有超时边界，未完成计 INFO。


## 3.1 用户授权的快速进程保护升级

同日后续用户明确要求“改成毫秒级，而且能终止进程做到守护”，并要求团队模式完成。该授权允许新增一个主动动作：对确认的 Claude Desktop 主程序和 Helper 发送强制退出信号。因此当前版本不得再整体描述为“100% 纯只读”。检测本身仍只读；不增加网络拦截，不修改系统配置、应用包或浏览器数据，不扩大敏感值读取/输出范围。

本轮实现范围：

- `mac_guard.py`：进程内 `sysctl/getifaddrs` 读取相关有效路由和接口，只接收 PF_ROUTE 事件；不每 100ms 启动系统命令。
- `protection.py`：独立本地保护线程，默认 100ms，可选 50/100/250/500ms；公网复核保持 15/30/60 秒。通知、日志和界面回调不在快速终止路径中执行。
- 严格保护覆盖启动/唤醒/重要路由变化后的未确认阶段、路由/TUN 风险、公网失败/地区/IP 异常和结果过期。旧目标、唤醒前和乱序结果不能将保护状态错误解锁。
- 只定位两处已知 Claude.app 中主程序/Helper 的精确路径，确认 Bundle ID、所属 UID、PID 和启动时间，发送前复核；不宽泛按进程名杀进程组，不提权。
- 网页与原生菜单栏同步保护开关和毫秒周期，显示阻断状态与强退指令统计。暂停监控或关闭保护后停止终止；恢复后不自动重开 Claude。可能丢失未保存内容已在产品与说明中明确告知。
- 自身保护事件最多 100 条，写入私有 `protection-events.jsonl`，不写入 `.app`。Windows 不启用本轮自动终止能力，继续保留原有只读审计与启动/打包入口。
- Shell 与打包冒烟改为独立测试状态目录，避免改变用户旧实例、实际偏好和实例锁。交付新版后，需要先正常退出旧 RegionGuard 再打开新版；不声称已对用户正在运行的旧实例热升级。

### 本轮验证记录

3.1 最终构建执行 `REGIONGUARD_BUILD_ARCH=universal2 ./build-macos-app.sh` 成功。121 项 Python 测试、5 组 CJS 回归、语法检查及真实 AppKit 冒烟全部通过；新增回归覆盖误杀边界、IPv4/IPv6 有效路由、保护线程错误、关闭竞态、唤醒与乱序隔离、前端超时及偏好回滚。`win_platform.py` 的既有跨平台入口和只读隐私回归继续通过；本轮没有 Windows 真机验收。

最终 `dist/RegionGuard.app` 为 3.1.0 Universal 2，入口包含 `x86_64 arm64`，深度严格验签通过。最终 DMG 以只读方式挂载并启动成功；冻结应用中的内核及进程后端均完成初始化。测试状态目录明确关闭自动终止，验证重复启动复用、偏好 API、浏览器保护控件、正常退出后无监听器，以及使用后再次严格验签。结果见 `dist/package-smoke-result.json`，全部字段为 true。真实 Safari 界面确认菜单栏运行模式、100 毫秒本地周期、独立秒级公网周期及自动强退开关；该包测试没有向真实 Claude 发送终止信号。

已执行的受控实际信号冒烟：`tests/smoke_fast_protection.py` 在 100ms 配置下读取真实内核 100 次，通过逻辑安全状态故障注入，实际终止 12 个测试自己创建的可丢弃子进程。没有更改网络，没有终止真实 Claude 或其他用户进程。结果文件：`build/fast-protection-smoke.json`。

最终构建门禁测得：内核采样中位数 1.225ms、P95 1.734ms；故障到信号中位数 98.566ms、P95 100.126ms、最大 100.324ms；观察到子进程退出 P95 125.616ms。该数字来自本机受控逻辑注入，不是硬实时保证或真实 Claude 断网现场实测。统计中的成功次数只代表已成功发出强退信号，不保证信号返回时进程已完全消失。完整操作及边界见 [3.1 进程保护说明](PROTECTION.md)。

### 3.1 不作出的保证

- 公网国家/IP 查询不具备毫秒级可靠判定能力；路由和接口看似正常时，上游故障可能仍需公网请求完成后才能确认。
- 周期、采样、信号和实际退出延迟各不相同；系统调度会增加延迟。已有连接、已经发送或排队的数据不能撤回，因此不承诺零泄漏或首包前阻断。
- 当前目标范围不包括外部 Claude Code CLI、全局 node/ssh 或任意安装目录；未获得进程身份/权限时不盲目终止，也不提权。
- 目标识别不是密码学身份认证；进程身份复核与发送信号之间仍存在很小的非原子时间窗口，不能宣称绝对不会发生 PID 复用竞态。
- 物理断网、实际合盖以及真实 Claude 强退不作为开发测试破坏性操作执行；受控逻辑注入与自有子进程的验证不能冒充这些场景的现场实测。

## 3.1.1 支付分流证据与诊断误报修复

2026-11-26，用户要求修复本地检查台的问题和警告，并核实支付接口走 VPN。实测 Hako 生效配置的 every-mode 规则与新建连接：Stripe JS、API、Radar 均使用既有 VLESS 路由。本轮没有修改其代理节点或分流规则。

- 新增 `proxy_runtime.py`，仅通过当前用户拥有的固定 Unix socket 发出白名单 GET；扫描期只保留三个 Stripe 主机的新连接传输类型，排除扫描前连接。直连或阻断判 FAIL，未取得证据判 INFO；HTTP 可达不能替代路由核验。报告不输出节点名、连接标识、进程路径或其他访问记录。
- Statsig 旧地址的 TLS 错误经公共 DNS 核实为 NXDOMAIN，从支付必达项分离；DNS 不确定时仍 WARN。所有 curl 探测统一移除代理环境变量，保持 curlrc 禁用与证书校验。
- Hako Packet Tunnel 根据运行时后端识别，避免将不存在的 Mihomo YAML 字段当作配置缺陷。正常本地状态改为信息提示；真实日志错误、实际站点存储、敏感权限与不确定状态不虚报通过。无 trace 内容的域名响应不计为已验证出口。
- 131 项 Python 测试、6 组 CJS 回归、Python/JS/Bash 语法、真实 AppKit 和快速保护冒烟通过。快速保护测试仅终止自身 12 个测试子进程。
- Universal 2 的 3.1.1（build 5）应用与 DMG 已重建、深度严格验签；隔离状态目录内的真实冻结应用扫描验证三项 VLESS、旧域名 NXDOMAIN 和原生 TUN。DMG 只读挂载、冻结后端、重复启动、偏好 API、正常退出清理验收通过。
- 已正常退出旧实例，保留旧产物在 `build/regionguard-before-3.1.1-20261126-222754/`，替换并启动 `dist/RegionGuard.app`。实际 `127.0.0.1:8765` 仍使用 US、15 秒公网复核、100ms 本地保护，保护状态 safe，偏好完整保留。
- 真实浏览器刷新后为 **86 分、0 FAIL、5 WARN**，支付表格三项均显示实时 VLESS 路由。剩余 WARN 为出口 IP 信誉参考、约 4 秒 HTTP 探测耗时、尚未验证的系统级断隧道阻断、网络唤醒开启、1 条历史遥测错误；未通过删除数据或掩盖风险强行清零。

## 3.1.2 遥测上传前的地区字段筛选：模块已准备，尚未激活

以下为历史记录。3.2.0 已按用户要求替换成软件内筛选，VPN 中旧模块已关闭；不要按本节继续启用 VPN 解密。

同日用户明确选择“只过滤中国地区字段”，并知悉需要 HTTPS 内容检查。本轮完成请求脚本和 Hako 原生模块准备；**尚未开启 HTTPS Decryption、尚未安装/信任新的 CA、尚未验证真实上传链路**。不得将以下离线/配置验收写成真实上传已经被拦住。

- `telemetry_filter/policy.js` 只检查已知遥测路径中的结构化国家/地区、CN 时区和明确 CN locale 区域段；命中阻断整条请求，正常请求空覆盖放行。不改写国家值，不删除或修改 Claude 本地文件。普通中文内容、zh-Hans、UTC+8 本身不作为中国地区判据。
- 支持 JSON、NDJSON、Sentry 长度标记信封与限量 gzip/deflate 解压；未知专用遥测格式暂缓上传。共享 Datadog 主机仅处理可明确归属 Claude 的 service，未归属数据不声称已筛选。详细范围、限制和同域明文可见范围见 [上传筛选说明](TELEMETRY_FILTER.md)。
- 本轮 132 项 Python 测试、7 组 CJS 回归通过；其中请求筛选有 96 个用例。实际 macOS JavaScriptCore 运行所交付钩子的 9 个用例通过，覆盖压缩 CN/非 CN、正常原样放行、重复键、支付和主 API 不进入字段判断。没有发送测试遥测给真实第三方收集端。
- Python/JS/Bash 语法、真实 AppKit、仅终止自身 12 个测试子进程的快速保护冒烟通过。新应用为 Universal 2 的 3.1.2（build 6）；隔离冻结应用验证三个静态产物、脚本 SHA-256、未启用状态和正常退出。签名、DMG 只读挂载、冻结后端、偏好 API、重复启动及清理验收通过。
- 已更新并启动 `dist/RegionGuard.app`，旧 3.1.1 产物保存在 `build/regionguard-before-3.1.2-20261126-230013/`。原 US / 公网 15 秒 / 本地 100ms / 自动退出偏好保留，后台状态 safe。检查台增加独立的上传筛选 INFO 项，未把网络 safe 当作上传筛选已启用。
- 通过 Clash 原生 UI 从本机 URL 导入 `RegionGuard CN Telemetry Filter`。UI 和发布 IR 确认 10 项有效、0 项忽略：4 条 request 阶段脚本、6 个 MITM 主机；四条均为 requiresBody=true、binaryBodyMode=true、maxSize=1048576、timeout=5，已缓存的完整脚本 SHA-256 全部匹配 `036463f7e229cd68c1f09c244ac57be1dc1caf8da77af4545c79840c503c0762`。
- Clash 主 HTTPS 解密开关仍为 off。原 AweSun 规则与 Stripe 三条 VLESS every-mode 规则保留。新模块配置详情与本机下载脚本可直接审阅。

机器可读证据位于 `build/telemetry-release/scan-smoke.json`、`build/telemetry-native-module.json`、`build/telemetry-upgrade.json` 和 `dist/package-smoke-result.json`。下一步是用户对新增证书信任与六个主机明文可见范围作执行时确认，然后用受控接收端验收真正的上传前阻断、正常转发与故障行为。

## 3.2.0 软件内筛选，替代 VPN 模块

2026-11-27，用户要求将拦截放进软件。已通过 Clash 原生 UI 关闭旧筛选模块，并验证发布清单不再包含它；主 HTTPS Decryption 保持关闭。原网络与 Stripe 分流继续由既有 VPN 配置处理。

- RegionGuard 自带 independent worker，以 regular HTTP(S) 代理监听本机随机端口。完整缓冲已知遥测后调用同一字段策略；CN 返回 403、未知格式 503，正常体不改写。其他域名 TLS 原样隧道转发，不安装 TUN 或系统扩展。
- 141 项 Python 测试在 Python 3.12 和原 3.9 环境均通过；7 组 CJS 回归通过，含 94 个策略用例。真实 JavaScriptCore 9 个用例通过。
- `tests/smoke_software_filter.py` 使用隔离本机 TLS 接收端，证明 CN、格式未知和 gzip CN 被阻断时上游连 TCP 连接都未建立；验证正常压缩字节及认证头保持不变、HTTP/2 阻断、聊天路径通过、共享域名归属、Stripe 原证书透传、私有计数和父进程退出清理。无钥匙串写入，无测试遥测上传第三方。
- 真实 AppKit 与原有快速保护冒烟通过，仅对测试创建的 12 个子进程发信号。签名、严格验签、DMG 只读挂载、冻结 worker 启动、偏好 API、重复实例复用及正常退出均通过。
- 已更新并运行 `dist/RegionGuard.app` 3.2.0 build 7。本次完整打包为当前 Intel 机器的 x86_64，未声称 Universal 2。旧产物与偏好快照保存在 `build/regionguard-before-3.2.0-20261127-022152/`。
- US、公网 15 秒、本地 100ms、自动退出及通知偏好逐字节保留。新 PID 12249、端口 8765，进程保护状态 safe。软件内服务已准备，但证书未受信任、尚未从它启动 Claude，实际检查计数为零。浏览器已验证显示「等待证书信任」且启动按钮禁用，证书说明可展开审阅。

证据：`build/software-frozen-smoke.json`、`build/software-package-smoke.json`、`build/software-upgrade.json`、`build/software-final-check.json`、`dist/package-smoke-result.json`。当前等待用户对本机证书及六域名 HTTPS 明文范围的执行时确认；不得把受控接收端验收写成真实 Claude 已接入。机制和使用边界见 [软件内筛选说明](TELEMETRY_FILTER.md)。


## 3.2.1 Claude 连接失败：Chromium 证书兼容修复

2026-11-27 用户报告客户端无法连接。排查时软件服务在线，系统验证成功，但 Claude 日志尾部有 43 次 ERR_CERT_AUTHORITY_INVALID，实际上传前计数为零，保护器未发送退出信号。无凭据 HEAD 请求直接与经筛选均可完成 TLS。Chromium 官方 trust_store_mac.cc 明确忽略 kSecTrustSettingsPolicyString；3.2.0 因此不能用 macOS 校验成功代表 Chromium 已接受证书。

修复改用新 CA 自身的 critical NameConstraints，允许六个准确 DNS 名，排除全部子域名及所有 IPv4/IPv6 地址，pathLength=0、EKU=TLS serverAuth。钥匙串只写入 Chromium 支持的 SSL 策略；不忽略证书错误，不关闭上游校验。服务身份保持稳定，Node 环境使用同一受限 CA，旧证书不用于新链。客户端退出后页面会撤回“已启动”提示。

144 项 Python 测试在完整 3.12 环境通过；原 3.9 的扫描兼容测试通过（新增两项加密测试因无相应依赖跳过）。7 组 CJS、9 项 JavaScriptCore、真实 HTTPS 的 CN/gzip/HTTP2 阻断及正常原字节转发回归通过。新增原生 SecTrust 测试验证六域名通过、其他域名/子域名/IP 即使用此 CA 的密钥签发也被拒绝；隔离的 OpenSSL TLS 实测同时验证准确域名约束。测试不写入钥匙串。

3.2.1 build 8 的签名、冻结服务启动、DMG 只读挂载、偏好 API、重复实例复用及正常退出通过。已替换运行本机应用，US / 15 秒 / 100ms 等偏好逐字节保留。新 CA 指纹不同，需要用户对新证书完成 macOS 认证，再从软件启动 Claude，随后才能报告客户端实际链路恢复。

证据：build/compat-package-smoke.json、build/compat-upgrade.json。旧产物保存在 `build/regionguard-before-3.2.1-20261127-030058/`。当前 PID 14256，端口 8765。

3.2.1 用户完成新证书认证后的实测：受信任状态为 true，软件收到 124 次 HTTPS 请求，已检查并放行 12 条正常遥测，CN 拦截 0、格式暂缓 0。客户端随后正常退出（退出码 0）；进程快照未发现 Claude / Anthropic 相关残留，仅有 RegionGuard 主进程及其直属筛选 worker。放行计数不代表收集端已确认接收，软件不记录远端回执或遥测正文。证据：`build/compat-live-verification.json`。

## 3.2.2 本地 Sentry 文件守护与本次启动证据

2026-11-27，用户要求补齐检查发现的文件监控与会话状态缺口，继续使用团队模式。新增 `telemetry_watch.py`，只读观察固定 Sentry `scope_v3.json` 的文化/明确环境元数据；不修改或清理 Claude 文件，不读取离线队列正文。后台文件线程通过 kqueue 事件加周期 stat 检查发现创建、原子替换和父目录重建，未变化时不反复读取正文。文件限长 1 MiB，逐组件拒绝 symlink、核验所属 UID 与普通文件类型，并在读取前后复核稳定性。

明确中国国家/地区、CN locale 区域段及大陆时区会进入现有身份校验和逐 PID 强退链路。普通中文、单独 zh/zh-Hans、UTC+8、HK/MO/TW 不作为中国证据。已观察到的明确风险保留至守护处理，旧 ACK 不能清掉较新风险；拒绝/权限失败或进程身份未知时不确认处理。文件核验中、解析或读取失败、观察结果陈旧会进入严格保护；缺失文件仅作为未验证范围显示，不判为中国风险。风险/未知解除仍需新的公网复核，恢复不自动重开 Claude。

上传筛选增加私有管道两阶段会话协议：arm ACK → 启动客户端 → activate ACK → 接受当前会话新请求统计。旧 worker、旧会话、ACK 前数据及跨会话完成的旧请求均不能确认本次接入。ACK 超时撤销证明并关闭 worker，不添加直连回退、不强退客户端。`stats` 为当前服务的历史累计；`session_stats`、`session_id`、`traffic_confirmed` 为本次启动证据。它们不证明所有请求或进程都遵循代理。

最终构建门禁：

- Python 3.12 的 **212 项测试全部通过**，包括 39 项文件观察与 18 项会话协议回归；Python 3.9 同样运行 212 项，通过 210 项，两项缺少加密依赖的测试按预期跳过。Windows 导入、共享行为和隐私回归保留；没有 Windows 真机验收。
- **7 组 CJS 回归通过**，其中上传字段策略 94 用例；真实 JavaScriptCore 的 9 项内存 fixtures 通过。界面覆盖文件风险/未知/缺失/暂停、观察年龄、敏感值不出界及历史计数不冒充当前会话。
- 真实 AppKit 冒烟通过。网络守护信号冒烟只终止测试创建的 12 个子进程；新增文件冒烟在隔离目录做 6 次实际原子写入，只终止其 6 个自有子进程。100ms 配置下，文件变化至成功发出信号中位数 **20.676ms**、P95/最大 **24.047ms**，观察到退出 P95 **43.289ms**。这是本机受控样本，不是硬实时或真实 Claude 断网实测。
- 隔离 HTTPS 接收端验证 CN/未知/gzip/HTTP2 上传前阻断、正常原字节转发、Stripe 原 TLS 透传，以及真实私有管道 arm/activate ACK、当前会话计数及父进程退出清理。测试不写入钥匙串，不向真实第三方发送虚构遥测。
- 在 `build/release-3.2.2` 独立输出目录完成 3.2.2 build 9；当前完整包为 Intel **x86_64**，没有声称 Universal 2。深度严格验签、SHA-256、DMG 只读挂载、冻结上传 worker 与文件观察模块初始化、重复实例复用、偏好 API、浏览器控件及正常退出后无监听器全部通过。冻结包测试明确关闭保护及证书/客户端激活。

验收后正常退出旧 RegionGuard，保留旧产物于 `build/regionguard-before-3.2.2-20261127-125242/`，替换并运行 `dist/RegionGuard.app`。偏好逐字节保留，US / 公网 15 秒 / 本地 100ms / 自动强退开启；原筛选服务恢复、证书指纹与信任保持不变，没有启动真实 Claude。启动时的文件恢复隔离完成新公网复核后，当前保护状态 safe，文件状态 safe，后端 kqueue+stat，真实终止指令计数 0。真实 Safari 确认当前文件观察、字段类型、检查年龄及“等待接入 Claude”；当前会话没有接入证明，计数为零。

机器可读证据：`build/telemetry-watch-smoke.json`、`dist/package-smoke-result.json`、`build/telemetry-watch-upgrade.json` 和 `build/telemetry-watch-live-check.json`。升级记录中的 blocked 是启动时的临时隔离快照，最终运行状态以随后 live-check 的 safe 为准。文件快照和已知上传端点均不能读取 Claude 服务端对账号的地区判定，也不能撤回已经上传的数据或覆盖未被观察到的瞬时文件内容。

## 3.3.0 八组文件守护与明确中国地区风险联动

2026-11-27，用户要求将列出的 Sentry、应用配置、偏好、桌面配置、日志、Cookie 与安装标识纳入守护，并再次明确“中国区域就是危险，发现危险后停止 Claude”。本轮按既有主动保护授权实现；检测只读，终止仍仅针对通过身份复核的 Claude Desktop 主程序与 Helper。没有修改 Claude 文件、系统网络、代理规则或证书信任，也没有启动真实 Claude。

新增 `artifact_policy.py` 与 `artifact_watch.py`，由现有快速保护线程消费脱敏状态，保留旧 `telemetry_watch.py` 的接口和 39 项回归。一个工作线程统一以 kqueue 加周期 stat 观察固定八组来源；默认 100ms，可通过现有保护周期设置调整。启动时已经存在的明确危险字段同样检查。

| 固定来源 | 实际观察内容 | 地区判定边界 |
| --- | --- | --- |
| Sentry scope | 白名单文化、国家/地区及环境字段 | 明确中国国家/地区、CN locale 区域段、大陆时区触发风险；必要文化字段缺失保持未知 |
| Sentry 离线队列 | 文件数、字节数及元数据变化 | 不读取信封正文，不核验地区 |
| 应用 config | 白名单 locale、语言及明确国家/地区、时区字段 | 只判断明确地区证据，不遍历任意用户内容 |
| Electron Preferences | `intl.accept_languages`、`intl.selected_languages`、`spellcheck.dictionaries` | 明确 CN 区域段触发风险；合法空列表表示未设置，不判格式错误 |
| 桌面 / MCP 配置 | 固定配置文件元数据 | 不读取 MCP 配置正文或设备名称，不核验地区 |
| Cookie 存储及 WAL/SHM | 固定存储文件元数据 | 不打开数据库、不读取或解密 Cookie 值，不核验地区 |
| ant-did 安装标识 | 文件元数据 | 不读取标识值、不计算标识内容哈希，不核验地区 |
| Claude 日志 | 固定七类日志码计数及完整结构化环境元数据 | 普通错误码只提示；明确结构化中国地区字段才形成 CN 风险 |

范围内正向 CN 证据优先于其他字段的格式错误，已观察风险按固定来源锁存，旧 ACK 不能消除新风险。身份拒绝、权限失败或进程未知不确认处理；风险解除后仍需新的公网复核，不自动重启 Claude。普通文件写入、中文内容、单独 zh/zh-Hans、UTC+8、英文或拼音设备名、Cookie 数量、新 ID 与零错误均不构成地区安全证明。

隐私和有界观察：JSON 上限 1 MiB；日志每次最多解析 512 KiB、最多 16 个受检文件，目录及队列枚举也有上限；超限、截断、读取或解析失败明确显示未知或范围受限。逐组件拒绝 symlink，核验所属 UID、文件类型、描述符及读前后稳定性。未变化文件不反复读取正文；用于检查大日志连续性的私有字节缓存仅驻留观察线程，停止时清理，不进入 API、事件日志或报告。API 只返回固定来源、模式、状态、原因类型、计数、年龄及限制标志，不输出路径、日志行、设备名、Cookie 或标识值。

独立回归发现并修复了三类漏判边界：后读来源耗时不能刷新先读来源的证据年龄；同 inode 的小文件及大日志截断后增长不能跳过新危险前缀；基线恰落在换行边界不能丢弃完整记录。同时验证正常追加不重复统计或重新锁存旧风险、无末尾换行后补换行不重复处理，以及多来源风险不被旧确认清除。

### 3.3.0 最终门禁与真实包验收

- Python 3.12 **294 项测试全部通过**，包括 30 项字段策略、43 项多来源观察、8 项保护集成及原有跨平台/隐私回归。Python 3.9 运行同样 294 项，通过 292 项，两项缺少加密依赖的测试按预期跳过。没有 Windows 真机验收，不声称扩大 Windows 主动终止范围。
- **7 组 CJS 回归通过**，含 94 项上传筛选策略；实际 JavaScriptCore 的 9 项夹具通过。界面验证固定八行、各观察模式、缺失与未知、来源风险锁存、年龄及敏感值不出界，历史计数不能冒充本次上传接入。
- 真实 AppKit、原有网络守护 12 个自有子进程、旧 Sentry 文件守护 6 个自有子进程冒烟通过。新增八组观察冒烟在私有临时目录执行 **8 次真实危险文件写入并终止 8 个测试自建子进程**；元数据来源正文读取次数为 0，未向真实 Claude 发信号，未更改网络或信任。
- 本次 100ms 配置下，新增文件变化至成功发出信号的中位数 **23.910ms**、P95/最大 **27.735ms**，观察到子进程退出 P95 **42.748ms**。这是本机事件驱动受控样本，不是硬实时承诺或真实 Claude 的退出时延保证。
- 隔离 HTTPS 接收端的 CN、未知、gzip、HTTP/2 上传前阻断、正常原字节转发、Stripe 原 TLS 透传、私有会话 ACK 与父进程清理继续通过。文件守护没有扩大上传端点覆盖，也没有改动证书信任。
- 3.3.0 build 10 在独立目录构建；当前完整包为 Intel **x86_64**、本地 Ad-hoc 签名，未公证，未声称 Universal 2 或 Apple Silicon 真机验收。严格深度验签与 DMG SHA-256 匹配。
- DMG 只读挂载验收 **15 项全部为 true**，覆盖冻结原生后端和上传 worker、固定八组声明且关闭保护时不读取用户文件、无真实进程信号、隔离状态目录、重复启动复用、偏好 API、真实浏览器控件与正常退出后无监听器。镜像已正常卸载，运行后应用再次严格验签通过。

验收后正常退出旧 RegionGuard，备份于 `build/regionguard-before-3.3.0-20261127-144647/`，将新版发布到 `dist/RegionGuard.app` 并启动。偏好逐字节一致，证书指纹与信任不变，原上传服务恢复。2026-11-27 14:50 美东时间核对：PID 43913、端口 8765，US / 公网 15 秒 / 本地 100ms / 自动强退开启，守护与受检字段状态 safe；八组来源均有当前观察，其中日志 6 个文件。真实终止指令为 0，没有启动真实 Claude；筛选服务 ready，但本次会话尚未接入，不能宣称当前 Claude 上传已经受保护。

真实 Safari 已显示八组来源表、100ms 周期、开启的强退开关；Cookie、安装标识、桌面配置和队列明确显示“仅观察元数据，地区未核验”，日志码仅提示，受检字段未见风险不表述为所有文件或账号绝对安全。

机器可读证据：`build/artifact-watch-preflight.json`、`build/artifact-watch-smoke.json`、`build/artifact-watch-upgrade.json`、`build/artifact-watch-live-check.json` 与当前 `dist/package-smoke-result.json`。完整操作见 [进程保护说明](PROTECTION.md)，上传范围见 [独立上传筛选说明](TELEMETRY_FILTER.md)。

文件守护在变化发生后读取并响应，无法在本地首次写入前阻止写入，也不能保证早于首次上传。文件事件可合并，未被读到的瞬时内容和范围外文件不在覆盖内；Sentry 必要文化字段暂缺仍按严格未知保护，未放宽启动规则。服务端实际地区/账号判定不可由本地快照证明；普通文件变化或错误码不等于中国地区，恢复条件也不等于服务端已解除限制。

## 3.4.0 缺字段误强退修复、服务原因分类与 HTTPS 解密退役

2026-11-27，用户提供五项建议并要求完成合理改进。使用既有团队模式分别完成本地策略、响应/版本分类、只读流量证据、界面与独立复核。本节取代 3.3.0 中“文件未知也强退”的规则和 3.2.x/3.3.0 中启用 HTTPS 解密的操作说明；之前章节只保留历史验收含义。

### 文件动作边界

- Sentry 的 `culture`、`locale` 或 `timezone` 尚未写入时返回 `observed`，显示待观察，不据此推断中国地区或终止进程。其他字段的格式错误、文件读取失败、核验中、缺失、观察结果陈旧亦仅作为文件范围未核验提示。
- 只有明确中国大陆国家/地区字段、CN locale 区域段或大陆时区的正向证据进入文件终止动作。元数据变化、错误日志码与服务拒绝分类均不单独触发强退。
- 已经确认的 CN 风险继续锁存，旧 ACK 不能清除新风险；观察器重启时年龄暂为 `None` 或年龄陈旧不会抹去已有风险。只有明确 CN 风险解除后才重新要求公网复核；普通未知/待观察恢复不使已确认的网络结果失效。
- 网络守护仍独立使用既有严格策略，包括公网首次验证、唤醒、重大路由变化、断流、国家/IP 异常及结果过期。文件放行不覆盖网络风险，恢复不自动重开 Claude，进程身份校验和信号范围不扩大。

### 服务响应与轻量版本提醒

新增纯函数 `service_diagnostics.py`，将明确地区拒绝、权限拒绝、IP 访问限制、Cloudflare 验证、明确封禁代码、超时、网络连接错误、原因未明的 403 和其他 HTTP 错误分为九类。复用已经读到的有界日志窗口，不增加日志原文输出或解密正文。地区拒绝不是用户国籍证明，权限/IP 限制不是封号，普通 403 保持原因未知；否定标志 `false`/`0` 不计为明确拒绝。

公开登录探测继续使用无凭据请求，但删除旧版“非挑战 403 就是地区封锁”的判定；只将精确同源地区拒绝重定向或明确错误码计入相应类别。原始 stderr 和重定向 URL 不进入响应报告。分类依据参考 [Claude 官方错误说明](https://platform.claude.com/docs/en/api/errors)、[官方 IP 白名单说明](https://platform.claude.com/docs/en/manage-claude/ip-allowlist)及 [Cloudflare 挑战响应说明](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)；不会由状态码推测账号原因并建议清理 Cookie 或 ant-did。

新增 `client_version.py`：普通全面扫描只读两处已知 Claude.app 的 `Info.plist`，记录经过约束的数字版本；不接入 100ms 路径，不读取队列正文。RegionGuard 自身 0600 版本基线保存未复核提示。真实版本变化只提醒，用户显式点击“已复核版本变化”后才清除私有提示；请求必须携带所显示的版本组，旧页面不能清除更新版本的提醒。失败保留提示，不影响地区判定或进程保护。

### 只读流量证据与退役边界

- 新增 `traffic_evidence.py`，只对再次验证 UID、PID、启动时间与准确程序路径的 Claude Desktop/Helper 使用限定 PID 的只读 `lsof`；输出有 2 秒和 2 MiB 上限。与当前用户拥有的固定 Hako socket 的白名单 GET 元数据关联，所有地址、目的地、路径、节点名和连接 ID 仅作私有匹配键，不输出。
- 两组固定计数分别显示当前 socket、匹配数、新连接样本以及 TUN/本机代理/未知入站和代理/DIRECT/未知路由选择。DIRECT 不等于物理网卡绕过或中国出口；未匹配项保留未知。客户端未运行时不执行全机连接枚举，也不虚构覆盖证据。`all_traffic_covered` 始终为 false，TUN 与 Global 配置均不能替代完整覆盖证明。
- 未做全进程抓包、TLS 解密、条件 OTLP 通道扩展或队列正文检查，维持轻量观察范围。
- `readonly_telemetry.py` 为产品的退役边界：状态固定 `retired`，原 start/trust/launch 接口拒绝操作，stop 仅为空操作兼容。界面删除准备服务、证书信任与经代理启动入口，不再注入 Claude 代理参数或 CA 环境变量。旧 worker 模式在初始化界面/服务前直接拒绝。
- 当前构建清单不再安装 MITM 依赖，新应用归档明确排除 `mitmproxy`、旧 worker、旧运行控制器、证书操作模块和筛选策略资源。历史源码及纯夹具可保留作为回归参考，不是当前产品能力。已有 CA 文件和系统信任没有被安装、移除或变更，不能把退役解释为旧信任已被撤销。

### 3.4.0 最终门禁与运行验收

- 完整 Python 3.12 构建门禁 **390 项测试全部通过**；Python 3.9 同样运行 390 项，通过 388 项，两个缺少可选加密依赖的历史证书夹具按预期跳过。包括 28 项响应诊断、29 项版本基线/确认、26 项流量关联，以及新增缺字段不终止、未知不终止、CN 锁存跨重启、API 拒绝启用和显式版本确认回归。原 Windows 导入、共享语义及隐私回归保持通过，没有 Windows 真机验收。
- **7 组 CJS 回归通过**，涵盖待观察与独立网络保护、九类诊断、HTTPS 退役、版本按钮默认隐藏、无自动确认、请求失败、幂等重试、旧 GET/ACK 不覆盖新版本；既有 94 项历史字段策略也只作离线回归。JS/Python/Bash 检查和真实 AppKit 验证通过。
- 私有文件冒烟先将 Sentry 改为缺少 culture 的正常启动夹具，经过多轮实际保护采样，自有健康子进程保持运行且未收到守护信号；之后 8 次明确危险文件写入分别终止 8 个自有测试子进程。元数据正文读取次数为 0，没有操作真实 Claude、修改网络或信任。当前构建的文件变化至信号中位数 **22.983ms**、P95/最大 **25.448ms**，观察到退出 P95 **42.136ms**，仅为本机受控样本，不是硬实时或首次上传前保证。原网络与 Sentry 信号夹具继续只操作其自有进程。
- 3.4.0 build 11 的完整 macOS 包为 Intel **x86_64**、Ad-hoc 签名，未公证；没有声称 Universal 2 或 Apple Silicon 真机验收。构建后与运行后严格深度验签通过，DMG SHA-256 匹配。
- 只读 DMG 验收 **16 项全部为 true**。实际检查冻结 PYZ 归档不含解密引擎、worker、旧控制器或证书模块；退役接口拒绝启用，不创建 CA 目录。原生后端与八组观察模块初始化、隔离状态目录、重复实例复用、偏好 API、关闭保护时不读取用户遥测文件、不发送真实进程信号、正常退出后无监听器均通过；测试镜像正常卸载。

正常退出旧 RegionGuard 后，旧产物保存在 `build/regionguard-before-3.4.0-20261127-222835/`，新版发布至 `dist/RegionGuard.app`。升级前确认无真实 Claude 在运行，已停止旧解密 worker；本轮没有启动或终止真实 Claude。偏好逐字节一致、原 CA 文件逐字节一致、没有调用信任修改操作。

2026-11-27 **22:30 美东时间**的实际运行核验：PID 62143、端口 8765，US / 公网 15 秒 / 本地 100ms / 自动保护开启，保护状态 safe，八组来源持续观察且日志 6 个文件；真实终止指令为 0。HTTPS 状态 retired、服务未运行、客户端未由软件启动；安装版本基线 6.28899.6、权限 0600，首次建基线无版本变化提醒。

真实 Safari 已显示“HTTPS 正文解密已停用”、仅明确中国大陆文件字段触发强退的说明、九类服务计数和版本缓存。实际观察窗口计数为地区拒绝 0、权限拒绝 3、IP 限制 0、挑战 0、明确封禁代码 0、超时 9、网络错误 6、未知 403 及其他 HTTP 错误各 0；此窗口可能包含历史日志，不是当前账号结果。实际流量检查显示客户端未运行，暂无连接证据，没有宣称真实 Claude 的全部流量已经验证。

证据：`build/readonly-guard-preflight.json`、当前 `build/artifact-watch-smoke.json`、`build/readonly-guard-upgrade.json`、`build/readonly-guard-live-check.json`、`dist/package-smoke-result.json`。详细行为见 [保护说明](PROTECTION.md)及 [HTTPS 退役与只读观察说明](TELEMETRY_FILTER.md)。当前版本不拦截 HTTPS 上传，文件观察也不能阻止首次写入、撤回已上传数据或读取服务端的地区/账号决定。

## 3.5.0 持续后台连接观察、真实目的路由与 Crashpad 补盲

2026-11-28，用户明确要求自行补齐连接监控的实现缺口。此前 3.4.0 的连接归因只在全面扫描时执行；本轮新增独立后台观察线程，随后台监控启动和停止，关闭网页或不执行全面扫描仍继续采样。继续不抓包、不解密 HTTPS、不修改系统网络、路由、代理、证书或 Claude 文件，也不放宽进程身份核验。

### 已完成的补盲

- 新增 `traffic_watch.py`。原生连接周期默认 **500ms**，与现有 **100ms** 网络/文件保护及秒级公网探测分开；原生不可用时才使用限定已验证 PID 的 lsof，回退周期至少 **2000ms**，不会每 100ms 启动外部命令。
- `GET /api/traffic/status` 和监控状态只复制内存缓存，不等待进程枚举、socket、路由或控制器 I/O。慢读取、异常、停止、唤醒、重启和陈旧都会撤销当前证明；旧代次结果不能覆盖新状态。快速停止后重新启动复用一个未完成的 I/O 通道，不堆积并发采样线程。
- 新增 SDK 编译的 `native_connections.c` 与 Python 窄 ABI 封装 `native_connections.py`。只对选定且重复核验的同用户 PID 使用 libproc FD 元数据，前后核验 UID、启动时间及权限状态。保留建立中和关闭中的 TCP，只排除 LISTEN；未连接或未绑定 UDP 仍作为未知对端 socket 可见，不能假装不存在。原生读取不启动子进程、不发送探测数据，不输出地址、端口、PID、文件路径或原始异常。
- SDK 的 `socket_fdinfo` 大结构由 C 头文件编译确定，Python 不手抄 Darwin union；私有输出行 64 字节，ABI 自检与边界测试通过。生产库不包含测试专用入口。`/api/headers` 可验证冻结包内的库确实加载成功，不只检查文件存在。
- `traffic_evidence.py` 修正增量和累计混用：当前帧 `new_connection_delta` 与本次监控累计分开，内部按进程身份和连接键做有界 LRU 去重。进程集合变化不把仍存在的连接全部重计，PID 重用不继承旧归因；一次有界控制器重查缓解建立先后竞态，无法匹配始终保留未知。
- 新增 `connection_routes.py`，按已观察 socket 的真实目的 IP 读取并索引内核路由，补上固定探测 IP 看不到的专门 host-route 例外。入站类型、控制器代理/DIRECT 选择、目的地址路由为三个独立维度。公共目的地址上有效、未限定接口的 en 路由例外可以形成保护事件；局域网、本地/FakeIP、未知和 DIRECT 本身不产生此事件。
- 最长前缀、并列路由、接口状态、IFScope、LOCAL/BROADCAST/MULTICAST、REJECT/BLACKHOLE、CONDEMNED/DEAD 均分别处理；本地或失效路由不误触强退，WASCLONED 不一概丢弃。一次路由快照建立私有索引，避免每个 socket 重复遍历全表。
- 明确目的路由风险锁存为固定 `connection_route_bypass` 事件，经原有逐 PID 身份复核后处理；拒绝、权限失败或身份未知不 ACK，旧 ACK 不能清除更新事件。风险处理/解除后要求新公网复核，不自动重开 Claude。仅只读观察期间产生的旧动作证据在重新启用强退前原子清除并换代，不跨启用边界误用；唤醒和普通失效仍保留尚未处理的已知事件。
- 只读确认本机 Claude 包内有 canonical Crashpad 可执行文件，将已验证 Claude.app 内精确的 `Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler` 纳入 Helper 组。名字仅是枚举前滤，最终仍核验 Bundle ID、UID、PID、启动时间和准确路径；Chrome/Safari 等其他浏览器的同名 Crashpad、框架别名、任意路径副本和独立 CLI 不因此纳入。
- 版本元数据检查随后台公网 Pulse 周期运行，不再只依赖全面扫描；不进入 100ms 动作线程，检查异常不能阻断公网探测。原有显式版本复核及旧页面保护保留。

界面沿用约 1 秒的监控轮询，不另起采样 timer。当前证据、最近一轮增量、本次监控累计和待处理事件分别显示；暂停、接口失败或陈旧撤销当前表，历史不冒充当前。未运行 Claude 时明确显示“等待 Claude 进程”，不误报读取后端未就绪；其他浏览器不在 Helper 范围。原有八组文件观察、缺 culture 不强退、服务错误分类和 HTTPS 退役继续保留。

### 3.5.0 最终门禁

- Python 3.12 **475 项测试全部通过**；Python 3.9 同样运行 475 项，通过 473 项，两项缺少可选加密依赖的历史证书夹具按预期跳过。含 21 项原生读取、39 项连接归因、19 项后台生命周期、13 项逐目的路由、7 项连接保护及 9 项监控集成回归；原有平台兼容、文件、服务分类和隐私门禁保留。没有 Windows 真机或独立 Apple Silicon 验收。
- **7 组 CJS 回归通过**，包括当前/历史/锁存分离、陈旧撤证、停止与恢复、fallback 实际周期、旧后台及错误 DTO、空闲等待提示。Python/JS/Bash 检查与真实 AppKit 门禁通过。
- 原生读取 30 轮自有回环测试通过：真实 TCP、半关闭 TCP、连接和未连接/未绑定 UDP、IPv6 UDP。SDK 实测 `socket_fdinfo` 792 字节、私有行 64 字节；热路径中位数 **0.332ms**、P95 **0.517ms**，冷启动最大 **29.900ms** 包含首次导入。仅为本机自有 socket 样本，不代表完整连接观察耗时或硬实时上限。
- 新端到端冒烟：原生读取测试自建子进程的真实 TCP/UDP socket，内存模拟控制器，仅逻辑注入目的路由风险，没有修改真实路由。未知 UDP 不产生强退；主程序及内置 Crashpad 的角色夹具分别触发原有单 PID 信号路径，共终止 **2 个自有测试子进程**。500ms 观察 / 100ms 保护配置下，故障至信号中位数 **372.213ms**、两样本 P95 **379.469ms**。未操作真实 Claude、未检查包体或向外网发送该测试流量，线程正常收尾。
- 原网络、文件信号及 AppKit 冒烟继续通过。当前八组文件冒烟包含缺 culture 健康子进程不被守护终止，以及 8 次明确危险文件写入的自有子进程联动；没有读取元数据源正文或改变网络/信任。
- 3.5.0 build 12 的应用与原生库均为 **x86_64**，本地 Ad-hoc 签名、未公证。构建后和运行后深度严格验签通过，DMG SHA-256 一致。当前构建使用 Xcode/Command Line Tools 的 clang 和 SDK；用户运行完整包不需另装编译器或 Python。
- 最终只读 DMG **19 项全部为 true**，新增冻结原生库实际加载、无扫描/无浏览器时后台样本继续增加、随暂停撤销连接观察；同时保持不含解密引擎、拒绝启用旧接口、隔离状态目录、偏好 API、重复实例复用、原生后端、用户遥测文件零读取的关闭保护状态、无真实信号及正常退出无监听器。测试镜像已卸载。

### 实际运行与边界

最终正常重启后，`dist/RegionGuard.app` 运行 PID **67466**、端口 **8765**，原偏好逐字节一致、原 CA 文件逐字节一致，未调用信任修改；上一构建备份在 `build/regionguard-before-3.5.0-20261128-000841/`。部署前确认无真实 Claude/Crashpad 进程；没有为测试启动或终止真实 Claude。

2026-11-28 **00:10 美东时间**核验：US / 公网 15 秒 / 网络与文件 100ms / 连接 500ms，自动保护开启、状态 safe，八组文件观察运行。原生库可加载，后台连接线程运行，采样已到 232 次且两个独立缓存请求之间继续增加；因当前无已验证 Claude 进程，证据状态为 `not_running`、读取后端尚未选择，不能声称当前真实客户端连接已经全覆盖。真实终止指令 0、待处理连接风险为空、HTTPS 状态 retired。真实 Safari 已核验当前表、样本增长和空闲提示；发布包 JS 与最终源码完全一致。

目的路由核验是 unscoped 最长前缀的配置证据，不是逐包实际出接口证明。SDK 的公开进程 socket 快照未可靠提供通用 socket 绑定接口，不猜测 IPv6 专用字段的意义，也不对其他进程调用 getsockopt。仍可能读不到完全落在采样间隔内或已结束的连接，未连接 UDP 的实际逐次目标、上传正文、未列来源、其他目录副本、独立 CLI 和服务端地区/账号决定不在完整覆盖承诺内；不保证首包前阻断或零泄漏。

证据：`build/native-connections-smoke.json`、`build/connection-protection-smoke.json`、当前 `build/artifact-watch-smoke.json`、`build/connections-guard-upgrade.json`、`build/connections-guard-live-check.json`、`dist/package-smoke-result.json`。当前操作与范围见 [保护说明](PROTECTION.md)，无解密边界见 [只读观察说明](TELEMETRY_FILTER.md)。
