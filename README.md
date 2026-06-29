# DrozerForge v3.3

Android 半自动交互渗透测试 — 输入 APK → 解析暴露面 → 生成 drozer 命令 → 联动执行 / 手动选发 → 导出报告

---

## 新功能 (v3.3)

- **半自动交互引擎** — `--interactive` 模式下逐条审查并决定是否发送，保留人工研判关口
- **漏洞关联逻辑修复** — Activity/Service/Receiver/Provider 与所属组件精确关联，消除误报
- **Payload 精简** — 每种漏洞类型仅保留最高效的 2-3 个 Payload，减少噪音
- **双引擎支持** — `--run` 全自动执行 + `--interactive` 半自动交互，灵活切换
- **直接解析 APK** — 无需手动提取 AndroidManifest，直接传入 `.apk` 文件
- **联动 drozer 自动执行** — `--run` 标志连接 drozer agent 逐条执行命令并捕获结果
- **报告导出** — `-o report.md` 或 `-o report.json` 输出可交付的测试报告
- **配置文件扫描** — 自动检测 APK 中硬编码的 WebView 调试端点、证书文件
- **多样化 DeepLink Payload** — XSS、LFI、Intent Scheme URL、SSRF 等 7 种载荷
- **StrandHogg 检测修复** — 记录所有可疑 Activity（不再只记录最后一个）
- **Windows 兼容** — 自动检测 cmd/PS 环境降级颜色输出，`--no-color` 手动禁用

---

## 安装

```bash
# 必需: drozer
pip install drozer

# 必需: APK 解析
pip install androguard

# 推荐: XXE 防护
pip install defusedxml
```

---

## 使用方法

```bash
# 基础: 只生成命令 (兼容 v1)
python DrozerForge.py -f target.apk

# 半自动交互模式: 逐条审核再执行 (推荐)
python DrozerForge.py -f target.apk --interactive

# 全自动联动 drozer 自动执行 + 报告
python DrozerForge.py -f target.apk --run -o test_result.md

# 输出 Markdown 报告
python DrozerForge.py -f target.apk -o report.md

# 静默模式 + JSON 输出 (CI/CD)
python DrozerForge.py -f target.apk --quiet --format json -o result.json

# 包含 DoS Fuzz 载荷
python DrozerForge.py -f target.apk --run --enable-dos
```

---

## 参数说明

| 参数 | 说明 |
|------|------|
| `-f, --file` | **必需**。APK 文件或反编译的 AndroidManifest.xml |
| `-o, --output` | 报告输出路径 (`.md` 或 `.json`) |
| `--format md\|json` | 显式指定报告格式 |
| `--run` | 联动 drozer 全自动执行生成的命令 |
| `--interactive` | 半自动交互模式：逐条审查命令，手动选发 (y/n/skip) |
| `--device <ID>` | 指定目标设备（默认自动选择） |
| `--server <HOST:PORT>` | drozer 服务器地址（默认 `127.0.0.1:31415`） |
| `--timeout <秒>` | 每条命令超时（默认 30 秒） |
| `--enable-dos` | 启用 DoS Fuzz 载荷（默认仅生成基础触发命令） |
| `--no-color` | 禁用终端颜色 |
| `--quiet` | 静默模式 |

---

## 检测能力

| 类别 | 检测项 |
|------|--------|
| **全局配置** | `debuggable` / `allowBackup` / StrandHogg 任务劫持 |
| **导出 Activity** | 无权限保护的越权访问 / 页面绕过 |
| **DeepLink / WebView** | Scheme/Host/Path 注入 (XSS/LFI/Intent URL/SSRF) |
| **Service / Receiver** | 非法触发 / DoS Fuzz (NullPointerException) |
| **Content Provider** | SQL 注入 / 目录遍历 (`../../etc/hosts`) |
| **配置文件** | WebView 远程调试端点 / 硬编码证书 / 密钥暴露 |

---

## 前置条件 (drozer 联动模式)

1. 手机通过 USB 连接，开启 USB 调试
2. 安装 drozer agent APK (`drozer-agent.apk`) 并在手机上启动
3. 执行端口转发: `adb forward tcp:31415 tcp:31415`
4. 确认连接: `drozer console connect`

---

## 免责声明

本工具仅供**合法授权的企业安全建设、渗透测试及教育学习**使用。使用者须自行承担因使用本工具产生的任何后果。

---

## License

MIT License
