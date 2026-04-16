# DrozerForge



Android 自动化渗透测试指令生成，可解析 AndroidManifest文件并生成 Drozer 测试指令。

它通过解析 App 的 `AndroidManifest.xml` 文件，自动识别攻击暴露面，并输出可以直接在[Drozer](https://github.com/WithSecureLabs/drozer) 控制台中执行的Payload 测试指令。

 ## ✨ 核心特性 / Features 

- 🛡️ **全局安全风险扫描**：自动检测 `allowBackup`、`debuggable` 以及潜在的 `StrandHogg` 任务劫持风险。 

- 🔓 **越权漏洞自动化（Activity）**：提取未加权限保护的导出 Activity，一键生成页面绕过/越权访问测试命令。

-   🔗 **DeepLink 深度挖掘（WebView）**：智能提取 Scheme/Host/Path，一键生成带有恶意 URL 参数的测试链路，直击任意 URL 跳转与 XSS 漏洞。

-  💣 **拒绝服务 Fuzzing（Service/Receiver）**：不仅提供基础启动命令，更内置了针对空对象异常（NullPointerException）的 `DoS Fuzzing` 专属 Payload。

-  🗄️ **提权与数据泄露探测（Content Provider）**：精准识别 `Exported` 或拥有 `GrantUriPermission` 风险的 Provider，直接生成物理目录遍历（`../../etc/hosts`）和 SQL 注入探测命令。 

-  🧽 **高保真降噪**：自动过滤正常的 MAIN 启动页，聚焦真正具有潜在风险的组件。 

   快速开始 / Quick Start ### 依赖安装 建议安装 `defusedxml` 以防御恶意 AndroidManifest 文件可能带来的 XXE 攻击： ```bash pip install defusedxml

- ### 使用方法

  将需要测试的 APK 反编译（如使用 jadx），提取出 AndroidManifest.xml 文件。

  \# 默认读取当前目录下的 AndroidManifest.xml 

  python3 DrozerForge.py

   \# 或者通过 -f 参数指定文件路径 

  python3 DrozerForge.py -f /path/to/AndroidManifest.xml

  

## ⚠️ 免责声明 / Disclaimer

本工具仅供**合法授权的企业安全建设、渗透测试及教育学习使用**。请勿用于任何非法用途，因使用本工具导致的任何直接或间接后果，由使用者本人承担。