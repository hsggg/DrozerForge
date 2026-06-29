#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DrozerForge v3.3 — Android 半自动交互渗透测试工作站
修复漏洞关联逻辑、精简 Payload、恢复全自动/半自动双引擎支持
"""

import sys
import os
import re
import json
import argparse
import zipfile
import time
import socket
from io import StringIO
from datetime import datetime

# ─── XML 解析 (XXE 防护) ───────────────────────────────────────────
try:
    from defusedxml import ElementTree as ET
except ImportError:
    print("[!] 建议安装 defusedxml 防御 XXE: pip install defusedxml")
    import xml.etree.ElementTree as ET


# ─── 终端颜色 (Windows 兼容) ───────────────────────────────────────
class Colors:
    RED = '\033[91m';       GREEN = '\033[92m'
    YELLOW = '\033[93m';    BLUE = '\033[94m'
    MAGENTA = '\033[95m';   CYAN = '\033[96m'
    RESET = '\033[0m';      BOLD = '\033[1m'

    _disabled = False

    @classmethod
    def disable(cls):
        cls._disabled = True

    @classmethod
    def paint(cls, text, *codes):
        if cls._disabled: return text
        return f"{''.join(codes)}{text}{cls.RESET}"


# ─── 载荷模板 ───────────────────────────────────────────────────────
class Payloads:
    # 针对自定义协议 (scheme != http/https) 的 Fuzz
    DEEPLINK = [
        ("钓鱼/任意跳转", "https://www.4399.com/"),
        ("Intent Scheme 注入", "intent://evil/#Intent;scheme=https;package={pkg};end"),
        ("文件协议测试", "file:///etc/hosts"),
        ("电话协议测试", "tel://10086"),
    ]
    # 针对 HTTP/HTTPS 协议的 Fuzz
    HTTP_DEEPLINK = [
        ("钓鱼/任意跳转", "https://www.4399.com/"),
        ("XSS/JS注入", "javascript:prompt('DrozerForge_XSS_Test')"),
    ]
    PROVIDER_TRAVERSAL = "../../../../../../../../etc/hosts"


# ─── Manifest 解析器 ────────────────────────────────────────────────
class ManifestParser:
    ANDROID_NS = "http://schemas.android.com/apk/res/android"

    def __init__(self, filepath):
        self.filepath = filepath
        self.ns = {'android': self.ANDROID_NS}
        self._attrs = self._build_attr_map()

    def _build_attr_map(self):
        a = self.ANDROID_NS
        return {
            'exported': f'{{{a}}}exported', 'name': f'{{{a}}}name',
            'scheme': f'{{{a}}}scheme', 'host': f'{{{a}}}host',
            'path': f'{{{a}}}path', 'pathPrefix': f'{{{a}}}pathPrefix', 'pathPattern': f'{{{a}}}pathPattern',
            'permission': f'{{{a}}}permission', 'authorities': f'{{{a}}}authorities',
            'allowBackup': f'{{{a}}}allowBackup', 'debuggable': f'{{{a}}}debuggable',
            'taskAffinity': f'{{{a}}}taskAffinity', 'launchMode': f'{{{a}}}launchMode',
            'grantUriPerm': f'{{{a}}}grantUriPermissions', 'targetSdk': f'{{{a}}}targetSdkVersion',
        }

    def _a(self, key):
        return self._attrs[key]

    def parse(self):
        if not os.path.exists(self.filepath):
            return None, f"文件不存在: {self.filepath}"
        xml_text = self._load_xml_text()
        if xml_text is None:
            return None, f"无法解析: {self.filepath} (既非 APK 也非有效 XML)"
        return self._parse_xml(xml_text)

    def _load_xml_text(self):
        if zipfile.is_zipfile(self.filepath):
            try: return self._decode_apk_manifest()
            except Exception: pass 
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception: return None

    def _decode_apk_manifest(self):
        try: from androguard.core.axml import AXMLPrinter
        except ImportError: raise RuntimeError("需要 androguard 库来解析 APK。安装: pip install androguard")

        with zipfile.ZipFile(self.filepath, 'r') as z:
            if 'AndroidManifest.xml' not in z.namelist(): raise ValueError("APK 中缺少 AndroidManifest.xml")
            raw = z.read('AndroidManifest.xml')

        stderr_fd = sys.stderr.fileno()
        with open(os.devnull, 'w') as devnull:
            old_stderr = os.dup(stderr_fd)
            try:
                os.dup2(devnull.fileno(), stderr_fd)
                axml = AXMLPrinter(raw)
                xml_bytes = axml.get_buff()
            finally:
                os.dup2(old_stderr, stderr_fd)
                os.close(old_stderr)
        return xml_bytes.decode('utf-8', errors='ignore') if isinstance(xml_bytes, bytes) else xml_bytes

    def _parse_xml(self, xml_text):
        try: root = ET.fromstring(xml_text)
        except ET.ParseError as e: return None, f"XML 解析错误: {e}"
        except Exception as e: return None, f"解析异常: {e}"

        pkg = root.get('package', 'com.unknown.package')
        target_sdk = int(root.find("uses-sdk").get(self._a('targetSdk'), '30')) if root.find("uses-sdk") is not None else 30
        app = root.find("application")
        if app is None: return None, "未找到 <application> 标签"

        sec = {
            "allowBackup": app.get(self._a('allowBackup'), 'true').lower() == 'true',
            "debuggable": app.get(self._a('debuggable'), 'false').lower() == 'true',
            "task_hijackings": [],
        }

        explicit_activities, implicit_activities, main_activities = [], [], []
        dos_targets, provider_targets, webview_debug_findings = [], [], []

        def check_exported(node, comp_type=""):
            exported_val = node.get(self._a('exported'))
            intent_filters = node.findall("intent-filter")
            if comp_type == "provider" and exported_val is None: return target_sdk < 17, intent_filters
            if exported_val == "true": return True, intent_filters
            if exported_val == "false": return False, intent_filters
            if exported_val is None and len(intent_filters) > 0: return True, intent_filters
            return False, intent_filters

        for act in root.findall(".//activity") + root.findall(".//activity-alias"):
            name = act.get(self._a('name'))
            if not name: continue
            is_exported, intent_filters = check_exported(act)

            task_aff, launch = act.get(self._a('taskAffinity')), act.get(self._a('launchMode'), '')
            if is_exported and task_aff and launch in ('singleTask', 'singleInstance'):
                sec["task_hijackings"].append({"name": name, "taskAffinity": task_aff, "launchMode": launch})

            if not is_exported: continue

            is_main = any("android.intent.action.MAIN" in [a.get(self._a('name')) for a in f_node.findall("action")] for f_node in intent_filters)
            if is_main:
                main_activities.append(name)
                continue

            deep_links = []
            for f_node in intent_filters:
                for data in f_node.findall("data"):
                    scheme = data.get(self._a('scheme'))
                    if scheme:
                        deep_links.append({"scheme": scheme, "host": data.get(self._a('host')), "path": data.get(self._a('path')) or data.get(self._a('pathPrefix')) or data.get(self._a('pathPattern'))})
            if deep_links: implicit_activities.append({"name": name, "links": deep_links})
            else: explicit_activities.append({"name": name, "permission": act.get(self._a('permission'))})

        for comp in root.findall(".//service") + root.findall(".//receiver"):
            name = comp.get(self._a('name'))
            if not name: continue
            is_exported, intent_filters = check_exported(comp)
            permission = comp.get(self._a('permission'))
            if permission and any(p in permission for p in ("BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN")): continue
            if is_exported:
                first_action = next((a.get(self._a('name')) for f in intent_filters for a in f.findall("action") if a.get(self._a('name'))), None)
                dos_targets.append({"name": name, "type": "service" if comp.tag == "service" else "broadcast", "permission": permission, "action": first_action})

        for prov in root.findall(".//provider"):
            is_exported, _ = check_exported(prov, comp_type="provider")
            permission, authorities = prov.get(self._a('permission')), prov.get(self._a('authorities'))
            has_grant = prov.get(self._a('grantUriPerm')) == "true" or len(prov.findall("grant-uri-permission")) > 0
            if authorities and (is_exported or has_grant):
                for auth in authorities.split(';'):
                    provider_targets.append({"name": prov.get(self._a('name')), "authority": auth.strip(), "permission": permission, "is_exported": is_exported, "has_grant": has_grant})

        if zipfile.is_zipfile(self.filepath):
            with zipfile.ZipFile(self.filepath, 'r') as z:
                if 'assets/config/custom_config.json' in z.namelist():
                    try:
                        for item in json.loads(z.read('assets/config/custom_config.json')):
                            if 'remote_debug' in str(item.get('key', '')):
                                webview_debug_findings.append({"file": "assets/config/custom_config.json", "key": item['key'], "value": item['value']})
                    except Exception: pass
                for cf in [n for n in z.namelist() if any(n.lower().endswith(ext) for ext in ('.crt', '.pem', '.p12', '.jks')) and n.startswith('assets/')][:10]:
                    webview_debug_findings.append({"file": cf, "key": "hardcoded_cert", "value": "证书文件打包在 APK 中"})

        return {
            "package": pkg, "target_sdk": target_sdk, "security": sec,
            "explicit_activities": explicit_activities, "implicit_activities": implicit_activities,
            "main_activities": main_activities, "dos_targets": dos_targets,
            "provider_targets": provider_targets, "webview_findings": webview_debug_findings,
        }


# ─── 安全分析器 ─────────────────────────────────────────────────────
class SecurityAnalyzer:
    @staticmethod
    def analyze(data):
        findings = []
        sec = data["security"]
        if sec.get("debuggable"): findings.append({"category": "global", "severity": "CRITICAL", "title": "debuggable=true", "desc": "应用处于完全可调试状态"})
        if sec.get("allowBackup"): findings.append({"category": "global", "severity": "HIGH", "title": "allowBackup=true", "desc": "可通过 ADB 备份窃取应用数据"})
        for tj in sec.get("task_hijackings", []): findings.append({"category": "global", "severity": "MEDIUM", "title": f"StrandHogg 任务劫持: {tj['name']}", "desc": f"taskAffinity={tj['taskAffinity']} launchMode={tj['launchMode']}"})
        for act in data["explicit_activities"]: findings.append({"category": "activity", "severity": "MEDIUM" if act["permission"] else "HIGH", "title": f"导出 Activity: {act['name']}", "desc": f"受 {act['permission']} 保护" if act["permission"] else "无权限保护可越权访问"})
        for item in data["implicit_activities"]: findings.append({"category": "deeplink", "severity": "MEDIUM", "title": f"DeepLink 组件: {item['name']}", "desc": f"{len(item['links'])} 个 URI scheme 暴露"})
        for comp in data["dos_targets"]: findings.append({"category": "dos", "severity": "MEDIUM", "title": f"导出 {comp['type']}: {comp['name']}", "desc": "可被外部应用触发"})
        for prov in data["provider_targets"]: findings.append({"category": "provider", "severity": "HIGH" if prov["is_exported"] else "MEDIUM", "title": f"ContentProvider: {prov['name']}", "desc": f"authority={prov['authority']}"})
        for wf in data.get("webview_findings", []): findings.append({"category": "config", "severity": "HIGH", "title": f"敏感配置: {wf['file']}", "desc": f"{wf['key']} = {wf['value']}"})
        return findings


# ─── 风险评分计算器 ─────────────────────────────────────────────────
class RiskCalculator:
    WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "INFO": 0}
    GRADE_THRESHOLDS = [(0, "A", "安全", "PASS"), (1, "B", "低风险", "PASS"),
                        (6, "C", "中风险", "WARNING"), (16, "D", "高风险", "FAIL"), (31, "F", "严重风险", "FAIL")]

    @classmethod
    def calculate(cls, findings):
        counts, score = {}, 0
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            score += cls.WEIGHTS.get(f["severity"], 0)

        grade, grade_label, verdict = "A", "安全", "PASS"
        for min_score, g, label, v in cls.GRADE_THRESHOLDS:
            if score >= min_score: grade, grade_label, verdict = g, label, v

        score_detail = [{"severity": sev, "count": counts[sev], "weight": cls.WEIGHTS[sev], "subtotal": counts[sev] * cls.WEIGHTS[sev]} 
                        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO") if counts.get(sev, 0) > 0]
        return {"score": score, "grade": grade, "grade_label": grade_label, "verdict": verdict, "counts": counts, "total": len(findings), "score_detail": score_detail}


# ─── 命令生成器 ─────────────────────────────────────────────────────
class CommandGenerator:
    def __init__(self, data, enable_dos=False):
        self.pkg = data["package"]
        self.data = data
        self.enable_dos = enable_dos
        self.commands = []

    def generate(self):
        cmds = []
        seen = set()

        # [修复点5]：将组件名(comp_name)直接绑定到元组中，防止后续关联漏洞时误匹配
        def _add(cat, sev, desc, cmd, exec_type="drozer", comp_name=""):
            if cmd not in seen:
                seen.add(cmd)
                cmds.append((cat, sev, desc, cmd, exec_type, comp_name))

        sec = self.data["security"]
        if sec.get("allowBackup"): _add("global", "HIGH", "ADB 备份测试", f"adb backup -f backup.ab -noapk {self.pkg}", "adb", "allowBackup")
        if sec.get("debuggable"): _add("global", "CRITICAL", "ADB 调试检查", f"adb shell run-as {self.pkg}", "adb", "debuggable")

        for act in self.data["explicit_activities"]:
            cname = act['name']
            cmd = f"run app.activity.start --component {self.pkg} {cname}"
            _add("activity", "HIGH" if not act["permission"] else "MEDIUM", f"越权启动 {cname}", cmd, "drozer", cname)

        for item in self.data["implicit_activities"]:
            cname = item['name']
            for link in item["links"]:
                scheme, host, path = link['scheme'], link['host'] or "", link['path'] or ""
                if path and not path.startswith('/'): path = '/' + path
                base_uri = f"{scheme}://{host}{path}"

                # [修复点1 & 2]：完整遍历对应的载荷库
                if scheme in ('http', 'https'):
                    for label, test_url in Payloads.HTTP_DEEPLINK:
                        cmd = f'run app.activity.start --action android.intent.action.VIEW --data-uri "{test_url}"'
                        _add("deeplink", "MEDIUM" if "javascript" not in test_url else "HIGH", f"[{label}] {cname}", cmd, "drozer", cname)
                else:
                    cmd = f'run app.activity.start --action android.intent.action.VIEW --data-uri "{base_uri}"'
                    _add("deeplink", "MEDIUM", f"[基础触发] {cname}", cmd, "drozer", cname)
                    
                    for label, uri_tmpl in Payloads.DEEPLINK:
                        payload = uri_tmpl.format(pkg=self.pkg) if '{pkg}' in uri_tmpl else uri_tmpl
                        uri = payload if scheme in ('file', 'javascript', 'intent') else f"{base_uri}?url={payload}"
                        cmd = f'run app.activity.start --action android.intent.action.VIEW --data-uri "{uri}"'
                        _add("deeplink", "MEDIUM", f"[{label}] {cname}", cmd, "drozer", cname)

        for comp in self.data["dos_targets"]:
            cname = comp['name']
            cmd_type = "app.service.start" if comp["type"] == "service" else "app.broadcast.send"
            cmd = f"run {cmd_type} --component {self.pkg} {cname}"
            _add("dos", "MEDIUM", f"触发 {comp['type']}: {cname}", cmd, "drozer", cname)
            if self.enable_dos:
                _add("dos", "MEDIUM", f"[DoS Fuzz] {cname}", f"run {cmd_type} --component {self.pkg} {cname} --extra string testFuzz null", "drozer", cname)
            if comp.get("action"):
                _add("dos", "INFO", f"隐式触发 {cname}", f"run {cmd_type} --action {comp['action']}", "drozer", cname)

        for prov in self.data["provider_targets"]:
            auth, cname = prov["authority"], prov["name"]
            _add("provider", "HIGH" if prov["is_exported"] else "MEDIUM", f"URI 枚举: {cname}", f"run scanner.provider.finduris -a {self.pkg} --authority {auth}", "scanner", cname)
            _add("provider", "HIGH" if prov["is_exported"] else "MEDIUM", f"目录遍历: {cname}", f"run app.provider.read content://{auth}/{Payloads.PROVIDER_TRAVERSAL}", "drozer", cname)
            _add("provider", "MEDIUM", f"SQL 注入扫描: {cname}", f"run scanner.provider.injection -a {self.pkg} --authority {auth}", "scanner", cname)

        self.commands = cmds
        return cmds


# ─── Drozer 执行器 ──────────────────────────────────────────────────
class DrozerExecutor:
    def __init__(self, target_pkg, device=None, server="127.0.0.1:31415", timeout=6, no_color=True):
        self.target_pkg = target_pkg
        self.device = device
        self.server = server
        self.timeout = timeout
        self.no_color = no_color
        self.session = None
        self._server_conn = None
        self._disable_drozer_logging()

    def _disable_drozer_logging(self):
        try:
            from loguru import logger
            logger.disable("drozer")
            logger.configure(handlers=[{"sink": sys.stderr, "level": "ERROR"}])
        except ImportError: pass

    def connect(self):
        try:
            import subprocess as _sp
            _sp.run(['adb', 'forward', 'tcp:31415', 'tcp:31415'], capture_output=True, timeout=5)
        except Exception: pass

        try:
            from drozer.connector import ServerConnector
            from drozer.console.session import Session
            from argparse import Namespace
        except ImportError: raise RuntimeError("需要 drozer 库。安装: pip install drozer")

        args = Namespace(server=self.server, ssl=False, accept_certificate=False, password=False, debug=False, no_color=self.no_color, onecmd=None, file=[], device=self.device, push_variables=[])
        self._server_conn = ServerConnector(args, lambda p, c, p2: None)
        device_list = self._server_conn.listDevices().system_response.devices
        if not device_list: raise RuntimeError("未发现 drozer 设备。请确认 agent 已启动。")

        device_id = self.device or device_list[0].id
        sr = self._server_conn.startSession(device_id, password=None).system_response
        if sr.status == 2: raise RuntimeError(f"启动会话失败: {sr.error_message}")

        self.session = Session(self._server_conn, sr.session_id, args)
        self._apply_socket_timeout()
        return device_id

    def _apply_socket_timeout(self):
        try:
            if self._server_conn and hasattr(self._server_conn, 'connection'):
                conn = self._server_conn.connection
                if hasattr(conn, 'transport') and conn.transport and hasattr(conn.transport, 'socket') and conn.transport.socket:
                    conn.transport.socket.settimeout(float(self.timeout))
        except Exception: pass

    def _diagnose_android_block(self):
        import subprocess as _sp
        diagnostics = ["\n" + "="*30 + " 异常现场诊断分析 " + "="*30]
        try:
            res = _sp.run(['adb', 'shell', 'dumpsys', 'window', 'displays'], capture_output=True, text=True, timeout=3)
            focus_lines = [line.strip() for line in res.stdout.splitlines() if "mCurrentFocus" in line or "mFocusedApp" in line]
            if focus_lines:
                diagnostics.append(f"[焦点诊断] 当前屏幕焦点: {'; '.join(focus_lines)}")
                focus_str = "".join(focus_lines).lower()
                if "resolveractivity" in focus_str or "chooseractivity" in focus_str: diagnostics.append("[原因判定] 🔴 卡在系统应用选择弹窗！")
                elif "permissiongrantactivity" in focus_str: diagnostics.append("[原因判定] 🔴 卡在系统动态权限申请弹窗！")
                elif "browser" in focus_str or "chrome" in focus_str: diagnostics.append("[原因判定] 🟡 已跳转至外部浏览器。")
        except Exception: pass
        try:
            logcat_res = _sp.run(['adb', 'logcat', '-d', '-t', '25', '*:W'], capture_output=True, text=True, timeout=3)
            if logcat_res.stdout.strip():
                diagnostics.append("[Logcat 异常报警]:")
                for line in logcat_res.stdout.splitlines():
                    if any(x in line for x in ["Exception", "Error", "ActivityManager", "ANR"]): diagnostics.append(f"  | {line}")
        except Exception: pass
        diagnostics.append("="*76 + "\n")
        return "\n".join(diagnostics)

    def execute(self, command, suppress_timeout_log=True):
        if not self.session: return False, "未连接到 drozer 会话"
        captured = StringIO()
        old_stdout = self.session.stdout
        self.session.stdout = captured
        self._apply_socket_timeout()
        success, output, is_timeout = True, "", False

        try:
            self.session.onecmd(command)
            output = captured.getvalue()
        except (socket.timeout, TimeoutError):
            is_timeout, success, output = True, False, f"TIMEOUT ({self.timeout}s)"
        except Exception as e:
            err_str = str(e)
            if "timeout" in err_str.lower() or "10060" in err_str:
                is_timeout, success, output = True, False, f"TIMEOUT ({self.timeout}s)"
            else: success, output = False, f"[ERROR] {err_str[:200]}"
        finally: self.session.stdout = old_stdout

        if "Exception occured" in output and any(x in output.lower() for x in ("timeout", "10038", "10054", "10060")):
            is_timeout, success = True, False

        if is_timeout:
            diagnosis_report = self._diagnose_android_block()
            if not suppress_timeout_log: print(f"\n{Colors.RED}[!] 命令执行超时! APP 组件已卡死 (ANR)。正在自动重置环境...{Colors.RESET}")
            output = f"TIMEOUT ({self.timeout}s)\n{diagnosis_report}"
            self.reconnect(quiet=suppress_timeout_log)
        return success, output

    def reconnect(self, quiet=False):
        if not quiet: print(f"{Colors.YELLOW}[*] 正在强杀【目标APP】和【Drozer Agent】以释放系统死锁...{Colors.RESET}")
        self.disconnect()
        try:
            import subprocess as _sp
            _sp.run(['adb', 'shell', 'am', 'force-stop', self.target_pkg], capture_output=True, timeout=5)
            _sp.run(['adb', 'shell', 'am', 'force-stop', 'com.mwr.dz'], capture_output=True, timeout=5)
            time.sleep(1.0)
            _sp.run(['adb', 'shell', 'am', 'startservice', '-n', 'com.mwr.dz/.services.ServerService', '-c', 'com.mwr.dz.START_EMBEDDED'], capture_output=True, timeout=5)
            _sp.run(['adb', 'shell', 'am', 'start-foreground-service', '-n', 'com.mwr.dz/.services.ServerService', '-c', 'com.mwr.dz.START_EMBEDDED'], capture_output=True, timeout=5)
            _sp.run(['adb', 'shell', 'am', 'start', '-n', 'com.mwr.dz/.activities.MainActivity'], capture_output=True, timeout=5)
            time.sleep(2.0)
            _sp.run(['adb', 'forward', 'tcp:31415', 'tcp:31415'], capture_output=True, timeout=5)
        except Exception: pass
        try:
            time.sleep(1.0)
            self.connect()
            if not quiet: print(f"{Colors.GREEN}[+] Drozer 会话重连成功，环境已恢复！{Colors.RESET}")
        except Exception as e:
            if not quiet: print(f"{Colors.RED}[!] 重连失败: {e}{Colors.RESET}")

    def disconnect(self):
        if self.session:
            try: self.session.do_exit("")
            except Exception: pass
            self.session = None
        if self._server_conn:
            try: self._server_conn.close()
            except Exception: pass
            self._server_conn = None


# ─── Drozer 结果解释器 ──────────────────────────────────────────────
class ResultInterpreter:
    VERIFIED = "verified"
    BLOCKED = "blocked"
    BENIGN = "benign"
    EMPTY = "empty"
    ERROR = "error"

    BLOCKED_SIGNATURES = [
        "Permission Denial", "Not allowed to start service", "without permission", "java.lang.SecurityException",
        "Permission denied", "is not exported", "cannot be launched", "not permitted", "Not allowed to bind",
        "does not have permission", "Missing permission", "Access denied",
    ]

    SDK_CALLBACK_PATTERNS = [
        r'\.wxapi\.(WXEntryActivity|WXPayEntryActivity)$', r'\.alipay\.sdk\.', r'\.mipush\.', r'\.mob\.(id|guard|com\.mob)',
        r'\.weibo\.sdk\.', r'\.wechat\.sdk\.', r'\.tencent\.connect\.', r'\.huawei\.(push|hms)', r'\.(com)\.(oppo|oplus|heytap)\.push',
        r'\.vivo\.push', r'\.honor\.push', r'\.(alipay|alibaba|taobao)\.', r'\.unionpay\.', r'\.(igexin|getui)\.',
        r'\.(umeng|ccix)\.', r'\.(baidu|bd)\.(push|location|map)', r'\.(firebase|google\.firebase|google\.android\.gms)\.',
        r'\.(share|pay|push)\.(.*Activity)$', r'(H5|WebView|Bridge).*(Activity)$', r'(Trans|Translucent|Trampoline).*(Activity)$',
        r'(Test|Debug|Demo).*(Activity)$',
    ]

    @classmethod
    def _check_sdk_callback(cls, command):
        import re as _re
        match = _re.search(r'--component\s+\S+\s+(\S+)', command)
        if not match: match = _re.search(r'--component\s+(\S+)', command)
        if not match: return False
        component = match.group(1)
        return any(_re.search(pattern, component) for pattern in cls.SDK_CALLBACK_PATTERNS)

    @classmethod
    def interpret(cls, category, command, success, output):
        output_clean = (output or "").strip()
        blocked_reason = next((sig for sig in cls.BLOCKED_SIGNATURES if sig.lower() in output_clean.lower()), None)
        if blocked_reason: return cls.BLOCKED, blocked_reason

        if category == "activity": return cls._interpret_activity(command, output_clean)
        elif category == "deeplink": return cls._interpret_deeplink(command, output_clean)
        elif category == "dos": return cls._interpret_dos(command, output_clean)
        elif category == "provider": return cls._interpret_provider(command, output_clean)
        elif category == "global": return cls._interpret_global(output_clean)
        return cls.EMPTY, "无法判定"

    @classmethod
    def _interpret_activity(cls, command, output):
        if "does not exist" in output.lower() or "unable to find" in output.lower(): return cls.ERROR, "组件不存在"
        if not output or output in ("No result", "Done", "Success"):
            if cls._check_sdk_callback(command): return cls.BENIGN, "SDK回调空壳，无实际危害"
            return cls.EMPTY, "组件已启动但无法自动确认危害"
        return cls.EMPTY, output[:80]

    @classmethod
    def _interpret_deeplink(cls, command, output):
        if "does not exist" in output.lower(): return cls.ERROR, "目标组件不存在"
        if not output or output in ("No result", "Done"):
            if cls._check_sdk_callback(command): return cls.BENIGN, "SDK回调组件，无实际危害"
            return cls.EMPTY, "组件已触发但无法确认URL是否被加载"
        return cls.EMPTY, output[:80]

    @classmethod
    def _interpret_dos(cls, command, output):
        if "does not exist" in output.lower(): return cls.ERROR, "组件不存在"
        if not output or output in ("No result", "Done"): return cls.EMPTY, "组件已触发但危害需人工确认"
        return cls.EMPTY, output[:80]

    @classmethod
    def _interpret_provider(cls, command, output):
        if "scanner.provider.injection" in command:
            if "Injection" in output or "Vulnerable" in output:
                if "not vulnerable" not in output.lower() and "no injection" not in output.lower(): return cls.VERIFIED, "SQL 注入确认"
            if "not vulnerable" in output.lower() or "No injection" in output.lower(): return cls.EMPTY, "未发现 SQL 注入"
            if not output: return cls.EMPTY, "注入扫描无返回"
        if "scanner.provider.finduris" in command:
            if "content://" in output or "Unable to" not in output:
                if output and "No content provider" not in output: return cls.VERIFIED, "Provider URI 可枚举"
            if not output: return cls.EMPTY, "URI 枚举无结果"
            if "No content provider" in output: return cls.ERROR, "Provider 不存在"
        if "app.provider.read" in command or "app.provider.query" in command:
            if output and len(output) > 10 and "unable" not in output.lower(): return cls.VERIFIED, "Provider 数据可读取"
            if not output or len(output) < 10: return cls.EMPTY, "无数据返回或读取失败"
        return cls.EMPTY, output[:80] if output else "无输出"

    @classmethod
    def _interpret_global(cls, output):
        if "backup" in output.lower() or output.startswith("Now unlock"): return cls.VERIFIED, "ADB 备份可执行"
        if "run-as" in output and "not found" not in output.lower(): return cls.VERIFIED, "run-as 可执行 (应用可调试)"
        if not output: return cls.EMPTY, "ADB 命令无输出"
        return cls.EMPTY, output[:80]


# ─── 报告导出器 ─────────────────────────────────────────────────────
class ReportExporter:
    def __init__(self, data, findings, commands, exec_results=None, output_path=None, verdict=None,
                 exec_analysis=None, confirmed_verdict=None):
        self.data = data
        self.findings = findings
        self.commands = commands
        self.exec_results = exec_results or {}
        self.output_path = output_path
        self.verdict = verdict
        self.exec_analysis = exec_analysis or {}
        self.confirmed_verdict = confirmed_verdict or verdict or {}

    def export(self):
        if not self.output_path:
            pkg_name = re.sub(r'[^\w\-.]', '_', self.data["package"])
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_path = f"report_{pkg_name}_{ts}.html"

        ext = os.path.splitext(self.output_path)[1].lower()
        if ext == '.json': content = self._build_json()
        elif ext in ('.md', '.markdown'): content = self._build_markdown()
        else: content = self._build_html()

        with open(self.output_path, 'w', encoding='utf-8') as f: f.write(content)
        print(f"\n[+] 报告已保存: {self.output_path}")

    def _build_markdown(self):
        pkg = self.data["package"]
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = [
            f"# DrozerForge 渗透测试报告", "", f"| 项目 | 内容 |", f"|------|------|",
            f"| 目标包名 | `{pkg}` |", f"| targetSdk | {self.data['target_sdk']} |",
            f"| 扫描时间 | {now} |", f"| 总发现数 | {len(self.findings)} |", "", "---", "", "## 风险统计", ""
        ]
        from collections import Counter
        sev_count = Counter(f["severity"] for f in self.findings)
        lines.extend(["| 严重程度 | 数量 |", "|----------|------|"])
        for s in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            if sev_count.get(s, 0): lines.append(f"| {s} | {sev_count[s]} |")
        lines.append("")

        if self.verdict:
            v, cv = self.verdict, self.confirmed_verdict
            verdict_label = {"PASS": "通过 (PASS)", "WARNING": "需整改 (WARNING)", "FAIL": "不通过 (FAIL)"}
            lines.extend(["---", "", "## 安全判决", ""])
            if bool(self.exec_analysis) and cv:
                lines.extend([
                    "| 项目 | 静态分析 | drozer 确认 |", "|------|----------|-------------|",
                    f"| 风险评分 | {v['score']} 分 | **{cv['score']} 分** |",
                    f"| 安全等级 | {v['grade']} ({v['grade_label']}) | **{cv['grade']} ({cv['grade_label']})** |",
                    f"| 判决结果 | {verdict_label.get(v['verdict'], v['verdict'])} | **{verdict_label.get(cv['verdict'], cv['verdict'])}** |",
                    f"| 总发现数 | {v['total']} | **{cv['total']}** (确认可利用) |",
                ])
            else:
                lines.extend([
                    "| 项目 | 结果 |", "|------|------|",
                    f"| 风险评分 | **{v['score']}** 分 |", f"| 安全等级 | **{v['grade']}** ({v['grade_label']}) |",
                    f"| 判决结果 | **{verdict_label.get(v['verdict'], v['verdict'])}** |",
                ])
            lines.extend(["", "### 评分明细", "", "| 严重程度 | 数量 | 权重 | 得分 |", "|----------|------|------|------|"])
            for d in v["score_detail"]: lines.append(f"| {d['severity']} | {d['count']} | x{d['weight']} | {d['subtotal']} |")
            lines.append(f"| **合计** | **{v['total']}** | | **{v['score']}** |")
            lines.append("")

        categories = {"global": "## 1. 全局安全配置", "activity": "## 2. 导出 Activity", "deeplink": "## 3. DeepLink / WebView",
                      "dos": "## 4. Service / Receiver", "provider": "## 5. Content Provider", "config": "## 6. 敏感配置文件"}

        for cat, heading in categories.items():
            cat_findings = [f for f in self.findings if f["category"] == cat]
            # [修复点4]：Markdown 精简输出，利用 <details> 折叠杂项
            if not cat_findings: continue
            lines.extend([heading, ""])
            for f in cat_findings:
                lines.extend([f"### [{f['severity']}] {f['title']}", f"- {f['desc']}"])
                f_key = f["title"].split(": ", 1)[1] if ": " in f["title"] else f["title"]
                matching_cmds = [c for c in self.commands if c[0] == cat and c[5] == f_key]
                if matching_cmds:
                    lines.extend(["<details><summary><b>展开查看验证命令</b></summary>", ""])
                    for _, sev, desc, cmd, _, _ in matching_cmds:
                        status_icon = "🔹"
                        if cmd in self.exec_analysis:
                            st = self.exec_analysis[cmd].get("status", "")
                            if st == ResultInterpreter.VERIFIED: status_icon = "✅"
                            elif st == ResultInterpreter.BLOCKED: status_icon = "🛡️"
                            elif st in (ResultInterpreter.BENIGN, ResultInterpreter.EMPTY): status_icon = "⚪"
                            elif st == ResultInterpreter.ERROR: status_icon = "❌"
                        lines.append(f"- {status_icon} `{cmd}`")
                    lines.extend(["", "</details>"])
                lines.append("")

        lines.extend(["---", f"*报告由 DrozerForge v3.3 生成 | {now}*"])
        return "\n".join(lines)

    def _build_json(self):
        report = {
            "tool": "DrozerForge", "version": "3.3", "timestamp": datetime.now().isoformat(),
            "target": {"package": self.data["package"], "targetSdk": self.data["target_sdk"]},
            "verdict": self.verdict if self.verdict else {}, "findings": self.findings,
            "commands": [{"category": c[0], "severity": c[1], "description": c[2], "command": c[3], "exec_type": c[4], "component": c[5]} for c in self.commands],
        }
        if self.exec_results:
            report["execution_results"] = {cmd: {"success": s, "output": o} for cmd, (s, o) in self.exec_results.items()}
        return json.dumps(report, ensure_ascii=False, indent=2)

    def _build_html(self):
        pkg = self.data["package"]
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        v = self.verdict or {}
        grade_colors = {"A": "#22c55e", "B": "#3b82f6", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
        sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "INFO": "#3b82f6"}
        grade_color = grade_colors.get(v.get("grade", "A"), "#6b7280")

        verdict_display = {"PASS": "通过 (PASS)", "WARNING": "需整改 (WARNING)", "FAIL": "不通过 (FAIL)"}.get(v.get("verdict", ""), "")

        score_detail_rows = "".join(f"<tr><td>{d['severity']}</td><td>{d['count']}</td><td>x{d['weight']}</td><td>{d['subtotal']}</td></tr>" for d in v.get("score_detail", []))
        findings_rows = "".join(f'<tr><td>{i+1}</td><td><span class="badge" style="background:{sev_colors.get(f["severity"], "#6b7280")}">{self._html_escape(f["severity"])}</span></td><td>{self._html_escape(f["category"])}</td><td>{self._html_escape(f["title"])}</td><td>{self._html_escape(f["desc"])}</td></tr>' for i, f in enumerate(self.findings))
        
        max_count = max(v.get("counts", {}).values()) if v.get("counts") else 1
        bar_chart = "".join(f'<div class="bar-row"><span class="bar-label">{sev}</span><div class="bar-track"><div class="bar-fill" style="width:{(v.get("counts", {}).get(sev, 0)/max_count*100) if max_count>0 else 0}%;background:{sev_colors[sev]}"></div></div><span class="bar-count">{v.get("counts", {}).get(sev, 0)}</span></div>' for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO") if v.get("counts", {}).get(sev, 0) > 0)
        
        pie_gradient = "#e5e7eb 0% 100%"
        if v.get("total", 0) > 0:
            pie_segments, cumulative = [], 0
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
                c = v.get("counts", {}).get(sev, 0)
                if c > 0:
                    pct = c / v["total"] * 100
                    pie_segments.append(f"{sev_colors[sev]} {cumulative:.1f}% {cumulative + pct:.1f}%")
                    cumulative += pct
            if pie_segments: pie_gradient = ", ".join(pie_segments)

        cmd_sections = ""
        for cat, heading in [("global", "全局安全配置"), ("activity", "导出 Activity"), ("deeplink", "DeepLink / WebView"), ("dos", "Service / Receiver"), ("provider", "Content Provider"), ("config", "敏感配置文件")]:
            cat_cmds = [c for c in self.commands if c[0] == cat]
            if not cat_cmds: continue
            cmd_sections += f'<h3>{heading}</h3><ul class="cmd-list">'
            for _, sev, desc, cmd, _, _ in cat_cmds[:20]:
                exc_html = ""
                if cmd in self.exec_results:
                    success, output = self.exec_results[cmd]
                    exc_html = f'<details><summary>{"&#x2705;" if success else "&#x274C;"} 执行结果</summary><pre>{self._html_escape(output[:500])}</pre></details>'
                cmd_sections += f'<li><code>{self._html_escape(cmd)}</code> — <em>{self._html_escape(desc)}</em>{exc_html}</li>'
            cmd_sections += '</ul>'

        html = f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>DrozerForge 安全报告 - {self._html_escape(pkg)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }} body {{ font-family: -apple-system, sans-serif; background: #f8fafc; color: #1e293b; line-height:1.6; }}
.container {{ max-width: 960px; margin:0 auto; padding:24px 16px; }} .verdict-header {{ background: {grade_color}; color: #fff; border-radius: 12px; padding: 32px 24px; margin-bottom: 24px; text-align: center; }}
.verdict-header h1 {{ font-size: 1.8rem; margin-bottom: 4px; }} .verdict-header .subtitle {{ opacity: 0.9; font-size: 0.95rem; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: #fff; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.card .value {{ font-size: 2rem; font-weight: 700; color: {grade_color}; }} .card .label {{ font-size: 0.85rem; color: #64748b; margin-top: 4px; }}
.charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }} .panel {{ background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.panel h2 {{ font-size: 1.1rem; margin-bottom: 16px; color: #334155; }} .donut {{ width: 160px; height: 160px; margin: 0 auto; border-radius: 50%; background: conic-gradient({pie_gradient}); }}
.bar-row {{ display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }} .bar-label {{ width: 80px; font-size: 0.82rem; font-weight: 600; text-align: right; }}
.bar-track {{ flex:1; background: #e2e8f0; border-radius: 4px; height: 22px; overflow: hidden; }} .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
.bar-count {{ width: 30px; font-size: 0.85rem; font-weight: 600; text-align: right; }} .score-table {{ width: 100%; border-collapse: collapse; }}
.score-table th, .score-table td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; }} .score-table th {{ background: #f1f5f9; font-weight: 600; }}
.findings-table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }} .findings-table th {{ background: #1e293b; color: #fff; padding: 10px 8px; text-align: left; position: sticky; top: 0; }}
.findings-table td {{ padding: 8px; border-bottom: 1px solid #e2e8f0; }} .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: 600; white-space: nowrap; }}
.table-wrap {{ max-height: 500px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 8px; }} .cmd-list {{ list-style: none; padding-left: 0; }}
.cmd-list li {{ background: #f1f5f9; padding: 8px 12px; margin-bottom: 6px; border-radius: 6px; font-size: 0.85rem; }} .cmd-list code {{ background: #e2e8f0; padding: 1px 5px; border-radius: 3px; font-size: 0.82rem; word-break: break-all; }}
details {{ margin-top: 6px; }} details pre {{ background: #1e293b; color: #e2e8f0; padding: 10px; border-radius: 6px; font-size: 0.8rem; overflow-x: auto; max-height: 200px; }}
.footer {{ text-align: center; color: #94a3b8; font-size: 0.8rem; margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; }} h2 {{ margin-top: 24px; margin-bottom: 12px; }}
</style></head><body>
<div class="container">
  <div class="verdict-header"><h1>DrozerForge 安全判决报告</h1><div class="subtitle">目标: {self._html_escape(pkg)} | targetSdk: {self.data['target_sdk']} | {now}</div></div>
  <div class="cards"><div class="card"><div class="value">{v.get('score', 0)}</div><div class="label">风险评分</div></div><div class="card"><div class="value">{v.get('grade', 'A')}</div><div class="label">安全等级 ({v.get('grade_label', '安全')})</div></div><div class="card"><div class="value">{verdict_display}</div><div class="label">判决结果</div></div><div class="card"><div class="value">{v.get('total', 0)}</div><div class="label">总发现项</div></div></div>
  <div class="charts"><div class="panel"><h2>严重程度分布</h2><div class="donut" title="严重程度环形图"></div></div><div class="panel"><h2>风险数量对比</h2>{bar_chart if bar_chart else '<p style="color:#94a3b8;text-align:center;padding:20px;">无风险项</p>'}</div></div>
  <div class="panel" style="margin-bottom:24px"><h2>评分明细</h2><table class="score-table"><tr><th>严重程度</th><th>数量</th><th>权重</th><th>得分</th></tr>{score_detail_rows if score_detail_rows else '<tr><td colspan="4" style="color:#94a3b8">无风险项</td></tr>'}<tr style="font-weight:700"><td>合计</td><td>{v.get('total', 0)}</td><td></td><td>{v.get('score', 0)}</td></tr></table></div>
  <div class="panel" style="margin-bottom:24px"><h2>发现详情</h2><div class="table-wrap"><table class="findings-table"><tr><th>#</th><th>严重度</th><th>类别</th><th>标题</th><th>描述</th></tr>{findings_rows if findings_rows else '<tr><td colspan="5" style="color:#94a3b8">无安全发现</td></tr>'}</table></div></div>
  <div class="panel" style="margin-bottom:24px"><h2>测试命令</h2>{cmd_sections if cmd_sections else '<p style="color:#94a3b8">无命令生成</p>'}</div>
  <div class="footer"><p>报告由 DrozerForge v3.3 生成 | {now}</p></div>
</div></body></html>'''
        return html

    @staticmethod
    def _html_escape(text):
        if text is None: return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def print_banner():
    banner = rf"""{Colors.CYAN}
    ____                                 ______
   / __ \_________  ____  ___  _____    / ____/___  _________ ____
  / / / / ___/ __ \/_  / / _ \/ ___/   / /_  / __ \/ ___/ __ `/ _ \
 / /_/ / /  / /_/ / / /_/  __/ /      / __/ / /_/ / /  / /_/ /  __/
/_____/_/   \____/ /___/\___/_/      /_/    \____/_/   \__, /\___/
                                                      /____/
=====================================================================
  Android 半自动交互渗透测试工作站 | 漏洞发现 → 命令生成 → 联动执行 v3.3
====================================================================={Colors.RESET}
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="DrozerForge v3.3 — Android 半自动交互渗透测试工作站",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-f", "--file", required=True, help="APK 文件或 AndroidManifest.xml 文件")
    parser.add_argument("-i", "--interactive", action="store_true", help="联动 drozer 半自动交互执行 (scanner 自动解析、跳转类人工判定)")
    parser.add_argument("--device", help="指定目标设备 ID")
    args = parser.parse_args()

    if os.name == 'nt' and 'ANSICON' not in os.environ: Colors.disable()
    print_banner()

    socket.setdefaulttimeout(8.0)

    print(f"{Colors.BLUE}[*] 正在解析: {args.file}{Colors.RESET}")
    parser_obj = ManifestParser(args.file)
    result = parser_obj.parse()

    if isinstance(result, tuple):
        _, err = result
        print(f"{Colors.RED}[!] {err}{Colors.RESET}")
        sys.exit(1)

    data = result
    print(f"{Colors.GREEN}[+] 解析完成: {data['package']} (targetSdk={data['target_sdk']}){Colors.RESET}")

    findings = SecurityAnalyzer.analyze(data)
    verdict = RiskCalculator.calculate(findings)

    gen = CommandGenerator(data, enable_dos=False)
    commands = gen.generate()

    exec_results = {}
    exec_analysis = {}
    is_exec = args.interactive

    if is_exec:
        print(f"\n{Colors.MAGENTA}[*] 正在连接 drozer (127.0.0.1:31415)...{Colors.RESET}")
        executor = DrozerExecutor(
            target_pkg=data['package'],
            device=args.device, server="127.0.0.1:31415", timeout=8, no_color=True
        )
        try:
            device_id = executor.connect()
            print(f"{Colors.GREEN}[+] 已连接设备: {device_id}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] 半自动交互模式 — scanner 类命令自动解析，跳转类需人工判定。{Colors.RESET}")
            executor.device = device_id

            total = len(commands)
            verified_count, blocked_count, benign_count = 0, 0, 0

            for i, (cat, sev, desc, cmd, exec_type, comp_name) in enumerate(commands, 1):
                if "[DoS" in desc: continue

                if exec_type == "adb":
                    print(f"\n{Colors.CYAN}[{i}/{total}] {desc}{Colors.RESET}")
                    print(f"  {Colors.YELLOW}[手动执行] 非 drozer 命令，请在终端手动运行:{Colors.RESET}")
                    print(f"  {Colors.BLUE}$ {cmd}{Colors.RESET}")
                    exec_analysis[cmd] = {"status": ResultInterpreter.EMPTY, "reason": "需手动执行 ADB 命令", "output": ""}
                    continue

                if exec_type == "scanner":
                    print(f"\n{Colors.CYAN}[{i}/{total}] {desc}{Colors.RESET}")
                    print(f"  {Colors.BLUE}dz> {cmd}{Colors.RESET}")
                    success, output = executor.execute(cmd, suppress_timeout_log=True)
                    exec_results[cmd] = (success, output)
                    analysis_status, analysis_reason = ResultInterpreter.interpret(cat, cmd, success, output)
                    exec_analysis[cmd] = {"status": analysis_status, "reason": analysis_reason, "output": output[:500]}

                    tag_map = {
                        ResultInterpreter.VERIFIED: f"{Colors.RED}[已确认]{Colors.RESET}",
                        ResultInterpreter.BENIGN:   f"{Colors.MAGENTA}[无危害]{Colors.RESET}",
                        ResultInterpreter.BLOCKED:  f"{Colors.GREEN}[已阻断]{Colors.RESET}",
                        ResultInterpreter.EMPTY:    f"{Colors.CYAN}[无结果]{Colors.RESET}",
                        ResultInterpreter.ERROR:    f"{Colors.YELLOW}[错误]{Colors.RESET}",
                    }
                    tag = tag_map.get(analysis_status, "")
                    if analysis_status == ResultInterpreter.VERIFIED: verified_count += 1
                    elif analysis_status == ResultInterpreter.BENIGN: benign_count += 1
                    elif analysis_status == ResultInterpreter.BLOCKED: blocked_count += 1
                    print(f"  [{tag}] {analysis_reason}")
                    if output and output.strip() and "TIMEOUT" not in output:
                        print(f"  {output[:200]}{'...' if len(output) > 200 else ''}")
                    continue

                # 跳转类命令：半自动人工判定
                while True:
                    print(f"\n{Colors.CYAN}[{i}/{total}] {desc}{Colors.RESET}")
                    print(f"  {Colors.BLUE}dz> {cmd}{Colors.RESET}")

                    success, output = executor.execute(cmd, suppress_timeout_log=True)
                    exec_results[cmd] = (success, output)

                    if "TIMEOUT" in output:
                        print(f"  {Colors.YELLOW}[!] 命令下发引发 App 卡死或无响应。环境已通过后台自动重置。{Colors.RESET}")
                    elif output.strip():
                        print(f"  [输出] {output[:150]}{'...' if len(output) > 150 else ''}")

                    print(f"\n{Colors.MAGENTA}>>> [人工判定] 请观察手机屏幕确认利用结果: {Colors.RESET}")
                    print(f"  {Colors.RED}[y]{Colors.RESET} 成功 (App内打开网页/越权启动成功)")
                    print(f"  {Colors.GREEN}[n]{Colors.RESET} 无效 (跳转了外部浏览器/无反应/被SDK拦截回主页)")
                    print(f"  {Colors.YELLOW}[b]{Colors.RESET} 阻断 (弹出了权限拒绝 Permission Denial 报错)")
                    print(f"  {Colors.CYAN}[r]{Colors.RESET} 重发 (没看清屏幕，再把这条命令发一次)")
                    print(f"  {Colors.BLUE}[q]{Colors.RESET} 强杀 (手机死锁卡住了，帮我重启一下环境)")

                    choice = input(f"{Colors.BOLD}请输入 (y/n/b/r/q) [默认 n]: {Colors.RESET}").strip().lower()

                    if choice == 'y':
                        analysis_status, analysis_reason = ResultInterpreter.VERIFIED, "人工确认：漏洞可利用"
                        verified_count += 1
                        break
                    elif choice == 'b':
                        analysis_status, analysis_reason = ResultInterpreter.BLOCKED, "人工确认：已被安全机制阻断"
                        blocked_count += 1
                        break
                    elif choice == 'r':
                        print(f"{Colors.CYAN}[*] 正在重新发送该命令...{Colors.RESET}")
                        continue
                    elif choice == 'q':
                        executor.reconnect(quiet=False)
                        print(f"{Colors.CYAN}[*] 环境已重置。您可以选择输入 r 重新测试，或按 n 标记为无效。{Colors.RESET}")
                        continue
                    else:
                        analysis_status, analysis_reason = ResultInterpreter.BENIGN, "人工确认：无实际危害/未成功"
                        benign_count += 1
                        break

                exec_analysis[cmd] = {"status": analysis_status, "reason": analysis_reason, "output": output[:500]}
                print(f"  [{Colors.CYAN}已记录状态{Colors.RESET}] {analysis_reason}")

            print(f"\n{Colors.BOLD}[+] drozer 执行完毕: {Colors.RED}{verified_count} 确认{Colors.RESET}, "
                  f"{Colors.MAGENTA}{benign_count} 无效/空壳{Colors.RESET}, {Colors.GREEN}{blocked_count} 阻断{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.RED}[!] 执行错误/连接失败: {e}{Colors.RESET}")
        finally:
            executor.disconnect()

        # 严格全等匹配关联 finding 与命令 (c[5] == comp_name)
        confirmed_findings = []
        for f in findings:
            f_key = f["title"].split(": ", 1)[1] if ": " in f["title"] else f["title"]
            matching_cmds = [c for c in commands if c[0] == f["category"] and c[5] == f_key]
            if not matching_cmds:
                confirmed_findings.append(f)
                continue
            cmd_statuses = [exec_analysis.get(c[3], {}).get("status", "") for c in matching_cmds if c[3] in exec_analysis]
            if ResultInterpreter.VERIFIED in cmd_statuses or not cmd_statuses:
                confirmed_findings.append(f)

        confirmed_verdict = RiskCalculator.calculate(confirmed_findings)
    else:
        confirmed_findings = findings
        confirmed_verdict = verdict

    # 默认仅输出确认存在漏洞的项
    report_findings, report_verdict = confirmed_findings, confirmed_verdict
    if is_exec:
        verified_cmds_set = {cmd for cmd, a in exec_analysis.items() if a.get("status") == ResultInterpreter.VERIFIED}
        report_commands = [c for c in commands if c[3] in verified_cmds_set]
    else:
        report_commands = [c for c in commands if c[1] in ("CRITICAL", "HIGH")]

    exporter = ReportExporter(
        data, report_findings, report_commands, exec_results, None, report_verdict,
        exec_analysis=exec_analysis, confirmed_verdict=confirmed_verdict
    )
    exporter.export()

    # 控制台输出
    v, cv = verdict, confirmed_verdict
    gc = {"A": Colors.GREEN, "B": Colors.GREEN, "C": Colors.YELLOW, "D": Colors.RED, "F": Colors.RED}.get(v["grade"], Colors.CYAN)
    verdict_icons = {"PASS": "通过 (PASS)", "WARNING": "需整改 (WARNING)", "FAIL": "不通过 (FAIL)"}

    print(f"\n{Colors.BOLD}{'='*69}\n  {'安全风险判决结果':^61}\n{'='*69}{Colors.RESET}")
    if is_exec:
        c_gc = {"A": Colors.GREEN, "B": Colors.GREEN, "C": Colors.YELLOW, "D": Colors.RED, "F": Colors.RED}.get(cv["grade"], Colors.CYAN)
        print(f"  静态分析: {gc}{v['score']} 分 {v['grade']}级 {verdict_icons.get(v['verdict'], '')}{Colors.RESET}")
        print(f"  drozer确认: {c_gc}{cv['score']} 分 {cv['grade']}级 {verdict_icons.get(cv['verdict'], '')}{Colors.RESET}")
        print(f"  (已自动过滤掉阻断的误报及安全的 SDK 空壳)")
    else:
        print(f"  风险评分: {gc}{v['score']} 分{Colors.RESET}")
        print(f"  安全等级: {gc}{v['grade']} ({v['grade_label']}){Colors.RESET}")

    print(f"{'-'*69}")
    detail_parts = [f"{d['severity']}(x{d['weight']})={d['subtotal']}" for d in v["score_detail"]]
    print(f"  评分明细: {' + '.join(detail_parts)} = {v['score']}" if detail_parts else "  评分明细: 未发现风险项")
    print(f"{'='*69}{Colors.RESET}")

    print(f"\n{Colors.BOLD}{Colors.RED}{'='*69}")
    print(f"  🚨 确认存在安全问题的组件及一键利用命令汇总 ({len(confirmed_findings)} 项) 🚨")
    print(f"{'='*69}{Colors.RESET}")
    if not confirmed_findings:
        print(f"  {Colors.GREEN}🎉 恭喜！本次测试未发现确认可被利用的(安全风险/漏洞)。{Colors.RESET}")
    else:
        for idx, f in enumerate(confirmed_findings, 1):
            f_key = f["title"].split(": ", 1)[1] if ": " in f["title"] else f["title"]
            print(f"  {Colors.BOLD}[{idx}] [{f['severity']}] {f['title']}{Colors.RESET}")
            print(f"      漏洞描述: {f['desc']}")

            matching_cmds = [c for c in commands if c[0] == f["category"] and c[5] == f_key]
            has_matching = False
            for _, _, desc, cmd, *_ in matching_cmds:
                if is_exec:
                    if exec_analysis.get(cmd, {}).get("status", "") == ResultInterpreter.VERIFIED:
                        print(f"      一键复现: {Colors.CYAN}dz> {cmd}{Colors.RESET}")
                        has_matching = True
                else:
                    print(f"      测试命令: {Colors.CYAN}dz> {cmd}{Colors.RESET}")
                    has_matching = True
            if not has_matching:
                print(f"      一键复现: {Colors.YELLOW}(属于全局隐患，无法通过单一命令复现){Colors.RESET}")
            print(f"  {'-'*69}")
    print(f"{Colors.BOLD}{Colors.RED}{'='*69}{Colors.RESET}")

if __name__ == "__main__":
    main()