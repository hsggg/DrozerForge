import sys
import os
import argparse
try:
    from defusedxml import ElementTree as ET # 防御 XXE 攻击
except ImportError:
    print("[!] 警告: 未安装 defusedxml，将使用原生 ET，可能存在 XML 解析安全风险。建议执行: pip install defusedxml")
    import xml.etree.ElementTree as ET

# 终端颜色代码
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = rf"""{Colors.CYAN}
    ____                                 ______                      
   / __ \_________  ____  ___  _____    / ____/___  _________ ____ 
  / / / / ___/ __ \/_  / / _ \/ ___/   / /_  / __ \/ ___/ __ `/ _ \
 / /_/ / /  / /_/ / / /_/  __/ /      / __/ / /_/ / /  / /_/ /  __/
/_____/_/   \____/ /___/\___/_/      /_/    \____/_/   \__, /\___/ 
                                                      /____/       
=====================================================================
  🎯 Android 自动化渗透测试指令生成 | 漏洞 Fuzz & 暴露面探测 v1.0
====================================================================={Colors.RESET}
    """
    print(banner)

def parse_android_manifest(xml_file):
    if not os.path.exists(xml_file):
        return None, f"未找到文件: {xml_file}，请检查路径是否正确！", None, None, None, None, None

    android_ns = "http://schemas.android.com/apk/res/android"
    ns = {'android': android_ns}
    
    attr_exported = f'{{{android_ns}}}exported'
    attr_name = f'{{{android_ns}}}name'
    attr_scheme = f'{{{android_ns}}}scheme'
    attr_host = f'{{{android_ns}}}host'
    attr_path = f'{{{android_ns}}}path'
    attr_pathPrefix = f'{{{android_ns}}}pathPrefix'
    attr_pathPattern = f'{{{android_ns}}}pathPattern'
    attr_permission = f'{{{android_ns}}}permission'
    attr_authorities = f'{{{android_ns}}}authorities'
    attr_allowBackup = f'{{{android_ns}}}allowBackup'
    attr_debuggable = f'{{{android_ns}}}debuggable'

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        package_name = root.get('package', 'com.unknown.package')
        
        target_sdk = 30
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            target_sdk = int(uses_sdk.get(f'{{{android_ns}}}targetSdkVersion', 30))

        app_node = root.find("application")
        if app_node is None:
            return None, "未找到 <application> 标签，XML 文件格式异常。", None, None, None, None, None

        security_configs = {
            "allowBackup": app_node.get(attr_allowBackup, "true").lower() == "true", 
            "debuggable": app_node.get(attr_debuggable, "false").lower() == "true"
        }
        
        explicit_activities, implicit_activities, main_activities = [], [], []
        dos_targets, provider_targets = [],[]

        def check_exported(node, comp_type=""):
            exported_val = node.get(attr_exported)
            intent_filters = node.findall("intent-filter")
            if comp_type == "provider" and exported_val is None:
                return target_sdk < 17, intent_filters
            if exported_val == "true": return True, intent_filters
            elif exported_val == "false": return False, intent_filters
            elif exported_val is None and len(intent_filters) > 0: return True, intent_filters
            return False, intent_filters

        # 1. 解析 Activity
        for activity in root.findall(".//activity") + root.findall(".//activity-alias"):
            name = activity.get(attr_name)
            if not name: continue
            is_exported, intent_filters = check_exported(activity)
            
            task_affinity = activity.get(f'{{{android_ns}}}taskAffinity')
            launch_mode = activity.get(f'{{{android_ns}}}launchMode')
            if is_exported and task_affinity and launch_mode in ["singleTask", "singleInstance"]:
                security_configs["task_hijacking"] = name

            if not is_exported: continue

            is_main = False
            for filter_node in intent_filters:
                actions =[a.get(attr_name) for a in filter_node.findall("action") if a.get(attr_name)]
                if "android.intent.action.MAIN" in actions:
                    is_main = True
                    break
            if is_main:
                main_activities.append(name)
                continue

            deep_links =[]
            for filter_node in intent_filters:
                for data in filter_node.findall("data"):
                    scheme = data.get(attr_scheme)
                    if scheme:
                        path = data.get(attr_path) or data.get(attr_pathPrefix) or data.get(attr_pathPattern)
                        deep_links.append({"scheme": scheme, "host": data.get(attr_host), "path": path})

            if deep_links:
                implicit_activities.append({"name": name, "links": deep_links})
            else:
                permission = activity.get(attr_permission)
                explicit_activities.append({"name": name, "permission": permission})

        # 2. 解析 Service & Receiver
        for component in root.findall(".//service") + root.findall(".//receiver"):
            name = component.get(attr_name)
            if not name: continue
            comp_type = "service" if component.tag == "service" else "broadcast"
            is_exported, intent_filters = check_exported(component)
            permission = component.get(attr_permission)

            if permission and ("BIND_ACCESSIBILITY_SERVICE" in permission or "BIND_DEVICE_ADMIN" in permission):
                continue

            if is_exported:
                first_action = None
                for filter_node in intent_filters:
                    actions =[a.get(attr_name) for a in filter_node.findall("action") if a.get(attr_name)]
                    if actions:
                        first_action = actions[0]
                        break
                dos_targets.append({"name": name, "type": comp_type, "permission": permission, "action": first_action})

        # 3. 解析 Content Provider
        for provider in root.findall(".//provider"):
            is_exported, _ = check_exported(provider, comp_type="provider")
            permission = provider.get(attr_permission)
            authorities = provider.get(attr_authorities)
            
            grant_uri = provider.get(f'{{{android_ns}}}grantUriPermissions') == "true"
            grant_nodes = provider.findall("grant-uri-permission")
            has_grant = grant_uri or len(grant_nodes) > 0

            if authorities and (is_exported or has_grant):
                for auth in authorities.split(';'):
                    provider_targets.append({
                        "name": provider.get(attr_name), "authority": auth,
                        "permission": permission, "is_exported": is_exported, "has_grant": has_grant
                    })

        return package_name, explicit_activities, implicit_activities, main_activities, dos_targets, provider_targets, security_configs

    except Exception as e:
        return None, f"XML 解析错误: {e}", None, None, None, None, None

def print_results(package_name, explicit, implicit, main_acts, dos_targets, provider_targets, security_configs):
    print(f"\n{Colors.GREEN}[i] 已锁定目标包名: {package_name}{Colors.RESET}")

    print(f"\n{Colors.BOLD}[+] 1. 全局应用安全配置风险{Colors.RESET}")
    print("-" * 69)
    if security_configs.get("allowBackup"):
        print(f"🚨 {Colors.RED}[高危] 发现 allowBackup=\"true\"，可通过 ADB 备份窃取 App 敏感数据{Colors.RESET}")
        print(f"💻 测试命令: {Colors.CYAN}adb backup -f backup.ab -noapk {package_name}{Colors.RESET}")
    if security_configs.get("debuggable"):
        print(f"🚨 {Colors.RED}[严重] 发现 debuggable=\"true\"，App 处于完全可调试状态，存在极高风险！{Colors.RESET}")
    if security_configs.get("task_hijacking"):
        print(f"⚠️  {Colors.YELLOW}[中危] 发现 Activity 组合缺陷可能导致 StrandHogg 任务劫持: {security_configs['task_hijacking']}{Colors.RESET}")
    if not any(security_configs.values()):
        print(f"✅ {Colors.GREEN}全局安全配置未见明显异常。{Colors.RESET}")

    print(f"\n{Colors.BOLD}[+] 2. Activity 配置错误 (越权访问 / 页面绕过){Colors.RESET}")
    print("-" * 69)
    for act in explicit:
        perm_str = f"(受 {act['permission']} 保护)" if act['permission'] else f"{Colors.YELLOW}(无权限保护 🔓){Colors.RESET}"
        print(f"📄 Activity: {act['name']} {perm_str}")
        print(f"💻 测试命令: {Colors.CYAN}dz> run app.activity.start --component {package_name} {act['name']}{Colors.RESET}\n")

    print(f"\n{Colors.BOLD}[+] 3. DeepLink 与 WebView (任意 URL 跳转 / XSS / RCE){Colors.RESET}")
    print("-" * 69)
    for item in implicit:
        print(f"🔗 分发组件: {item['name']}")
        for link in item['links']:
            scheme = link['scheme']
            host = link['host'] if link['host'] else ""
            path = link['path'] if link['path'] else ""
            if path and not path.startswith('/'): path = '/' + path
            
            uri = f"{scheme}://{host}{path}?url=http://hacker.com"
            print(f"💻 测试命令: {Colors.CYAN}dz> run app.activity.start --action android.intent.action.VIEW --data-uri \"{uri}\"{Colors.RESET}")
        print("")

    print(f"\n{Colors.BOLD}[+] 4. Service/Receiver 暴露 (拒绝服务 DoS / 非法越权){Colors.RESET}")
    print("-" * 69)
    for comp in dos_targets:
        perm_str = f"权限保护: {comp['permission']}" if comp['permission'] else f"{Colors.YELLOW}无 🔓{Colors.RESET}"
        print(f"⚙️  {comp['type'].upper()}: {comp['name']} ({perm_str})")
        cmd_type = "app.service.start" if comp['type'] == "service" else "app.broadcast.send"
        
        print(f"💻 基础触发: {Colors.CYAN}dz> run {cmd_type} --component {package_name} {comp['name']}{Colors.RESET}")
        print(f"💣 {Colors.MAGENTA}DoS Fuzz: dz> run {cmd_type} --component {package_name} {comp['name']} --extra string testFuzz null{Colors.RESET}")
        
        if comp['action']:
            print(f"💻 隐式触发: {Colors.CYAN}dz> run {cmd_type} --action {comp['action']}{Colors.RESET}")
        print("")

    print(f"\n{Colors.BOLD}[+] 5. Content Provider 暴露 (SQL注入 / 目录遍历){Colors.RESET}")
    print("-" * 69)
    if not provider_targets:
        print("未发现高危暴露的 Content Provider。")
    for prov in provider_targets:
        print(f"🗄️  Provider: {prov['name']}")
        risk_tags = []
        if prov['is_exported']: risk_tags.append(f"{Colors.RED}Exported 🔓{Colors.RESET}")
        if prov['has_grant']: risk_tags.append(f"{Colors.YELLOW}GrantUriPermission(提权) ⚠️{Colors.RESET}")
        print(f"📌 Authority: {prov['authority']} | 风险: {' + '.join(risk_tags)}")
        
        auth = prov['authority']
        print(f"💻 列出 URI : {Colors.CYAN}dz> run scanner.provider.finduris -a {package_name}{Colors.RESET}")
        if prov['has_grant']:
            print(f"💻 物理遍历 : {Colors.RED}dz> run app.provider.read content://{auth}/../../../../../../../../etc/hosts{Colors.RESET}")
        print(f"💻 扫描遍历 : {Colors.CYAN}dz> run scanner.provider.traversal -a {package_name}{Colors.RESET}")
        print(f"💻 扫描注入 : {Colors.CYAN}dz> run scanner.provider.injection -a {package_name}{Colors.RESET}\n")

    print(f"{Colors.GREEN}=====================================================================")
    print(f"[i] 已智能过滤 {len(main_acts)} 个 MAIN 启动页组件。Enjoy Hack!")
    print(f"====================================================================={Colors.RESET}")

if __name__ == "__main__":
    print_banner()
    
    # 引入命令行参数解析
    parser = argparse.ArgumentParser(description="Android 自动化渗透测试指令锻造炉")
    parser.add_argument("-f", "--file", help="指定 AndroidManifest.xml 文件的路径", default="AndroidManifest.xml")
    args = parser.parse_args()
    
    pkg, exp, imp, mains, dos, provs, sec_configs = parse_android_manifest(args.file)
    
    if pkg is None:
        print(f"{Colors.RED}[!] {exp}{Colors.RESET}")
        sys.exit(1)
    else:
        print_results(pkg, exp, imp, mains, dos, provs, sec_configs)