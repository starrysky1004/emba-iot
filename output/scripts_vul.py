#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Any

def get_python_error_description(error_code):
    """
    获取Python错误代码的中文描述
    
    Args:
        error_code (str): 错误代码
    
    Returns:
        str: 错误代码 + 中文描述
    """
    error_descriptions = {
        'B101': 'assert_used - 使用了assert语句',
        'B102': 'exec_used - 使用了exec函数',
        'B103': 'set_bad_file_permissions - 设置了不安全的文件权限',
        'B104': 'hardcoded_bind_all_interfaces - 硬编码绑定所有接口',
        'B105': 'hardcoded_password_string - 硬编码密码字符串',
        'B106': 'hardcoded_password_funcarg - 硬编码密码函数参数',
        'B107': 'hardcoded_password_default - 硬编码密码默认值',
        'B108': 'hardcoded_tmp_directory - 硬编码临时目录',
        'B109': 'password_config_option_not_marked_secret - 密码配置选项未标记为秘密',
        'B110': 'try_except_pass - try-except块中使用了pass',
        'B111': 'execute_with_run_as_root_equals_true - 以root权限执行',
        'B112': 'try_except_continue - try-except块中使用了continue',
        'B113': 'request_without_timeout - 请求没有超时设置',
        'B201': 'flask_debug_true - Flask调试模式开启',
        'B202': 'tarfile_unsafe_members - tarfile不安全的成员',
        'B301': 'blacklist - 使用了不安全的pickle',
        'B306': 'blacklist - 使用了不安全的mktemp',
        'B307': 'blacklist - 使用了不安全的eval',
        'B310': 'blacklist - 使用了不安全的marshal',
        'B311': 'blacklist - 使用了不安全的random',
        'B323': 'blacklist - 使用了不安全的unverified_context',
        'B324': 'hashlib - 使用了hashlib',
        'B403': 'blacklist - 使用了不安全的import',
        'B404': 'blacklist - 使用了不安全的importlib',
        'B501': 'request_with_no_cert_validation - 请求没有证书验证',
        'B502': 'ssl_with_bad_version - SSL使用了错误的版本',
        'B503': 'ssl_with_bad_defaults - SSL使用了错误的默认值',
        'B504': 'ssl_with_no_version - SSL没有指定版本',
        'B505': 'weak_cryptographic_key - 弱加密密钥',
        'B506': 'yaml_load - 使用了yaml.load',
        'B507': 'ssh_no_host_key_verification - SSH没有主机密钥验证',
        'B508': 'snmp_insecure_version - SNMP不安全版本',
        'B509': 'snmp_weak_cryptography - SNMP弱加密',
        'B601': 'paramiko_calls - 使用了paramiko调用',
        'B602': 'subprocess_popen_with_shell_equals_true - subprocess使用shell=True',
        'B603': 'subprocess_without_shell_equals_true - subprocess没有使用shell=True',
        'B604': 'any_other_function_with_shell_equals_true - 其他函数使用shell=True',
        'B605': 'start_process_with_a_shell - 使用shell启动进程',
        'B606': 'start_process_with_no_shell - 不使用shell启动进程',
        'B607': 'start_process_with_partial_path - 使用部分路径启动进程',
        'B608': 'hardcoded_sql_expressions - 硬编码SQL表达式',
        'B609': 'linux_commands_wildcard_injection - Linux命令通配符注入',
        'B610': 'django_extra_used - 使用了Django extra',
        'B611': 'django_rawsql_used - 使用了Django raw SQL',
        'B612': 'logging_config_insecure_listen - 日志配置不安全监听',
        'B613': 'trojansource - 特洛伊木马源代码',
        'B614': 'pytorch_load - 使用了PyTorch load',
        'B615': 'huggingface_unsafe_download - HuggingFace不安全下载',
        'B701': 'jinja2_autoescape_false - Jinja2自动转义关闭',
        'B702': 'use_of_mako_templates - 使用了Mako模板',
        'B703': 'django_mark_safe - Django标记为安全',
        'B704': 'markupsafe_markup_xss - MarkupSafe标记XSS'
    }
    
    return error_descriptions.get(error_code, f'{error_code} - 未知错误类型')

def get_php_cwe_description(cwe_code):
    """
    获取PHP CWE错误代码的中文描述
    
    Args:
        cwe_code (str): CWE错误代码或semgrep规则名称
    
    Returns:
        str: CWE错误代码 + 中文描述
    """
    cwe_descriptions = {
        'CWE_78': 'OS Command Injection - 操作系统命令注入',
        'CWE_79': 'Cross-site Scripting (XSS) - 跨站脚本攻击',
        'CWE_89': 'SQL Injection - SQL注入',
        'CWE_90': 'LDAP Injection - LDAP注入',
        'CWE_91': 'XML Injection - XML注入',
        'CWE_95': 'Code Injection - 代码注入',
        'CWE_98': 'PHP File Inclusion - PHP文件包含',
        'CWE_22': 'Path Traversal - 路径遍历',
        'CWE_384': 'Session Fixation - 会话固定',
        'CWE_601': 'URL Redirection to Untrusted Site - URL重定向到不可信站点',
        'CWE_1333': 'Regular Expression Denial of Service (ReDoS) - 正则表达式拒绝服务'
    }
    
    # semgrep 规则的中文描述
    semgrep_descriptions = {
        'external.semgrep-rules.php.lang.security.unlink-use': 'Unsafe File Deletion - 不安全的文件删除',
        'external.semgrep-rules.php.lang.security.unserialize-use': 'Unsafe Unserialize - 不安全的反序列化',
        'external.semgrep-rules.php.lang.security.weak-crypto': 'Weak Cryptography - 弱加密算法'
    }
    
    # 先检查 CWE 描述
    if cwe_code in cwe_descriptions:
        return cwe_descriptions[cwe_code]
    
    # 再检查 semgrep 规则描述
    if cwe_code in semgrep_descriptions:
        return semgrep_descriptions[cwe_code]
    
    return f'{cwe_code} - 未知漏洞类型'

def get_perl_error_description(error_code):
    """
    获取Perl错误代码的中文描述
    
    Args:
        error_code (str): Perl错误代码
    
    Returns:
        str: Perl错误代码 + 中文描述
    """
    perl_descriptions = {
        'Debug module enabled': 'Debug module enabled - 调试模块启用',
        'Code Injection': 'Code Injection - 代码注入',
        'Path Traversal': 'Path Traversal - 路径遍历',
        'Weak Criptography Algorithm': 'Weak Criptography Algorithm - 弱加密算法',
        'Weak Random Value Generator': 'Weak Random Value Generator - 弱随机值生成器',
        'Error Suppression': 'Error Suppression - 错误抑制',
        'Cross Site Scripting (XSS)': 'Cross Site Scripting (XSS) - 跨站脚本攻击',
        'Command Injection': 'Command Injection - 命令注入',
        'Connection String Injection': 'Connection String Injection - 连接字符串注入',
        'LDAP Injection': 'LDAP Injection - LDAP注入',
        'XSS': 'XSS - 跨站脚本攻击',
        'Remote File Inclusion': 'Remote File Inclusion - 远程文件包含',
        'Resource Injection': 'Resource Injection - 资源注入',
        'SQL Injection': 'SQL Injection - SQL注入'
    }
    
    return perl_descriptions.get(error_code, f'{error_code} - 未知漏洞类型')

def get_perl_error_message_description(error_code):
    """
    获取Perl错误消息的中文描述
    
    Args:
        error_code (str): Perl错误代码
    
    Returns:
        str: 中文描述
    """
    perl_message_descriptions = {
        'Debug module enabled': '调试模块可能暴露敏感信息并创建安全漏洞',
        'Code Injection': '当不受信任的数据作为代码执行时发生，允许攻击者在服务器上运行任意命令',
        'Path Traversal': '当用户输入未正确清理时发生，允许攻击者访问预期目录结构之外的文件和目录',
        'Weak Criptography Algorithm': 'MD5等弱算法容易受到各种攻击，应避免使用，转而使用更强的替代方案以确保敏感数据的安全',
        'Weak Random Value Generator': '弱随机值生成器可能导致可预测的值，攻击者可以利用这些值绕过安全控制',
        'Error Suppression': '抑制错误可能使识别和排除故障变得困难，可能导致安全漏洞',
        'Cross Site Scripting (XSS)': '当不受信任的数据在没有适当转义的情况下渲染为HTML时发生，允许攻击者在受害者浏览器的上下文中执行恶意脚本',
        'Command Injection': '当应用程序将不安全的用户提供数据（如表单值、cookie、HTTP头等）传递给系统shell时，可能发生命令注入攻击',
        'Connection String Injection': '当使用动态字符串连接构建基于用户输入的连接字符串时，可能发生连接字符串注入攻击',
        'LDAP Injection': 'LDAP注入是一种攻击，用于利用基于用户输入构建LDAP语句的基于Web的应用程序',
        'XSS': '跨站脚本攻击是一种注入类型，其中恶意脚本被注入到原本良性和可信的网站中',
        'Remote File Inclusion': '此漏洞允许攻击者包含文件，通常利用目标应用程序中实现的"动态文件包含"机制',
        'Resource Injection': '此攻击包括更改应用程序使用的资源标识符以执行恶意任务',
        'SQL Injection': 'SQL注入攻击包括通过客户端到应用程序的输入数据插入或"注入"SQL查询'
    }
    
    return perl_message_descriptions.get(error_code, '未知漏洞类型')

def remove_ansi_escape_codes(text):
    """
    移除文本中的ANSI颜色和格式控制字符
    
    Args:
        text (str): 包含ANSI控制字符的文本
    
    Returns:
        str: 清理后的文本
    """
    # ANSI控制字符的正则表达式模式
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)
    # 清理常见的颜色代码格式 [0m[31m[1m 等
    color_codes = re.compile(r'\[0;?\d*m|\[\d+m|\[0m')
    text = color_codes.sub('', text)
    return text.strip()

def extract_s21_python_check(base_dir):
    """
    提取 S21 Python 脚本检查结果
    
    Args:
        base_dir (str): 基础目录路径
    
    Returns:
        dict: Python 检查结果
    """
    s21_results = {
        'total_issues': 0,
        'issues': []
    }
    
    txt_file = os.path.join(base_dir, 's21_python_check.txt')
    folder_path = os.path.join(base_dir, 's21_python_check')
    
    if not os.path.exists(txt_file):
        # 文件不存在，跳过
        pass
        return s21_results
    
    try:
        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = remove_ansi_escape_codes(f.read())
            
            # 检查是否有发现问题
            if "nothing reported" in content:
                print("ℹ️  S21: 没有发现 Python 脚本问题")
                return s21_results
            
            # 提取Python文件和对应的bandit结果文件
            pattern = r'Found (\d+) issues in script.*?:\s*(.*?)\s*\(.*?\[REF\]\s*(.*?)\.txt'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for match in matches:
                issue_count, script_path, ref_file = match
                script_name = os.path.basename(script_path.strip())
                
                # 读取bandit详细结果
                detail_file = os.path.join(folder_path, f"{os.path.basename(ref_file)}.txt")
                if os.path.exists(detail_file):
                    with open(detail_file, 'r', encoding='utf-8', errors='ignore') as df:
                        detail_content = remove_ansi_escape_codes(df.read())
                        
                    # 解析bandit结果
                    issue_pattern = r'>> Issue: \[([^\]]+)\].*?Severity: (\w+).*?Confidence: (\w+).*?Location: [^:]+:(\d+):(\d+)(.*?)(?=--------------------------------------------------|\Z)'
                    issue_matches = re.findall(issue_pattern, detail_content, re.DOTALL)
                    
                    for issue_match in issue_matches:
                        error_code_full, severity, confidence, line_num, col_num, description = issue_match
                        # 提取错误代码的前半部分（如 B311:blacklist -> B311）
                        error_code = error_code_full.split(':')[0] if ':' in error_code_full else error_code_full
                        s21_results['issues'].append({
                            "file_name": script_name,
                            "line_number": int(line_num),
                            "column_number": int(col_num),
                            "error_code": f"{error_code_full} - {get_python_error_description(error_code).split(' - ')[1]}",
                            "error_message": description.strip(),
                            "severity": severity.lower(),
                            "confidence": confidence.lower()
                        })
            
            s21_results['total_issues'] = len(s21_results['issues'])
            
    except Exception as e:
        # 处理失败，跳过
        pass
    
    return s21_results

def extract_s22_php_check(base_dir):
    """
    提取 S22 PHP 脚本检查结果
    
    Args:
        base_dir (str): 基础目录路径
    
    Returns:
        dict: PHP 检查结果
    """
    s22_results = {
        'total_issues': 0,
        'progpilot_issues': 0,
        'issues': []
    }
    
    txt_file = os.path.join(base_dir, 's22_php_check.txt')
    folder_path = os.path.join(base_dir, 's22_php_check')
    
    if not os.path.exists(txt_file):
        # 文件不存在，跳过
        pass
        return s22_results
    
    try:
        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = remove_ansi_escape_codes(f.read())
            
            # 检查是否有发现问题
            if "nothing reported" in content:
                print("ℹ️  S22: 没有发现 PHP 脚本问题")
                return s22_results
            
            # 提取PHP漏洞文件（progpilot结果）
            pattern = r'Found (\d+) vulnerabilities.*?in php file:\s*(.*?)\s*\(.*?\[REF\]\s*(.*?)\.txt'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for match in matches:
                vuln_count, script_path, ref_file = match
                script_name = os.path.basename(script_path.strip())
                
                # 读取PHP漏洞详细结果（JSON格式）
                detail_file = os.path.join(folder_path, f"{os.path.basename(ref_file)}.txt")
                if os.path.exists(detail_file):
                    try:
                        with open(detail_file, 'r', encoding='utf-8', errors='ignore') as df:
                            json_content = remove_ansi_escape_codes(df.read())
                            vulns = json.loads(json_content)
                            
                        for vuln in vulns:
                            # 提取代码片段
                            code_snippet = ""
                            try:
                                # 尝试从semgrep_sources文件夹中提取代码片段
                                source_file = os.path.join(folder_path, "semgrep_sources", f"{script_name}.log")
                                if os.path.exists(source_file):
                                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as sf:
                                        source_content = remove_ansi_escape_codes(sf.read())
                                        lines = source_content.split('\n')
                                        line_num = vuln.get("sink_line", 0)
                                        if line_num > 0 and line_num <= len(lines):
                                            # 提取漏洞行及其上下文（前后各2行）
                                            start_line = max(0, line_num - 3)
                                            end_line = min(len(lines), line_num + 2)
                                            context_lines = lines[start_line:end_line]
                                            code_snippet = '\n'.join(context_lines)
                            except Exception as e:
                                code_snippet = f"Error extracting code: {e}"
                            
                            s22_results['issues'].append({
                                "file_name": script_name,
                                "line_number": vuln.get("sink_line", 0),
                                "column_number": vuln.get("sink_column", 0),
                                "error_code": vuln.get("vuln_cwe", ""),
                                "error_message": f"{get_php_cwe_description(vuln.get('vuln_cwe', '')).split(' - ')[1] if vuln.get('vuln_cwe', '') else ''} - {vuln.get('sink_name', '')}",
                                "vulnerability_type": vuln.get("vuln_type", ""),
                                "code_snippet": code_snippet,
                                "severity": "high"
                            })
                            s22_results['progpilot_issues'] += 1
                    except json.JSONDecodeError:
                        continue
            
            s22_results['total_issues'] = len(s22_results['issues'])
            
    except Exception as e:
        # 处理失败，跳过
        pass
    
    return s22_results

def extract_s27_perl_check(base_dir):
    """
    提取 S27 Perl 脚本检查结果
    
    Args:
        base_dir (str): 基础目录路径
    
    Returns:
        dict: Perl 检查结果
    """
    s27_results = {
        'total_issues': 0,
        'issues': []
    }
    
    txt_file = os.path.join(base_dir, 's27_perl_check.txt')
    folder_path = os.path.join(base_dir, 's27_perl_check')
    
    if not os.path.exists(txt_file):
        # 文件不存在，跳过
        pass
        return s27_results
    
    try:
        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = remove_ansi_escape_codes(f.read())
            
            # 检查是否有发现问题
            if "nothing reported" in content:
                print("ℹ️  S27: 没有发现 Perl 脚本问题")
                return s27_results
            
            # 提取Perl文件
            pattern = r'Found (\d+) possible issue\(s\) in perl script.*?:\s*(.*?)\s*\(.*?\[REF\]\s*(.*?)\.txt'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for match in matches:
                issue_count, script_path, ref_file = match
                script_name = os.path.basename(script_path.strip())
                
                # 读取zarn详细结果
                detail_file = os.path.join(folder_path, f"{os.path.basename(ref_file)}.txt")
                if os.path.exists(detail_file):
                    with open(detail_file, 'r', encoding='utf-8', errors='ignore') as df:
                        detail_content = remove_ansi_escape_codes(df.read())
                        
                    # 解析zarn结果 - 使用实际的格式
                    vuln_pattern = r'Vulnerability title: ([^\n]+).*?Vulnerability description: ([^\n]+).*?(\d+) - (.*?)(?=-----------------------------------------------------------------|\Z)'
                    vuln_matches = re.findall(vuln_pattern, detail_content, re.DOTALL)
                    
                    for vuln_match in vuln_matches:
                        vuln_title, vuln_desc, line_num, code_snippet = vuln_match
                        s27_results['issues'].append({
                            "file_name": script_name,
                            "line_number": int(line_num),
                            "error_code": get_perl_error_description(vuln_title.strip()),
                            "error_message": get_perl_error_message_description(vuln_title.strip()),
                            "code_snippet": remove_ansi_escape_codes(code_snippet.strip()),
                            "severity": "high"
                        })
            
            s27_results['total_issues'] = len(s27_results['issues'])
            
    except Exception as e:
        # 处理失败，跳过
        pass
    
    return s27_results

def print_scripts_report(s21_data, s22_data, s23_data, s27_data):
    """
    打印脚本漏洞检查报告到日志文件
    
    Args:
        s21_data (dict): S21 数据
        s22_data (dict): S22 数据
        s23_data (dict): S23 数据
        s27_data (dict): S27 数据
    """
    import logging
    
    # 获取当前日志配置
    logger = logging.getLogger()
    if not logger.handlers:
        logging.basicConfig(
            filename='../result/scripts.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            filemode='a',
            encoding='utf-8'
        )
    
    logging.info("=" * 70)
    logging.info("🔍 脚本漏洞检查报告 (不包含S20 Shell检查)")
    logging.info("=" * 70)
    
    # S21 报告
    logging.info(f"🐍 S21 - Python 脚本检查结果:")
    logging.info(f"   📊 发现问题数量: {s21_data['total_issues']} 个")
    if s21_data['total_issues'] > 0:
        # 显示前3个问题作为示例
        for i, issue in enumerate(s21_data['issues'][:3]):
            logging.info(f"      - {issue['file_name']}:{issue['line_number']} - {issue['error_message'][:60]}...")
        if s21_data['total_issues'] > 3:
            logging.info(f"      ... 还有 {s21_data['total_issues'] - 3} 个问题")
    
    # S22 报告
    logging.info(f"🌐 S22 - PHP 脚本检查结果:")
    logging.info(f"   📊 总问题数量: {s22_data['total_issues']} 个")
    if s22_data['total_issues'] > 0:
        logging.info(f"   🔍 Progpilot 问题: {s22_data['progpilot_issues']} 个")
        # 显示前3个问题作为示例
        for i, issue in enumerate(s22_data['issues'][:3]):
            logging.info(f"      - {issue['file_name']}:{issue['line_number']} - {issue['error_message'][:60]}...")
        if s22_data['total_issues'] > 3:
            logging.info(f"      ... 还有 {s22_data['total_issues'] - 3} 个问题")
    
    # S27 报告
    logging.info(f"🔷 S27 - Perl 脚本检查结果:")
    logging.info(f"   📊 发现问题数量: {s27_data['total_issues']} 个")
    if s27_data['total_issues'] > 0:
        # 显示前3个问题作为示例
        for i, issue in enumerate(s27_data['issues'][:3]):
            logging.info(f"      - {issue['file_name']}:{issue['line_number']} - {issue['error_message'][:60]}...")
        if s27_data['total_issues'] > 3:
            logging.info(f"      ... 还有 {s27_data['total_issues'] - 3} 个问题")
    
    logging.info("=" * 70)

def save_to_json(data, output_file):
    """
    保存数据到JSON文件
    
    Args:
        data (dict): 要保存的数据
        output_file (str): 输出文件路径
    
    Returns:
        bool: 保存是否成功
    """
    try:
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        return False

def main():
    import argparse
    import logging
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='脚本漏洞分析脚本')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    
    args = parser.parse_args()
    
    # 配置日志 - 使用独立的日志文件
    log_file = os.path.join(args.log_prefix, 'scripts_vul.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    # 设置路径
    base_directory = args.input_prefix
    output_file = f"{args.output_prefix}/scripts_vul.json"
    
    logging.info("🔍 正在提取脚本漏洞检查数据...")
    
    # 检查目录是否存在
    if not os.path.exists(base_directory):
        logging.error(f"❌ 目录不存在: {base_directory}")
        return
    
    # 检查必要文件是否存在
    required_files = [
        "s21_python_check.txt", 
        "s22_php_check.txt",
        "s27_perl_check.txt"
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(os.path.join(base_directory, f))]
    if missing_files:
        logging.warning(f"⚠️  警告: 以下文件不存在: {', '.join(missing_files)}")
        logging.info("   将跳过相应模块的分析")
    
    # 提取各模块数据（去掉 s20 模块）
    logging.info("📄 提取 S21 Python 脚本检查数据...")
    s21_data = extract_s21_python_check(base_directory)
    
    logging.info("📄 提取 S22 PHP 脚本检查数据...")
    s22_data = extract_s22_php_check(base_directory)
    
    logging.info("📄 提取 S27 Perl 脚本检查数据...")
    s27_data = extract_s27_perl_check(base_directory)
    
    # 构建完整结果
    result = {
        'scan_summary': {
            'total_python_issues': s21_data['total_issues'],
            'total_php_issues': s22_data['total_issues'],
            'total_perl_issues': s27_data['total_issues'],
            'total_all_issues': (
                s21_data['total_issues'] + 
                s22_data['total_issues'] + 
                s27_data['total_issues']
            )
        },
        'statistics': {
            'python': {
                'total_issues': s21_data['total_issues'],
                'files_affected': len(set(issue['file_name'] for issue in s21_data['issues']))
            },
            'php': {
                'total_issues': s22_data['total_issues'],
                'progpilot_issues': s22_data['progpilot_issues'],
                'files_affected': len(set(issue['file_name'] for issue in s22_data['issues']))
            },
            'perl': {
                'total_issues': s27_data['total_issues'],
                'files_affected': len(set(issue['file_name'] for issue in s27_data['issues']))
            }
        },
        'detailed_results': {
            's21_python_check': s21_data,
            's22_php_check': s22_data,
            's27_perl_check': s27_data
        }
    }
    
    # 打印报告
    print_scripts_report(s21_data, s22_data, {}, s27_data)
    
    # 保存到JSON文件
    if save_to_json(result, output_file):
        logging.info(f"✅ 脚本漏洞检查结果已保存到: {output_file}")
        
        # 显示统计摘要
        logging.info(f"📈 统计摘要:")
        total_issues = result['scan_summary']['total_all_issues']
        logging.info(f"   总计: {total_issues} 个问题")
        if s21_data['total_issues'] > 0:
            logging.info(f"   PYTHON: {s21_data['total_issues']} 个问题")
        if s22_data['total_issues'] > 0:
            logging.info(f"   PHP: {s22_data['total_issues']} 个问题")
        if s27_data['total_issues'] > 0:
            logging.info(f"   PERL: {s27_data['total_issues']} 个问题")
    else:
        logging.error("❌ 保存文件失败")

if __name__ == "__main__":
    main()

