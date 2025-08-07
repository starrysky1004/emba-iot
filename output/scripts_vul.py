#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Any

def get_python_error_description(error_code):
    """
    Get description for Python error code
    
    Args:
        error_code (str): Error code
    
    Returns:
        str: Error code +  description
    """
    error_descriptions = {
        'B101': 'assert_used',
        'B102': 'exec_used',
        'B103': 'set_bad_file_permissions',
        'B104': 'hardcoded_bind_all_interfaces',
        'B105': 'hardcoded_password_string',
        'B106': 'hardcoded_password_funcarg',
        'B107': 'hardcoded_password_default',
        'B108': 'hardcoded_tmp_directory',
        'B109': 'password_config_option_not_marked_secret',
        'B110': 'try_except_pass',
        'B111': 'execute_with_run_as_root_equals_true',
        'B112': 'try_except_continue',
        'B113': 'request_without_timeout',
        'B201': 'flask_debug_true',
        'B202': 'tarfile_unsafe_members',
        'B301': 'blacklist',
        'B306': 'blacklist',
        'B307': 'blacklist',
        'B310': 'blacklist',
        'B311': 'blacklist',
        'B323': 'blacklist',
        'B324': 'hashlib',
        'B403': 'blacklist',
        'B404': 'blacklist',
        'B501': 'request_with_no_cert_validation',
        'B502': 'ssl_with_bad_version',
        'B503': 'ssl_with_bad_defaults',
        'B504': 'ssl_with_no_version',
        'B505': 'weak_cryptographic_key',
        'B506': 'yaml_load',
        'B507': 'ssh_no_host_key_verification',
        'B508': 'snmp_insecure_version',
        'B509': 'snmp_weak_cryptography',
        'B601': 'paramiko_calls',
        'B602': 'subprocess_popen_with_shell_equals_true',
        'B603': 'subprocess_without_shell_equals_true',
        'B604': 'any_other_function_with_shell_equals_true',
        'B605': 'start_process_with_a_shell',
        'B606': 'start_process_with_no_shell',
        'B607': 'start_process_with_partial_path',
        'B608': 'hardcoded_sql_expressions',
        'B609': 'linux_commands_wildcard_injection',
        'B610': 'django_extra_used',
        'B611': 'django_rawsql_used',
        'B612': 'logging_config_insecure_listen',
        'B613': 'trojansource',
        'B614': 'pytorch_load',
        'B615': 'huggingface_unsafe_download',
        'B701': 'jinja2_autoescape_false',
        'B702': 'use_of_mako_templates',
        'B703': 'django_mark_safe',
        'B704': 'markupsafe_markup_xss'
    }
    
    return error_descriptions.get(error_code, f'{error_code} - Unknown error type')

def get_php_cwe_description(cwe_code):
    """
    Get English description for PHP CWE error code
    
    Args:
        cwe_code (str): CWE error code or semgrep rule name
    
    Returns:
        str: CWE error code + English description
    """
    cwe_descriptions = {
        'CWE_78': 'OS Command Injection',
        'CWE_79': 'Cross-site Scripting (XSS)',
        'CWE_89': 'SQL Injection',
        'CWE_90': 'LDAP Injection',
        'CWE_91': 'XML Injection',
        'CWE_95': 'Code Injection',
        'CWE_98': 'PHP File Inclusion',
        'CWE_22': 'Path Traversal',
        'CWE_384': 'Session Fixation',
        'CWE_601': 'URL Redirection to Untrusted Site',
        'CWE_1333': 'Regular Expression Denial of Service (ReDoS)'
    }
    
    semgrep_descriptions = {
        'external.semgrep-rules.php.lang.security.unlink-use': 'Unsafe File Deletion',
        'external.semgrep-rules.php.lang.security.unserialize-use': 'Unsafe Unserialize',
        'external.semgrep-rules.php.lang.security.weak-crypto': 'Weak Cryptography'
    }
    
    if cwe_code in cwe_descriptions:
        return cwe_descriptions[cwe_code]
    
    if cwe_code in semgrep_descriptions:
        return semgrep_descriptions[cwe_code]
    
    return f'{cwe_code} - Unknown vulnerability type'

def get_perl_error_description(error_code):
    """
    Get description for Perl error code
    
    Args:
        error_code (str): Perl error code
    
    Returns:
        str: Perl error code + description
    """
    perl_descriptions = {
        'Debug module enabled': 'Debug module enabled',
        'Code Injection': 'Code Injection',
        'Path Traversal': 'Path Traversal',
        'Weak Criptography Algorithm': 'Weak Criptography Algorithm',
        'Weak Random Value Generator': 'Weak Random Value Generator',
        'Error Suppression': 'Error Suppression',
        'Cross Site Scripting (XSS)': 'Cross Site Scripting (XSS)',
        'Command Injection': 'Command Injection',
        'Connection String Injection': 'Connection String Injection',
        'LDAP Injection': 'LDAP Injection',
        'XSS': 'XSS',
        'Remote File Inclusion': 'Remote File Inclusion',
        'Resource Injection': 'Resource Injection',
        'SQL Injection': 'SQL Injection'
    }
    
    return perl_descriptions.get(error_code, f'{error_code} - Unknown vulnerability type')

def get_perl_error_message_description(error_code):
    """
    Get description for Perl error message
    
    Args:
        error_code (str): Perl error code
    
    Returns:
        str: description
    """
    perl_message_descriptions = {
        'Debug module enabled': 'Debug module may expose sensitive information and create security vulnerabilities',
        'Code Injection': 'Occurs when untrusted data is executed as code, allowing attackers to run arbitrary commands on the server',
        'Path Traversal': 'Occurs when user input is not properly sanitized, allowing attackers to access files and directories outside the intended directory structure',
        'Weak Criptography Algorithm': 'Weak algorithms like MD5 are vulnerable to various attacks and should be avoided in favor of stronger alternatives to ensure sensitive data security',
        'Weak Random Value Generator': 'Weak random value generators may produce predictable values that attackers can exploit to bypass security controls',
        'Error Suppression': 'Suppressing errors may make it difficult to identify and troubleshoot issues, potentially leading to security vulnerabilities',
        'Cross Site Scripting (XSS)': 'Occurs when untrusted data is rendered as HTML without proper escaping, allowing attackers to execute malicious scripts in the context of the victim\'s browser',
        'Command Injection': 'Command injection attacks may occur when applications pass unsafe user-provided data to system shells',
        'Connection String Injection': 'Connection string injection attacks may occur when dynamic string concatenation is used to build connection strings based on user input',
        'LDAP Injection': 'LDAP injection is an attack used to exploit web-based applications that build LDAP statements based on user input',
        'XSS': 'Cross-site scripting is an injection type where malicious scripts are injected into otherwise benign and trusted websites',
        'Remote File Inclusion': 'This vulnerability allows attackers to include files, typically exploiting the "dynamic file inclusion" mechanism implemented in target applications',
        'Resource Injection': 'This attack involves changing resource identifiers used by applications to perform malicious tasks',
        'SQL Injection': 'SQL injection attacks involve inserting or "injecting" SQL queries via input data from the client to the application'
    }
    
    return perl_message_descriptions.get(error_code, 'Unknown vulnerability type')

def remove_ansi_escape_codes(text):
    """
    Remove ANSI color and format control characters from text
    
    Args:
        text (str): Text containing ANSI control characters
    
    Returns:
        str: Cleaned text
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)
    color_codes = re.compile(r'\[0;?\d*m|\[\d+m|\[0m')
    text = color_codes.sub('', text)
    return text.strip()

def extract_s21_python_check(base_dir):
    """
    Extract S21 Python script check results
    
    Args:
        base_dir (str): Base directory path
    
    Returns:
        dict: Python check results
    """
    s21_results = {
        'total_issues': 0,
        'issues': []
    }
    
    txt_file = os.path.join(base_dir, 's21_python_check.txt')
    folder_path = os.path.join(base_dir, 's21_python_check')
    
    if not os.path.exists(txt_file):
        return s21_results
    
    try:
        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = remove_ansi_escape_codes(f.read())
            
            if "nothing reported" in content:
                print("S21: No Python script issues found")
                return s21_results
            
            pattern = r'Found (\d+) issues in script.*?:\s*(.*?)\s*\(.*?\[REF\]\s*(.*?)\.txt'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for match in matches:
                issue_count, script_path, ref_file = match
                script_name = os.path.basename(script_path.strip())
                
                detail_file = os.path.join(folder_path, f"{os.path.basename(ref_file)}.txt")
                if os.path.exists(detail_file):
                    with open(detail_file, 'r', encoding='utf-8', errors='ignore') as df:
                        detail_content = remove_ansi_escape_codes(df.read())
                        
                    issue_pattern = r'>> Issue: \[([^\]]+)\].*?Severity: (\w+).*?Confidence: (\w+).*?Location: [^:]+:(\d+):(\d+)(.*?)(?=--------------------------------------------------|\Z)'
                    issue_matches = re.findall(issue_pattern, detail_content, re.DOTALL)
                    
                    for issue_match in issue_matches:
                        error_code_full, severity, confidence, line_num, col_num, description = issue_match
                        error_code = error_code_full.split(':')[0] if ':' in error_code_full else error_code_full
                        s21_results['issues'].append({
                            "file_name": script_name,
                            "line_number": int(line_num),
                            "column_number": int(col_num),
                            "error_code": f"{error_code_full} - {get_python_error_description(error_code)}",
                            "error_message": description.strip(),
                            "severity": severity.lower(),
                            "confidence": confidence.lower()
                        })
            
            s21_results['total_issues'] = len(s21_results['issues'])
            
    except Exception as e:
        pass
    
    return s21_results

def extract_s22_php_check(base_dir):
    """
    Extract S22 PHP script check results
    
    Args:
        base_dir (str): Base directory path
    
    Returns:
        dict: PHP check results
    """
    s22_results = {
        'total_issues': 0,
        'progpilot_issues': 0,
        'issues': []
    }
    
    txt_file = os.path.join(base_dir, 's22_php_check.txt')
    folder_path = os.path.join(base_dir, 's22_php_check')
    
    if not os.path.exists(txt_file):
        return s22_results
    
    try:
        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = remove_ansi_escape_codes(f.read())
            
            if "nothing reported" in content:
                print("S22: No PHP script issues found")
                return s22_results
            
            pattern = r'Found (\d+) vulnerabilities.*?in php file:\s*(.*?)\s*\(.*?\[REF\]\s*(.*?)\.txt'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for match in matches:
                vuln_count, script_path, ref_file = match
                script_name = os.path.basename(script_path.strip())
                
                detail_file = os.path.join(folder_path, f"{os.path.basename(ref_file)}.txt")
                if os.path.exists(detail_file):
                    try:
                        with open(detail_file, 'r', encoding='utf-8', errors='ignore') as df:
                            json_content = remove_ansi_escape_codes(df.read())
                            vulns = json.loads(json_content)
                            
                        for vuln in vulns:
                            code_snippet = ""
                            try:
                                source_file = os.path.join(folder_path, "semgrep_sources", f"{script_name}.log")
                                if os.path.exists(source_file):
                                    with open(source_file, 'r', encoding='utf-8', errors='ignore') as sf:
                                        source_content = remove_ansi_escape_codes(sf.read())
                                        lines = source_content.split('\n')
                                        line_num = vuln.get("sink_line", 0)
                                        if line_num > 0 and line_num <= len(lines):
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
                                "error_message": f"{get_php_cwe_description(vuln.get('vuln_cwe', '')).split(' - ')[1] if vuln.get('vuln_cwe', '') and ' - ' in get_php_cwe_description(vuln.get('vuln_cwe', '')) else get_php_cwe_description(vuln.get('vuln_cwe', ''))} - {vuln.get('sink_name', '')}",
                                "vulnerability_type": vuln.get("vuln_type", ""),
                                "code_snippet": code_snippet,
                                "severity": "high"
                            })
                            s22_results['progpilot_issues'] += 1
                    except json.JSONDecodeError:
                        continue
            
            s22_results['total_issues'] = len(s22_results['issues'])
            
    except Exception as e:
        pass
    
    return s22_results

def extract_s27_perl_check(base_dir):
    """
    Extract S27 Perl script check results
    
    Args:
        base_dir (str): Base directory path
    
    Returns:
        dict: Perl check results
    """
    s27_results = {
        'total_issues': 0,
        'issues': []
    }
    
    txt_file = os.path.join(base_dir, 's27_perl_check.txt')
    folder_path = os.path.join(base_dir, 's27_perl_check')
    
    if not os.path.exists(txt_file):
        return s27_results
    
    try:
        with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = remove_ansi_escape_codes(f.read())
            
            if "nothing reported" in content:
                print("S27: No Perl script issues found")
                return s27_results
            
            pattern = r'Found (\d+) possible issue\(s\) in perl script.*?:\s*(.*?)\s*\(.*?\[REF\]\s*(.*?)\.txt'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for match in matches:
                issue_count, script_path, ref_file = match
                script_name = os.path.basename(script_path.strip())
                
                detail_file = os.path.join(folder_path, f"{os.path.basename(ref_file)}.txt")
                if os.path.exists(detail_file):
                    with open(detail_file, 'r', encoding='utf-8', errors='ignore') as df:
                        detail_content = remove_ansi_escape_codes(df.read())
                        
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
        pass
    
    return s27_results

def print_scripts_report(s21_data, s22_data, s23_data, s27_data):
    """
    Print script vulnerability check report to log file
    
    Args:
        s21_data (dict): S21 data
        s22_data (dict): S22 data
        s23_data (dict): S23 data
        s27_data (dict): S27 data
    """
    import logging
    
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
    logging.info("Script Vulnerability Check Report (excluding S20 Shell check)")
    logging.info("=" * 70)
    
    logging.info(f"S21 - Python Script Check Results:")
    logging.info(f"   Issues found: {s21_data['total_issues']}")
    if s21_data['total_issues'] > 0:
        for i, issue in enumerate(s21_data['issues'][:3]):
            logging.info(f"      - {issue['file_name']}:{issue['line_number']} - {issue['error_message'][:60]}...")
        if s21_data['total_issues'] > 3:
            logging.info(f"      ... {s21_data['total_issues'] - 3} more issues")
    
    logging.info(f"S22 - PHP Script Check Results:")
    logging.info(f"   Total issues: {s22_data['total_issues']}")
    if s22_data['total_issues'] > 0:
        logging.info(f"   Progpilot issues: {s22_data['progpilot_issues']}")
        for i, issue in enumerate(s22_data['issues'][:3]):
            logging.info(f"      - {issue['file_name']}:{issue['line_number']} - {issue['error_message'][:60]}...")
        if s22_data['total_issues'] > 3:
            logging.info(f"      ... {s22_data['total_issues'] - 3} more issues")
    
    logging.info(f"S27 - Perl Script Check Results:")
    logging.info(f"   Issues found: {s27_data['total_issues']}")
    if s27_data['total_issues'] > 0:
        for i, issue in enumerate(s27_data['issues'][:3]):
            logging.info(f"      - {issue['file_name']}:{issue['line_number']} - {issue['error_message'][:60]}...")
        if s27_data['total_issues'] > 3:
            logging.info(f"      ... {s27_data['total_issues'] - 3} more issues")
    
    logging.info("=" * 70)

def save_to_json(data, output_file):
    """
    Save data to JSON file
    
    Args:
        data (dict): Data to save
        output_file (str): Output file path
    
    Returns:
        bool: Whether save was successful
    """
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        return False

def main():
    import argparse
    import logging
    
    parser = argparse.ArgumentParser(description='Script Vulnerability Analysis Script')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    
    args = parser.parse_args()
    
    log_file = os.path.join(args.log_prefix, 'scripts_vul.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    base_directory = args.input_prefix
    output_file = f"{args.output_prefix}/scripts_vul.json"
    
    logging.info("Extracting script vulnerability check data...")
    
    if not os.path.exists(base_directory):
        logging.error(f"Directory not found: {base_directory}")
        return
    
    required_files = [
        "s21_python_check.txt", 
        "s22_php_check.txt",
        "s27_perl_check.txt"
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(os.path.join(base_directory, f))]
    if missing_files:
        logging.warning(f"Warning: Following files not found: {', '.join(missing_files)}")
        logging.info("   Will skip analysis of corresponding modules")
    
    logging.info("Extracting S21 Python script check data...")
    s21_data = extract_s21_python_check(base_directory)
    
    logging.info("Extracting S22 PHP script check data...")
    s22_data = extract_s22_php_check(base_directory)
    
    logging.info("Extracting S27 Perl script check data...")
    s27_data = extract_s27_perl_check(base_directory)
    
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
    
    print_scripts_report(s21_data, s22_data, {}, s27_data)
    
    if save_to_json(result, output_file):
        logging.info(f"Script vulnerability check results saved to: {output_file}")
        
        logging.info(f"Statistics summary:")
        total_issues = result['scan_summary']['total_all_issues']
        logging.info(f"   Total: {total_issues} issues")
        if s21_data['total_issues'] > 0:
            logging.info(f"   PYTHON: {s21_data['total_issues']} issues")
        if s22_data['total_issues'] > 0:
            logging.info(f"   PHP: {s22_data['total_issues']} issues")
        if s27_data['total_issues'] > 0:
            logging.info(f"   PERL: {s27_data['total_issues']} issues")
    else:
        logging.error("Failed to save file")

if __name__ == "__main__":
    main()


