#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import glob
from pathlib import Path

def is_binary_content(content):
    """
    判断内容是否为二进制文件（包含不可见字符）
    
    Args:
        content (str): 文件内容
    
    Returns:
        bool: 是否为二进制内容
    """
    try:
        if not content:
            return False
        
        # 检查是否包含控制字符（除了常见的换行、制表符等）
        control_chars = 0
        printable_chars = 0
        
        for c in content:
            if c.isprintable() or c in '\n\r\t':
                printable_chars += 1
            elif ord(c) < 32 or ord(c) == 127:  # 控制字符
                control_chars += 1
        
        total_chars = len(content)
        
        # 如果控制字符超过5%或可打印字符少于70%，认为是二进制内容
        control_ratio = control_chars / total_chars if total_chars > 0 else 0
        printable_ratio = printable_chars / total_chars if total_chars > 0 else 0
        
        return control_ratio > 0.05 or printable_ratio < 0.7
    except:
        return True

def has_invisible_characters(content):
    """
    检查内容是否包含不可见字符（如 \u0001, \u0003 等）
    
    Args:
        content (str): 文件内容
    
    Returns:
        bool: 是否包含不可见字符
    """
    try:
        if not content:
            return False
        
        # 检查是否包含 Unicode 控制字符
        for c in content:
            # 检查控制字符（除了常见的空白字符）
            if ord(c) < 32 and c not in '\n\r\t':
                return True
            # 检查其他 Unicode 控制字符范围
            if 0x7F <= ord(c) <= 0x9F:
                return True
        
        return False
    except:
        return True

def extract_s106_deep_key_search(base_dir):
    """
    提取 S106 深度密钥搜索结果
    
    Args:
        base_dir (str): 基础目录路径
    
    Returns:
        dict: 密钥搜索结果
    """
    s106_results = {
        'total_files_with_keys': 0,
        'key_files': []
    }
    
    s106_dir = os.path.join(base_dir, 's106_deep_key_search')
    
    if not os.path.exists(s106_dir):
        print(f"❌ S106 目录不存在: {s106_dir}")
        return s106_results
    
    # 读取所有深度搜索结果文件
    search_files = glob.glob(os.path.join(s106_dir, 'deep_key_search_*.txt'))
    
    for search_file in search_files:
        try:
            with open(search_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # 提取文件路径
                path_match = re.search(r'\[*\] FILE_PATH: (.+?) \(', content)
                if not path_match:
                    continue
                
                file_path = path_match.group(1)
                
                # 提取文件内容（去掉路径和搜索结果部分）
                content_lines = content.split('\n')
                file_content_lines = []
                in_content = False
                
                for line in content_lines:
                    if line.startswith('[*] FILE_PATH:'):
                        in_content = True
                        continue
                    elif line.startswith('[*] Deep search results:'):
                        break
                    elif in_content and line.strip():
                        # 去掉行号前缀
                        if ':' in line and line.split(':', 1)[0].isdigit():
                            file_content_lines.append(line.split(':', 1)[1])
                        elif line.startswith(('-', ' ')):
                            file_content_lines.append(line[1:])
                        else:
                            file_content_lines.append(line)
                
                file_content = '\n'.join(file_content_lines).strip()
                
                # 提取pattern（从Deep search results部分）
                pattern = ""
                pattern_section = content.split('[*] Deep search results:')
                if len(pattern_section) > 1:
                    pattern_lines = pattern_section[1].strip().split('\n')
                    for line in pattern_lines:
                        if line.strip() and ':' in line:
                            # 提取pattern部分（去掉行号和制表符）
                            pattern_part = line.split(':', 1)[1].strip()
                            if pattern_part:
                                pattern = pattern_part
                                break
                
                key_file_info = {
                    'file_path': file_path,
                    'pattern': pattern,
                    'content_length': len(file_content)
                }
                
                s106_results['key_files'].append(key_file_info)
                
        except Exception as e:
            print(f"❌ 处理文件失败 {search_file}: {e}")
    
    s106_results['total_files_with_keys'] = len(s106_results['key_files'])
    return s106_results

def extract_s108_stacs_password_search(base_dir):
    """
    提取 S108 STACS 密码搜索结果
    
    Args:
        base_dir (str): 基础目录路径
    
    Returns:
        dict: 密码搜索结果
    """
    s108_results = {
        'total_credentials': 0,
        'credentials': []
    }
    
    s108_file = os.path.join(base_dir, 's108_stacs_password_search.txt')
    
    if not os.path.exists(s108_file):
        print(f"❌ S108 文件不存在: {s108_file}")
        return s108_results
    
    try:
        with open(s108_file, 'r', encoding='utf-8') as f:
            content = f.read()
           
            content = remove_ansi_escape_codes(content)

            # 提取路径和哈希信息
            credential_matches = re.findall(
                r'\[\+\] PATH: (.+?)\s+-\s+Hash: "(.+?)"\.', 
                content
            )
            
            for path, hash_value in credential_matches:
                credential_info = {
                    'path': path.strip(),
                    'hash': hash_value.strip()
                }
                s108_results['credentials'].append(credential_info)
            
            s108_results['total_credentials'] = len(s108_results['credentials'])
            
    except Exception as e:
        print(f"❌ 处理 S108 文件失败: {e}")
    
    return s108_results

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
    return ansi_escape.sub('', text)

def extract_s109_jtr_password_cracking(base_dir):
    """
    提取 S109 John the Ripper 密码破解结果
    
    Args:
        base_dir (str): 基础目录路径
    
    Returns:
        dict: 密码破解结果
    """
    s109_results = {
        'total_passwords_found': 0,
        'total_hashes_cracked': 0,
        'found_passwords': [],
        'cracked_passwords': []
    }
    
    s109_file = os.path.join(base_dir, 's109_jtr_local_pw_cracking.txt')
    
    if not os.path.exists(s109_file):
        print(f"❌ S109 文件不存在: {s109_file}")
        return s109_results
    
    try:
        with open(s109_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 首先移除所有ANSI颜色控制字符
            cleaned_content = remove_ansi_escape_codes(content)
            
            # 检查是否有密码被破解
            final_status_match = re.search(r'final status: (\d+) password hashes cracked', cleaned_content)
            if not final_status_match or int(final_status_match.group(1)) == 0:
                print("ℹ️  S109: 没有密码被成功破解")
                return s109_results
            
            # 提取发现的密码数据（去重）
            found_passwords = set()
            found_matches = re.findall(r'\[\*\] Found password data (.+?) for further processing', cleaned_content)
            
            for password_data in found_matches:
                found_passwords.add(password_data.strip())
            
            s109_results['found_passwords'] = list(found_passwords)
            s109_results['total_passwords_found'] = len(found_passwords)
            
            # 提取破解的密码
            cracked_matches = re.findall(r'\[\+\] Password hash cracked: (.+)', cleaned_content)
            
            for cracked_password in cracked_matches:
                s109_results['cracked_passwords'].append(cracked_password.strip())
            
            s109_results['total_hashes_cracked'] = len(s109_results['cracked_passwords'])
            
    except Exception as e:
        print(f"❌ 处理 S109 文件失败: {e}")
    
    return s109_results

def print_security_report(s106_data, s108_data, s109_data):
    """
    打印安全分析报告到日志文件
    
    Args:
        s106_data (dict): S106 数据
        s108_data (dict): S108 数据
        s109_data (dict): S109 数据
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
    logging.info("🔐 固件安全数据提取报告")
    logging.info("=" * 70)
    
    # S106 报告
    logging.info(f"📁 S106 - 深度密钥搜索结果:")
    logging.info(f"   🔑 发现包含密钥的文件: {s106_data['total_files_with_keys']} 个")
    
    if s106_data['key_files']:
        logging.info(f"   📋 密钥文件详情:")
        for i, key_file in enumerate(s106_data['key_files'][:3], 1):  # 只显示前3个
            logging.info(f"      {i}. {os.path.basename(key_file['file_path'])}")
            if key_file.get('pattern'):
                logging.info(f"         Pattern: {key_file['pattern']}")
            logging.info(f"         内容: [文件大小: {key_file['content_length']} 字节]")
        
        if len(s106_data['key_files']) > 3:
            logging.info(f"      ... 还有 {len(s106_data['key_files']) - 3} 个文件")
    
    # S108 报告
    logging.info(f"🔍 S108 - STACS 密码搜索结果:")
    logging.info(f"   🎯 发现凭据区域: {s108_data['total_credentials']} 个")
    
    if s108_data['credentials']:
        logging.info(f"   📋 凭据详情:")
        for i, cred in enumerate(s108_data['credentials'][:3], 1):  # 只显示前3个
            logging.info(f"      {i}. 路径: {cred['path']}")
            hash_preview = cred['hash'][:50] + "..." if len(cred['hash']) > 50 else cred['hash']
            logging.info(f"         哈希: {hash_preview}")
    
    # S109 报告
    logging.info(f"🔓 S109 - John the Ripper 密码破解结果:")
    logging.info(f"   📊 发现的密码数据: {s109_data['total_passwords_found']} 个")
    logging.info(f"   ✅ 成功破解的哈希: {s109_data['total_hashes_cracked']} 个")
    
    if s109_data['cracked_passwords']:
        logging.info(f"   🎉 破解成功的密码:")
        for i, cracked in enumerate(s109_data['cracked_passwords'], 1):
            logging.info(f"      {i}. {cracked}")
    
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
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ 保存文件失败: {e}")
        return False

def main():
    import argparse
    import logging
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='密码安全分析脚本')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    
    args = parser.parse_args()
    
    # 配置日志 - 使用独立的日志文件
    log_file = os.path.join(args.log_prefix, 'passwd.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    # 设置路径
    base_directory = args.input_prefix
    output_file = f"{args.output_prefix}/passwd.json"
    
    logging.info("🔍 正在提取安全数据...")
    
    # 检查目录是否存在
    if not os.path.exists(base_directory):
        logging.error(f"❌ 目录不存在: {base_directory}")
        return
    
    # 提取各模块数据
    logging.info("📄 提取 S106 深度密钥搜索数据...")
    s106_data = extract_s106_deep_key_search(base_directory)
    
    logging.info("📄 提取 S108 STACS 密码搜索数据...")
    s108_data = extract_s108_stacs_password_search(base_directory)
    
    logging.info("📄 提取 S109 John the Ripper 密码破解数据...")
    s109_data = extract_s109_jtr_password_cracking(base_directory)
    
    # 构建完整结果
    result = {
        'scan_summary': {
            'total_key_files': s106_data['total_files_with_keys'],
            'total_credentials': s108_data['total_credentials'],
            'total_passwords_found': s109_data['total_passwords_found'],
            'total_hashes_cracked': s109_data['total_hashes_cracked']
        },
        'modules': {
            's106_deep_key_search': s106_data,
            's108_stacs_password_search': s108_data,
            's109_jtr_password_cracking': s109_data
        }
    }
    
    # 打印报告
    print_security_report(s106_data, s108_data, s109_data)
    
    # 保存到JSON文件
    if save_to_json(result, output_file):
        logging.info(f"✅ 安全数据提取结果已保存到: {output_file}")
    else:
        logging.error("❌ 保存文件失败")

if __name__ == "__main__":
    main()
