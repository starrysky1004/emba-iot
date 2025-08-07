#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import glob
from pathlib import Path

def is_binary_content(content):
    """
    Determine if content is binary file (contains invisible characters)
    
    Args:
        content (str): File content
    
    Returns:
        bool: Whether it's binary content
    """
    try:
        if not content:
            return False
        
        control_chars = 0
        printable_chars = 0
        
        for c in content:
            if c.isprintable() or c in '\n\r\t':
                printable_chars += 1
            elif ord(c) < 32 or ord(c) == 127:
                control_chars += 1
        
        total_chars = len(content)
        
        control_ratio = control_chars / total_chars if total_chars > 0 else 0
        printable_ratio = printable_chars / total_chars if total_chars > 0 else 0
        
        return control_ratio > 0.05 or printable_ratio < 0.7
    except:
        return True

def has_invisible_characters(content):
    """
    Check if content contains invisible characters
    
    Args:
        content (str): File content
    
    Returns:
        bool: Whether it contains invisible characters
    """
    try:
        if not content:
            return False
        
        for c in content:
            if ord(c) < 32 and c not in '\n\r\t':
                return True
            if 0x7F <= ord(c) <= 0x9F:
                return True
        
        return False
    except:
        return True

def extract_s106_deep_key_search(base_dir):
    """
    Extract S106 deep key search results
    
    Args:
        base_dir (str): Base directory path
    
    Returns:
        dict: Key search results
    """
    s106_results = {
        'total_files_with_keys': 0,
        'key_files': []
    }
    
    s106_dir = os.path.join(base_dir, 's106_deep_key_search')
    
    if not os.path.exists(s106_dir):
        print(f"S106 directory not found: {s106_dir}")
        return s106_results
    
    search_files = glob.glob(os.path.join(s106_dir, 'deep_key_search_*.txt'))
    
    for search_file in search_files:
        try:
            with open(search_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                path_match = re.search(r'\[*\] FILE_PATH: (.+?) \(', content)
                if not path_match:
                    continue
                
                file_path = path_match.group(1)
                
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
                        if ':' in line and line.split(':', 1)[0].isdigit():
                            file_content_lines.append(line.split(':', 1)[1])
                        elif line.startswith(('-', ' ')):
                            file_content_lines.append(line[1:])
                        else:
                            file_content_lines.append(line)
                
                file_content = '\n'.join(file_content_lines).strip()
                
                pattern = ""
                pattern_section = content.split('[*] Deep search results:')
                if len(pattern_section) > 1:
                    pattern_lines = pattern_section[1].strip().split('\n')
                    for line in pattern_lines:
                        if line.strip() and ':' in line:
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
            print(f"Failed to process file {search_file}: {e}")
    
    s106_results['total_files_with_keys'] = len(s106_results['key_files'])
    return s106_results

def extract_s108_stacs_password_search(base_dir):
    """
    Extract S108 STACS password search results
    
    Args:
        base_dir (str): Base directory path
    
    Returns:
        dict: Password search results
    """
    s108_results = {
        'total_credentials': 0,
        'credentials': []
    }
    
    s108_file = os.path.join(base_dir, 's108_stacs_password_search.txt')
    
    if not os.path.exists(s108_file):
        print(f"S108 file not found: {s108_file}")
        return s108_results
    
    try:
        with open(s108_file, 'r', encoding='utf-8') as f:
            content = f.read()
           
            content = remove_ansi_escape_codes(content)

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
        print(f"Failed to process S108 file: {e}")
    
    return s108_results

def remove_ansi_escape_codes(text):
    """
    Remove ANSI color and format control characters from text
    
    Args:
        text (str): Text containing ANSI control characters
    
    Returns:
        str: Cleaned text
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def extract_s109_jtr_password_cracking(base_dir):
    """
    Extract S109 John the Ripper password cracking results
    
    Args:
        base_dir (str): Base directory path
    
    Returns:
        dict: Password cracking results
    """
    s109_results = {
        'total_passwords_found': 0,
        'total_hashes_cracked': 0,
        'found_passwords': [],
        'cracked_passwords': []
    }
    
    s109_file = os.path.join(base_dir, 's109_jtr_local_pw_cracking.txt')
    
    if not os.path.exists(s109_file):
        print(f"S109 file not found: {s109_file}")
        return s109_results
    
    try:
        with open(s109_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            cleaned_content = remove_ansi_escape_codes(content)
            
            final_status_match = re.search(r'final status: (\d+) password hashes cracked', cleaned_content)
            if not final_status_match or int(final_status_match.group(1)) == 0:
                print("S109: No passwords successfully cracked")
                return s109_results
            
            found_passwords = set()
            found_matches = re.findall(r'\[\*\] Found password data (.+?) for further processing', cleaned_content)
            
            for password_data in found_matches:
                found_passwords.add(password_data.strip())
            
            s109_results['found_passwords'] = list(found_passwords)
            s109_results['total_passwords_found'] = len(found_passwords)
            
            cracked_matches = re.findall(r'\[\+\] Password hash cracked: (.+)', cleaned_content)
            
            for cracked_password in cracked_matches:
                s109_results['cracked_passwords'].append(cracked_password.strip())
            
            s109_results['total_hashes_cracked'] = len(s109_results['cracked_passwords'])
            
    except Exception as e:
        print(f"Failed to process S109 file: {e}")
    
    return s109_results

def print_security_report(s106_data, s108_data, s109_data):
    """
    Print security analysis report to log file
    
    Args:
        s106_data (dict): S106 data
        s108_data (dict): S108 data
        s109_data (dict): S109 data
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
    logging.info("Firmware Security Data Extraction Report")
    logging.info("=" * 70)
    
    logging.info(f"S106 - Deep Key Search Results:")
    logging.info(f"   Files with keys found: {s106_data['total_files_with_keys']}")
    
    if s106_data['key_files']:
        logging.info(f"   Key file details:")
        for i, key_file in enumerate(s106_data['key_files'][:3], 1):
            logging.info(f"      {i}. {os.path.basename(key_file['file_path'])}")
            if key_file.get('pattern'):
                logging.info(f"         Pattern: {key_file['pattern']}")
            logging.info(f"         Content: [File size: {key_file['content_length']} bytes]")
        
        if len(s106_data['key_files']) > 3:
            logging.info(f"      ... {len(s106_data['key_files']) - 3} more files")
    
    logging.info(f"S108 - STACS Password Search Results:")
    logging.info(f"   Credential areas found: {s108_data['total_credentials']}")
    
    if s108_data['credentials']:
        logging.info(f"   Credential details:")
        for i, cred in enumerate(s108_data['credentials'][:3], 1):
            logging.info(f"      {i}. Path: {cred['path']}")
            hash_preview = cred['hash'][:50] + "..." if len(cred['hash']) > 50 else cred['hash']
            logging.info(f"         Hash: {hash_preview}")
    
    logging.info(f"S109 - John the Ripper Password Cracking Results:")
    logging.info(f"   Password data found: {s109_data['total_passwords_found']}")
    logging.info(f"   Successfully cracked hashes: {s109_data['total_hashes_cracked']}")
    
    if s109_data['cracked_passwords']:
        logging.info(f"   Successfully cracked passwords:")
        for i, cracked in enumerate(s109_data['cracked_passwords'], 1):
            logging.info(f"      {i}. {cracked}")
    
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
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to save file: {e}")
        return False

def main():
    import argparse
    import logging
    
    parser = argparse.ArgumentParser(description='Password Security Analysis Script')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    
    args = parser.parse_args()
    
    log_file = os.path.join(args.log_prefix, 'passwd.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    base_directory = args.input_prefix
    output_file = f"{args.output_prefix}/passwd.json"
    
    logging.info("Extracting security data...")
    
    if not os.path.exists(base_directory):
        logging.error(f"Directory not found: {base_directory}")
        return
    
    logging.info("Extracting S106 deep key search data...")
    s106_data = extract_s106_deep_key_search(base_directory)
    
    logging.info("Extracting S108 STACS password search data...")
    s108_data = extract_s108_stacs_password_search(base_directory)
    
    logging.info("Extracting S109 John the Ripper password cracking data...")
    s109_data = extract_s109_jtr_password_cracking(base_directory)
    
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
    
    print_security_report(s106_data, s108_data, s109_data)
    
    if save_to_json(result, output_file):
        logging.info(f"Security data extraction results saved to: {output_file}")
    else:
        logging.error("Failed to save file")

if __name__ == "__main__":
    main()

