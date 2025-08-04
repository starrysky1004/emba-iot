#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json
import os
from collections import defaultdict

def parse_license_summary(file_path):
    """
    Parse f10_license_summary.txt file and extract binary information
    
    Args:
        file_path (str): Path to f10_license_summary.txt file
    
    Returns:
        list: List of dictionaries containing binary, product, version, license info
    """
    binary_info_list = []
    
    # Regular expression pattern for matching
    pattern = r'\[\+\] Binary: (.+?) / Product: (.+?) / Version: (.+?) / License: (.+?)$'
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                
                # Match lines containing binary information
                match = re.match(pattern, line)
                if match:
                    binary_info = {
                        'binary': match.group(1).strip(),
                        'product': match.group(2).strip(),
                        'version': match.group(3).strip(),
                        'license': match.group(4).strip()
                    }
                    binary_info_list.append(binary_info)
    
    except FileNotFoundError:
        print(f"错误: 找不到文件 {file_path}")
        return []
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        return []
    
    return binary_info_list

def generate_license_summary(binary_info_list):
    """
    Generate license summary grouped by license type
    
    Args:
        binary_info_list (list): List containing binary information
    
    Returns:
        dict: Dictionary with license summary information
    """
    # Group by license
    license_groups = defaultdict(list)
    for info in binary_info_list:
        license_type = info['license']
        license_groups[license_type].append(info)
    
    # Create summary structure
    license_summary = {}
    for license_type, items in license_groups.items():
        # Sort components by binary name
        sorted_items = sorted(items, key=lambda x: x['binary'])
        license_summary[license_type] = {
            'count': len(items),
            'components': sorted_items
        }
    
    return license_summary

def save_json_output(binary_info_list, output_file):
    """
    Save license information to JSON file
    
    Args:
        binary_info_list (list): List containing binary information
        output_file (str): Output JSON file path
    """
    # Create result directory if it doesn't exist
    result_dir = os.path.dirname(output_file)
    if result_dir and not os.path.exists(result_dir):
        os.makedirs(result_dir)
    
    # Filter out components with "No license identified"
    filtered_components = [comp for comp in binary_info_list if comp['license'] != 'No license identified']
    
    # Generate license summary from filtered components
    license_summary = generate_license_summary(filtered_components)
    
    # Create comprehensive JSON structure
    json_data = {
        'metadata': {
            'total_components': len(filtered_components),
            'total_licenses': len(license_summary),
            'filtered_out_components': len(binary_info_list) - len(filtered_components),
            'generated_at': None  # Could add timestamp if needed
        },
        'components': filtered_components,
        'license_summary': license_summary
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        return False

def print_summary_stats(binary_info_list, license_summary):
    """
    Print summary statistics to log file
    
    Args:
        binary_info_list (list): List containing binary information
        license_summary (dict): License summary dictionary
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
    
    # Filter out components with "No license identified"
    filtered_components = [comp for comp in binary_info_list if comp['license'] != 'No license identified']
    filtered_out_count = len(binary_info_list) - len(filtered_components)
    
    logging.info("🔍 解析许可证信息文件...")
    logging.info("="*60)
    logging.info(f"✅ 成功解析 {len(binary_info_list)} 个组件信息")
    logging.info(f"📋 发现 {len(license_summary)} 种不同的许可证类型")
    logging.info(f"🚫 过滤掉 {filtered_out_count} 个未识别许可证的组件")
    
    logging.info("许可证类型统计：")
    logging.info("-" * 40)
    for license_type, info in sorted(license_summary.items()):
        logging.info(f"  • {license_type}: {info['count']} 个组件")

def main():
    import argparse
    import logging
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='许可证分析脚本')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    
    args = parser.parse_args()
    
    # 配置日志 - 使用独立的日志文件
    log_file = os.path.join(args.log_prefix, 'license.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    # File paths
    input_file = f"{args.input_prefix}/f10_license_summary.txt"
    output_file = f"{args.output_prefix}/license.json"
    
    # Parse file
    binary_info_list = parse_license_summary(input_file)
    
    if binary_info_list:
        # Generate license summary
        license_summary = generate_license_summary(binary_info_list)
        
        # Print summary statistics
        print_summary_stats(binary_info_list, license_summary)
        
        # Save to JSON file
        if save_json_output(binary_info_list, output_file):
            logging.info(f"🎉 处理完成！结果已保存到 {output_file}")
        else:
            logging.error("❌ JSON文件保存失败")
    else:
        logging.error("❌ 没有找到任何组件信息")

if __name__ == "__main__":
    main()
