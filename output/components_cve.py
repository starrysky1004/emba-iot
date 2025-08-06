#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE信息提取脚本
从f17_cve_bin_tool文件夹中的CSV文件提取组件漏洞信息，生成JSON文件
跳过包含kernel的文件
"""

import os
import csv
import json
import glob
from pathlib import Path
from typing import Dict, List, Any


def parse_csv_file(csv_file_path: str) -> List[Dict[str, Any]]:
    """
    解析CSV文件并提取CVE信息
    
    Args:
        csv_file_path: CSV文件路径
        
    Returns:
        包含CVE信息的字典列表
    """
    vulnerabilities = []
    
    try:
        with open(csv_file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                # 清理数据，移除空值和vendor字段
                cleaned_row = {k: v.strip() if isinstance(v, str) else v 
                             for k, v in row.items() 
                             if v and v.strip() and k != 'vendor'}
                
                # 转换score为数值类型
                if 'score' in cleaned_row:
                    try:
                        cleaned_row['score'] = float(cleaned_row['score'])
                    except (ValueError, TypeError):
                        cleaned_row['score'] = None
                
                vulnerabilities.append(cleaned_row)
                
    except Exception as e:
        print(f"解析文件 {csv_file_path} 时出错: {e}")
        return []
    
    return vulnerabilities


def extract_component_info_from_filename(filename: str) -> Dict[str, str]:
    """
    从文件名中提取组件信息
    
    Args:
        filename: CSV文件名
        
    Returns:
        包含组件信息的字典
    """
    # 移除.csv扩展名
    name_without_ext = filename.replace('.csv', '')
    
    # 尝试从文件名中提取组件信息
    # 文件名格式通常是: uuid_component_version.csv
    parts = name_without_ext.split('_')
    
    component_info = {
        'component_name': '',
        'version': ''
    }
    
    # 尝试提取组件名和版本
    if len(parts) >= 3:
        # 假设最后一部分是版本号
        component_info['version'] = parts[-1]
        # 中间部分可能是组件名
        component_info['component_name'] = '_'.join(parts[1:-1])
    elif len(parts) == 2:
        component_info['component_name'] = parts[1]
    
    return component_info


def process_csv_files(csv_dir: str) -> Dict[str, Any]:
    """
    处理CSV文件并返回所有数据
    
    Args:
        csv_dir: CSV文件目录
        
    Returns:
        包含所有组件漏洞信息的字典
    """
    # 查找所有CSV文件
    csv_files = glob.glob(os.path.join(csv_dir, "*.csv"))
    
    print(f"找到 {len(csv_files)} 个CSV文件")
    
    all_data = {
        'total_components': 0,
        'total_vulnerabilities': 0,
        'severity_summary': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'components': []
    }
    
    processed_count = 0
    skipped_count = 0
    
    for csv_file in csv_files:
        filename = os.path.basename(csv_file)
        
        # 跳过包含kernel的文件
        if 'kernel' in filename.lower():
            skipped_count += 1
            continue
        
        # 提取组件信息
        component_info = extract_component_info_from_filename(filename)
        
        # 解析CSV文件
        vulnerabilities = parse_csv_file(csv_file)
        
        if not vulnerabilities:
            continue
        
        # 计算严重程度统计
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'CRITICAL']),
            'high': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'HIGH']),
            'medium': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'MEDIUM']),
            'low': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'LOW'])
        }
        
        # 创建组件数据
        component_data = {
            'component_name': component_info['component_name'],
            'version': component_info['version'],
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'vulnerabilities': vulnerabilities
        }
        
        all_data['components'].append(component_data)
        all_data['total_vulnerabilities'] += len(vulnerabilities)
        
        # 累加严重程度统计
        for severity in ['critical', 'high', 'medium', 'low']:
            all_data['severity_summary'][severity] += severity_counts[severity]
        
        processed_count += 1
    
    all_data['total_components'] = len(all_data['components'])
    
    # 按漏洞数量排序
    all_data['components'].sort(key=lambda x: x['total_vulnerabilities'], reverse=True)
    
    return all_data
    
    return all_data


def main():
    """主函数"""
    import argparse
    import logging
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='CVE信息提取脚本')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    
    args = parser.parse_args()
    
    # 配置日志 - 使用独立的日志文件
    log_file = os.path.join(args.log_prefix, 'components_cve.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    # 设置路径
    csv_dir = f"{args.input_prefix}/f17_cve_bin_tool"
    output_file = f"{args.output_prefix}/components_cve.json"
    
    logging.info("🔍 CVE信息提取脚本")
    logging.info("=" * 50)
    logging.info(f"📁 CSV文件目录: {csv_dir}")
    logging.info(f"📄 输出文件: {output_file}")
    
    # 检查CSV目录是否存在
    if not os.path.exists(csv_dir):
        logging.error(f"❌ 错误: CSV目录不存在: {csv_dir}")
        return
    
    # 处理CSV文件
    all_data = process_csv_files(csv_dir)
    
    # 写入JSON文件
    try:
        with open(output_file, 'w', encoding='utf-8') as json_file:
            json.dump(all_data, json_file, indent=2, ensure_ascii=False)
        
        logging.info(f"✅ 已生成: {output_file}")
        
    except Exception as e:
        logging.error(f"❌ 写入文件时出错: {e}")
    
    logging.info("🎉 脚本执行完成!")


if __name__ == "__main__":
    main() 
