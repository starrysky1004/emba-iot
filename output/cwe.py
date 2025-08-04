#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import glob
from pathlib import Path

def extract_high_risk_vulnerabilities(log_directory):
    """
    从s17 CWE checker的log文件中提取高风险漏洞信息
    
    Args:
        log_directory (str): log文件所在目录路径
    
    Returns:
        list: 包含高风险漏洞信息的列表
    """
    vulnerabilities = []
    
    # 排除的低风险漏洞类型
    excluded_cwes = ['CWE676', 'CWE252', 'CWE476', 'CWE782']
    
    # 查找所有.log文件
    log_files = glob.glob(os.path.join(log_directory, "*.log"))
    
    for log_file in log_files:
        # 从文件名提取二进制文件名
        filename = os.path.basename(log_file)
        binary_name = filename.replace("cwe_", "").replace(".log", "")
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                # 跳过空文件
                if not content:
                    continue
                
                # 解析JSON内容
                cwe_data = json.loads(content)
                
                # 处理每个漏洞条目
                for vulnerability in cwe_data:
                    cwe_id = vulnerability.get('name', 'Unknown')
                    
                    # 跳过排除的漏洞类型
                    if cwe_id in excluded_cwes:
                        continue
                    
                    # 只保留最重要的信息
                    vuln_info = {
                        'binary_file': binary_name,
                        'vulnerability_type': cwe_id,
                        'addresses': vulnerability.get('addresses', []),
                        'symbols': vulnerability.get('symbols', []),
                        'description': vulnerability.get('description', 'No description')
                    }
                    
                    vulnerabilities.append(vuln_info)
                    
        except json.JSONDecodeError as e:
            print(f"❌ 解析JSON文件失败: {log_file} - {e}")
        except Exception as e:
            print(f"❌ 处理文件时发生错误: {log_file} - {e}")
    
    return vulnerabilities

def get_cwe_description(cwe_id):
    """获取CWE漏洞类型的详细描述"""
    cwe_descriptions = {
        'CWE78': 'OS Command Injection - 操作系统命令注入',
        'CWE119': 'Buffer Overflow - 缓冲区溢出',
        'CWE120': 'Buffer Copy without Checking Size - 未检查大小的缓冲区复制',
        'CWE125': 'Out-of-bounds Read - 越界读取',
        'CWE134': 'Use of Externally-Controlled Format String - 使用外部控制的格式化字符串',
        'CWE190': 'Integer Overflow or Wraparound - 整数溢出或回绕',
        'CWE215': 'Information Exposure Through Debug Information - 通过调试信息泄露信息',
        'CWE243': 'Creation of chroot Jail Without Changing Working Directory - 创建chroot监狱但未更改工作目录',
        'CWE332': 'Insufficient Entropy in PRNG - PRNG中熵不足',
        'CWE337': 'Predictable Seed in Pseudo-Random Number Generator (PRNG) - 伪随机数生成器中的可预测种子',
        'CWE367': 'Time-of-check Time-of-use (TOCTOU) Race Condition - 检查时间与使用时间竞争条件',
        'CWE415': 'Double Free - 双重释放',
        'CWE416': 'Use After Free - 释放后使用',
        'CWE426': 'Untrusted Search Path - 不可信搜索路径',
        'CWE467': 'Use of sizeof() on a Pointer Type - 对指针类型使用sizeof()',
        'CWE476': 'NULL Pointer Dereference - 空指针解引用',
        'CWE560': 'Use of umask() with chmod-style Argument - 使用chmod风格参数的umask()',
        'CWE676': 'Use of Potentially Dangerous Function - 使用潜在危险函数',
        'CWE782': 'Exposed IOCTL with Insufficient Access Control - 暴露的IOCTL访问控制不足',
        'CWE787': 'Out-of-bounds Write - 越界写入',
        'CWE789': 'Memory Allocation with Excessive Size Value - 内存分配大小值过大'
    }
    return cwe_descriptions.get(cwe_id, f'{cwe_id} - 未知漏洞类型')

def generate_vulnerability_summary(vulnerabilities):
    """生成漏洞统计摘要"""
    if not vulnerabilities:
        return {
            'total_high_risk_vulnerabilities': 0,
            'affected_binaries': 0,
            'vulnerability_types': {},
            'critical_count': 0
        }
    
    # 统计信息
    vuln_counts = {}
    affected_binaries = set()
    critical_cwes = ['CWE78', 'CWE119', 'CWE125', 'CWE134', 'CWE190', 'CWE215', 'CWE367', 'CWE415', 'CWE416', 'CWE476', 'CWE787', 'CWE789']
    critical_count = 0
    
    for vuln in vulnerabilities:
        vuln_type = vuln['vulnerability_type']
        vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        affected_binaries.add(vuln['binary_file'])
        
        if vuln_type in critical_cwes:
            critical_count += 1
    
    return {
        'total_high_risk_vulnerabilities': len(vulnerabilities),
        'affected_binaries': len(affected_binaries),
        'vulnerability_types': vuln_counts,
        'critical_count': critical_count,
        'binary_list': list(affected_binaries)
    }

def save_to_json(vulnerabilities, output_file):
    """保存结果到JSON文件"""
    # 生成摘要
    summary = generate_vulnerability_summary(vulnerabilities)
    
    # 为每个漏洞添加CWE描述
    for vuln in vulnerabilities:
        vuln['vulnerability_description'] = get_cwe_description(vuln['vulnerability_type'])
    
    # 构建完整结果
    result = {
        'scan_summary': summary,
        'high_risk_vulnerabilities': vulnerabilities
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ 保存文件失败: {e}")
        return False

def print_vulnerability_report(vulnerabilities):
    """打印漏洞报告到日志文件"""
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
    
    if not vulnerabilities:
        logging.info("✅ 未发现高风险CWE漏洞")
        return
    
    summary = generate_vulnerability_summary(vulnerabilities)
    
    logging.info("=" * 60)
    logging.info("🔍 高风险 CWE 漏洞分析报告")
    logging.info("=" * 60)
    logging.info(f"📊 高风险漏洞数量: {summary['total_high_risk_vulnerabilities']}")
    logging.info(f"📁 受影响二进制文件: {summary['affected_binaries']} 个")
    logging.info(f"🚨 严重漏洞: {summary['critical_count']} 个")
    
    logging.info("\n📋 高风险漏洞类型分布:")
    for vuln_type, count in sorted(summary['vulnerability_types'].items()):
        description = get_cwe_description(vuln_type)
        logging.info(f"  • {description}: {count} 个")
    
    logging.info(f"\n📂 受影响的二进制文件:")
    for binary in sorted(summary['binary_list']):
        logging.info(f"  • {binary}")
    
    logging.info("\n" + "=" * 60)

def main():
    import argparse
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='CWE漏洞分析脚本')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    
    args = parser.parse_args()
    
    # 设置路径
    log_directory = f"{args.input_prefix}/s17_cwe_checker"
    output_file = f"{args.output_prefix}/cwe.json"
    
    import logging
    # 配置日志 - 使用独立的日志文件
    log_file = os.path.join(args.log_prefix, 'cwe.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    logging.info("🔍 正在分析高风险CWE漏洞...")
    logging.info("📝 已排除: CWE676(危险函数), CWE252(未检查返回值), CWE476(空指针), CWE782(未知类型)")
    
    # 检查目录是否存在
    if not os.path.exists(log_directory):
        logging.error(f"❌ 目录不存在: {log_directory}")
        return
    
    # 提取高风险漏洞信息
    vulnerabilities = extract_high_risk_vulnerabilities(log_directory)
    
    # 打印报告
    print_vulnerability_report(vulnerabilities)
    
    # 保存到JSON文件
    if save_to_json(vulnerabilities, output_file):
        logging.info(f"✅ 高风险漏洞分析结果已保存到: {output_file}")
    else:
        logging.error(f"❌ 保存文件失败")

if __name__ == "__main__":
    main()
