#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内核信息提取器
从s24、s25、s26模块输出文件中提取有效信息
"""

import re
import json
import sys
import os
# from typing import Dict, List, Any  # 注释掉类型提示以兼容旧版本Python

class KernelInfoExtractor:
    def __init__(self):
        self.kernel_info = {
            "summary": {
                "exploitable_vulnerabilities": 0,
                "severity_distribution": {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Unknown": 0
                }
            },
            "kernel_analysis": {},
            "vulnerabilities": []
        }
    
    def clean_ansi_codes(self, text):
        """Remove ANSI escape sequences from text"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text).strip()
    
    def extract_s24_info(self, file_path):
        """Extract s24 kernel binary identification information"""
        # 由于不需要kernel_identification，此方法保留但不使用
        pass
    
    def extract_s25_info(self, file_path):
        """Extract s25 kernel check information"""
        info = {
            "kernel_version": "",
            "kernel_modules": [],
            "statistics": {}
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # 清理ANSI代码
            content = self.clean_ansi_codes(content)
            
            # 提取内核版本
            version_match = re.search(r'Kernel version:\s*(\d+\.\d+\.\d+)', content)
            if version_match:
                info["kernel_version"] = version_match.group(1)
            
            # 提取内核模块详细信息
            module_pattern = r'Found kernel module ([^(]+) \([^)]+\) - License ([^-]+) - (.+)'
            modules = re.findall(module_pattern, content)
            for module in modules:
                info["kernel_modules"].append({
                    "path": self.clean_ansi_codes(module[0].strip()),
                    "license": self.clean_ansi_codes(module[1].strip()),
                    "status": self.clean_ansi_codes(module[2].strip())
                })
            
            # 移除exploits提取部分
            
            # 提取统计信息
            stats_pattern = r'Statistics:(\d+\.\d+\.\d+)'
            stats_match = re.search(stats_pattern, content)
            if stats_match:
                info["statistics"]["version"] = stats_match.group(1)
            
            stats_pattern2 = r'Statistics1:(\d+):(\d+)'
            stats_match2 = re.search(stats_pattern2, content)
            if stats_match2:
                info["statistics"]["total_modules"] = int(stats_match2.group(1))
                info["statistics"]["other_count"] = int(stats_match2.group(2))
                
        except Exception as e:
            print("Error reading s25 file: " + str(e))
        
        return info
    
    def extract_s26_info(self, file_path):
        """Extract s26 kernel vulnerability verification information"""
        info = {
            "kernel_version": "",
            "architecture": "",
            "vulnerabilities": []
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # 清理ANSI代码
            content = self.clean_ansi_codes(content)
            
            # 提取内核版本
            version_match = re.search(r'Identified kernel version: (\d+\.\d+\.\d+)', content)
            if version_match:
                info["kernel_version"] = version_match.group(1)
            
            # 提取架构信息
            arch_match = re.search(r'Identified kernel architecture (\w+)', content)
            if arch_match:
                info["architecture"] = arch_match.group(1)
            
            # 提取漏洞信息 - 修复正则表达式以匹配实际格式
            vuln_pattern = r'([^:]+)\s*:\s*([^:]+)\s*:\s*(CVE-\d{4}-\d+)\s*:\s*([^:]+)\s*:\s*([^:]+)\s*:\s*([^:]+)\s*:\s*([^\n]+)'
            vulnerabilities = re.findall(vuln_pattern, content)
            
            for vuln in vulnerabilities:
                # 跳过不是漏洞信息的行
                if not vuln[2].startswith('CVE-'):
                    continue
                
                exploit_info = self.clean_ansi_codes(vuln[6].strip())
                
                severity = "Unknown"
                cvss_score = self.clean_ansi_codes(vuln[3].strip())
                
                # 根据CVSS分数判断严重程度
                try:
                    score = float(cvss_score.split()[0])
                    if score >= 9.0:
                        severity = "Critical"
                    elif score >= 7.0:
                        severity = "High"
                    elif score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
                except:
                    pass
                
                # 跳过exploit_info为"No exploit available"的漏洞
                if "no exploit available" in exploit_info.lower():
                    continue
                    
                vuln_data = {
                    "binary_name": self.clean_ansi_codes(vuln[0].strip()),
                    "version": self.clean_ansi_codes(vuln[1].strip()),
                    "cve_id": self.clean_ansi_codes(vuln[2].strip()),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "epss": self.clean_ansi_codes(vuln[4].strip()),
                    "source": self.clean_ansi_codes(vuln[5].strip()),
                    "exploit_info": exploit_info
                }
                
                info["vulnerabilities"].append(vuln_data)
                
        except Exception as e:
            print("Error reading s26 file: " + str(e))
        
        return info
    
    def update_summary(self, vuln_info):
        """更新汇总信息"""
        if not vuln_info:
            return
            
        # 获取可利用漏洞
        exploitable_vulns = vuln_info.get("vulnerabilities", [])
        
        # 更新汇总统计
        self.kernel_info["summary"]["exploitable_vulnerabilities"] = len(exploitable_vulns)
        
        # 统计严重程度分布
        severity_dist = self.kernel_info["summary"]["severity_distribution"]
        for vuln in exploitable_vulns:
            severity = vuln.get("severity", "Unknown")
            if severity in severity_dist:
                severity_dist[severity] += 1
    
    def process_files(self, input_prefix="../"):
        """处理所有文件"""
        files = {
            "s24": f"{input_prefix}/s24_kernel_bin_identifier.txt",
            "s25": f"{input_prefix}/s25_kernel_check.txt", 
            "s26": f"{input_prefix}/s26_kernel_vuln_verifier.txt"
        }
        
        for module, filename in files.items():
            if os.path.exists(filename):
                print("Processing " + filename + "...")
                if module == "s24":
                    # 跳过s24处理，因为不需要kernel_identification
                    pass
                elif module == "s25":
                    self.kernel_info["kernel_analysis"] = self.extract_s25_info(filename)
                elif module == "s26":
                    vuln_info = self.extract_s26_info(filename)
                    self.kernel_info["vulnerabilities"] = vuln_info["vulnerabilities"]
                    self.update_summary(vuln_info)
            else:
                print("Warning: File " + filename + " does not exist")
    
    def print_summary(self):
        """Print summary information to log file"""
        import logging
        
        # 获取当前日志配置
        logger = logging.getLogger()
        if not logger.handlers:
            logging.basicConfig(
                filename='../result/scripts/kernel.log',
                level=logging.INFO,
                format='%(asctime)s - %(message)s',
                filemode='a',
                encoding='utf-8'
            )
        
        logging.info("\n" + "="*60)
        logging.info("🐧 Kernel Security Analysis Summary")
        logging.info("="*60)
        
        # Summary information
        summary = self.kernel_info["summary"]
        logging.info("🔍 Exploitable Vulnerabilities: " + str(summary["exploitable_vulnerabilities"]))
        
        # Severity distribution
        severity_dist = summary["severity_distribution"]
        if any(severity_dist.values()):
            logging.info("📊 Severity Distribution:")
            logging.info("  - Critical: " + str(severity_dist['Critical']))
            logging.info("  - High: " + str(severity_dist['High']))
            logging.info("  - Medium: " + str(severity_dist['Medium']))
            logging.info("  - Low: " + str(severity_dist['Low']))
            logging.info("  - Unknown: " + str(severity_dist['Unknown']))
        
        # Kernel analysis information
        kernel_analysis = self.kernel_info["kernel_analysis"]
        if kernel_analysis.get("kernel_version"):
            logging.info("🔧 Kernel Version: " + kernel_analysis['kernel_version'])
        if kernel_analysis.get("kernel_modules"):
            logging.info("📦 Kernel Modules Found: " + str(len(kernel_analysis['kernel_modules'])))
        
        logging.info("="*60)
    
    def save_json(self, output_file="../result/kernel.json"):
        """Save results to JSON file"""
        import logging
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.kernel_info, f, indent=2)
            logging.info("✅ Results saved to: " + output_file)
        except Exception as e:
            logging.error("❌ Error saving JSON file: " + str(e))

def main():
    import argparse
    import logging
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Kernel Information Extractor')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    
    args = parser.parse_args()
    
    # 设置具体路径
    input_prefix = args.input_prefix
    output_prefix = args.output_prefix
    log_prefix = args.log_prefix
    
    # 配置日志 - 使用独立的日志文件
    log_file = os.path.join(log_prefix, 'kernel.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    logging.info("🐧 Kernel Information Extractor Starting...")
    
    extractor = KernelInfoExtractor()
    extractor.process_files(input_prefix)
    extractor.print_summary()
    extractor.save_json(f'{output_prefix}/kernel.json')
    
    logging.info("🎉 Processing Complete!")

if __name__ == "__main__":
    main()
