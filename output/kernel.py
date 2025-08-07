#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kernel Information Extractor
Extract valid information from s24, s25, s26 module output files
"""

import re
import json
import sys
import os

class KernelInfoExtractor:
    def __init__(self):
        self.kernel_info = {
            "summary": {
                "total_vulnerabilities": 0,
                "verified_vulnerabilities": 0,
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
            
            content = self.clean_ansi_codes(content)
            
            version_match = re.search(r'Kernel version:\s*(\d+\.\d+\.\d+)', content)
            if version_match:
                info["kernel_version"] = version_match.group(1)
            
            module_pattern = r'Found kernel module ([^(]+) \([^)]+\) - License ([^-]+) - (.+)'
            modules = re.findall(module_pattern, content)
            for module in modules:
                info["kernel_modules"].append({
                    "path": self.clean_ansi_codes(module[0].strip()),
                    "license": self.clean_ansi_codes(module[1].strip()),
                    "status": self.clean_ansi_codes(module[2].strip())
                })
            
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
        
        # Get the directory path to look for CSV file
        file_dir = os.path.dirname(file_path)
        csv_file = None
        
        # Find the CSV file in the same directory
        if os.path.exists(file_dir):
            for filename in os.listdir(file_dir):
                if filename.startswith("cve_results_kernel_") and filename.endswith(".csv"):
                    csv_file = os.path.join(file_dir, filename)
                    break
        
        # Read verification status from CSV file
        verified_cves = set()
        if csv_file and os.path.exists(csv_file):
            try:
                with open(csv_file, 'r') as f:
                    for line in f:
                        if line.startswith("Kernel version"):
                            continue  # Skip header
                        parts = line.strip().split(';')
                        if len(parts) >= 7:
                            cve_id = parts[2]
                            verified_symbols = parts[5]
                            verified_compile = parts[6]
                            # If either symbols or compile verification is successful (1), mark as verified
                            if verified_symbols == "1" or verified_compile == "1":
                                verified_cves.add(cve_id)
            except Exception as e:
                print("Error reading CSV file: " + str(e))
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            content = self.clean_ansi_codes(content)
            
            version_match = re.search(r'Identified kernel version: (\d+\.\d+\.\d+)', content)
            if version_match:
                info["kernel_version"] = version_match.group(1)
            
            arch_match = re.search(r'Identified kernel architecture (\w+)', content)
            if arch_match:
                info["architecture"] = arch_match.group(1)
            
            vuln_pattern = r'([^:]+)\s*:\s*([^:]+)\s*:\s*(CVE-\d{4}-\d+)\s*:\s*([^:]+)\s*:\s*([^:]+)\s*:\s*([^:]+)\s*:\s*([^\n]+)'
            vulnerabilities = re.findall(vuln_pattern, content)
            
            for vuln in vulnerabilities:
                if not vuln[2].startswith('CVE-'):
                    continue
                
                exploit_info = self.clean_ansi_codes(vuln[6].strip())
                cve_id = self.clean_ansi_codes(vuln[2].strip())
                
                severity = "Unknown"
                cvss_score = self.clean_ansi_codes(vuln[3].strip())
                
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
                
                # Check if this CVE is verified
                verified = cve_id in verified_cves
                    
                vuln_data = {
                    "binary_name": self.clean_ansi_codes(vuln[0].strip()),
                    "version": self.clean_ansi_codes(vuln[1].strip()),
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "epss": self.clean_ansi_codes(vuln[4].strip()),
                    "source": self.clean_ansi_codes(vuln[5].strip()),
                    "exploit_info": exploit_info,
                    "verified": verified
                }
                
                info["vulnerabilities"].append(vuln_data)
                
        except Exception as e:
            print("Error reading s26 file: " + str(e))
        
        return info
    
    def update_summary(self, vuln_info):
        """Update summary information"""
        if not vuln_info:
            return
            
        all_vulns = vuln_info.get("vulnerabilities", [])
        
        self.kernel_info["summary"]["total_vulnerabilities"] = len(all_vulns)
        
        # Count verified vulnerabilities
        verified_count = sum(1 for vuln in all_vulns if vuln.get("verified", False))
        self.kernel_info["summary"]["verified_vulnerabilities"] = verified_count
        
        severity_dist = self.kernel_info["summary"]["severity_distribution"]
        for vuln in all_vulns:
            severity = vuln.get("severity", "Unknown")
            if severity in severity_dist:
                severity_dist[severity] += 1
    
    def process_files(self, input_prefix="../"):
        """Process all files"""
        files = {
            "s24": f"{input_prefix}/s24_kernel_bin_identifier.txt",
            "s25": f"{input_prefix}/s25_kernel_check.txt", 
            "s26": f"{input_prefix}/s26_kernel_vuln_verifier.txt"
        }
        
        for module, filename in files.items():
            if os.path.exists(filename):
                print("Processing " + filename + "...")
                if module == "s24":
                    pass
                elif module == "s25":
                    self.kernel_info["kernel_analysis"] = self.extract_s25_info(filename)
                elif module == "s26":
                    vuln_info = self.extract_s26_info(filename)
                    self.kernel_info["vulnerabilities"] = vuln_info["vulnerabilities"]
                    self.update_summary(vuln_info)
            else:
                # For S26, try to find alternative files
                if module == "s26":
                    # Look for kernel verification detailed log
                    alt_files = [
                        f"{input_prefix}/kernel_verification_*_detailed.log",
                        f"{input_prefix}/s26_kernel_vuln_verifier/kernel_verification_*_detailed.log"
                    ]
                    
                    import glob
                    for pattern in alt_files:
                        matching_files = glob.glob(pattern)
                        if matching_files:
                            filename = matching_files[0]
                            print("Processing " + filename + "...")
                            vuln_info = self.extract_s26_info(filename)
                            self.kernel_info["vulnerabilities"] = vuln_info["vulnerabilities"]
                            self.update_summary(vuln_info)
                            break
                    else:
                        print("Warning: No S26 kernel verification files found")
                else:
                    print("Warning: File " + filename + " does not exist")
    
    def print_summary(self):
        """Print summary information to log file"""
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
        
        logging.info("\n" + "="*60)
        logging.info("Kernel Security Analysis Summary")
        logging.info("="*60)
        
        summary = self.kernel_info["summary"]
        logging.info("Total Vulnerabilities: " + str(summary["total_vulnerabilities"]))
        logging.info("Verified Vulnerabilities: " + str(summary["verified_vulnerabilities"]))
        
        severity_dist = summary["severity_distribution"]
        if any(severity_dist.values()):
            logging.info("Severity Distribution:")
            logging.info("  - Critical: " + str(severity_dist['Critical']))
            logging.info("  - High: " + str(severity_dist['High']))
            logging.info("  - Medium: " + str(severity_dist['Medium']))
            logging.info("  - Low: " + str(severity_dist['Low']))
            logging.info("  - Unknown: " + str(severity_dist['Unknown']))
        
        kernel_analysis = self.kernel_info["kernel_analysis"]
        if kernel_analysis.get("kernel_version"):
            logging.info("Kernel Version: " + kernel_analysis['kernel_version'])
        if kernel_analysis.get("kernel_modules"):
            logging.info("Kernel Modules Found: " + str(len(kernel_analysis['kernel_modules'])))
        
        logging.info("="*60)
    
    def save_json(self, output_file="../result/kernel.json"):
        """Save results to JSON file"""
        import logging
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.kernel_info, f, indent=2)
            logging.info("Results saved to: " + output_file)
        except Exception as e:
            logging.error("Error saving JSON file: " + str(e))

def main():
    import argparse
    import logging
    
    parser = argparse.ArgumentParser(description='Kernel Information Extractor')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    
    args = parser.parse_args()
    
    input_prefix = args.input_prefix
    output_prefix = args.output_prefix
    log_prefix = args.log_prefix
    
    log_file = os.path.join(log_prefix, 'kernel.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    logging.info("Kernel Information Extractor Starting...")
    
    extractor = KernelInfoExtractor()
    extractor.process_files(input_prefix)
    extractor.print_summary()
    extractor.save_json(f'{output_prefix}/kernel.json')
    
    logging.info("Processing Complete!")

if __name__ == "__main__":
    main()

