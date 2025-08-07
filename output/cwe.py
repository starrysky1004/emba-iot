#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import glob
from pathlib import Path

def extract_high_risk_vulnerabilities(log_directory):
    """
    Extract high-risk vulnerability information from s17 CWE checker log files
    
    Args:
        log_directory (str): Log file directory path
    
    Returns:
        list: List containing high-risk vulnerability information
    """
    vulnerabilities = []
    
    excluded_cwes = ['CWE676', 'CWE252', 'CWE476', 'CWE782']
    
    log_files = glob.glob(os.path.join(log_directory, "*.log"))
    
    for log_file in log_files:
        filename = os.path.basename(log_file)
        binary_name = filename.replace("cwe_", "").replace(".log", "")
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                if not content:
                    continue
                
                cwe_data = json.loads(content)
                
                for vulnerability in cwe_data:
                    cwe_id = vulnerability.get('name', 'Unknown')
                    
                    if cwe_id in excluded_cwes:
                        continue
                    
                    vuln_info = {
                        'binary_file': binary_name,
                        'vulnerability_type': cwe_id,
                        'addresses': vulnerability.get('addresses', []),
                        'symbols': vulnerability.get('symbols', []),
                        'description': vulnerability.get('description', 'No description')
                    }
                    
                    vulnerabilities.append(vuln_info)
                    
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON file: {log_file} - {e}")
        except Exception as e:
            print(f"Error processing file: {log_file} - {e}")
    
    return vulnerabilities

def get_cwe_description(cwe_id):
    """Get detailed description of CWE vulnerability type"""
    cwe_descriptions = {
        'CWE78': 'OS Command Injection',
        'CWE119': 'Buffer Overflow',
        'CWE120': 'Buffer Copy without Checking Size',
        'CWE125': 'Out-of-bounds Read',
        'CWE134': 'Use of Externally-Controlled Format String',
        'CWE190': 'Integer Overflow or Wraparound',
        'CWE215': 'Information Exposure Through Debug Information',
        'CWE243': 'Creation of chroot Jail Without Changing Working Directory',
        'CWE332': 'Insufficient Entropy in PRNG',
        'CWE337': 'Predictable Seed in Pseudo-Random Number Generator (PRNG)',
        'CWE367': 'Time-of-check Time-of-use (TOCTOU) Race Condition',
        'CWE415': 'Double Free',
        'CWE416': 'Use After Free',
        'CWE426': 'Untrusted Search Path',
        'CWE467': 'Use of sizeof() on a Pointer Type',
        'CWE476': 'NULL Pointer Dereference',
        'CWE560': 'Use of umask() with chmod-style Argument',
        'CWE676': 'Use of Potentially Dangerous Function',
        'CWE782': 'Exposed IOCTL with Insufficient Access Control',
        'CWE787': 'Out-of-bounds Write',
        'CWE789': 'Memory Allocation with Excessive Size Value'
    }
    return cwe_descriptions.get(cwe_id, f'{cwe_id} - Unknown vulnerability type')

def generate_vulnerability_summary(vulnerabilities):
    """Generate vulnerability statistics summary"""
    if not vulnerabilities:
        return {
            'total_high_risk_vulnerabilities': 0,
            'affected_binaries': 0,
            'vulnerability_types': {},
            'critical_count': 0
        }
    
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
    """Save results to JSON file"""
    summary = generate_vulnerability_summary(vulnerabilities)
    
    for vuln in vulnerabilities:
        vuln['vulnerability_description'] = get_cwe_description(vuln['vulnerability_type'])
    
    result = {
        'scan_summary': summary,
        'high_risk_vulnerabilities': vulnerabilities
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to save file: {e}")
        return False

def print_vulnerability_report(vulnerabilities):
    """Print vulnerability report to log file"""
    import logging
    
    logger = logging.getLogger()
    if not logger.handlers:
        logging.basicConfig(
            filename='../result/scripts_log/cwe.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            filemode='a',
            encoding='utf-8'
        )
    
    if not vulnerabilities:
        logging.info("No high-risk CWE vulnerabilities found")
        return
    
    summary = generate_vulnerability_summary(vulnerabilities)
    
    logging.info("=" * 60)
    logging.info("High-Risk CWE Vulnerability Analysis Report")
    logging.info("=" * 60)
    logging.info(f"High-risk vulnerabilities: {summary['total_high_risk_vulnerabilities']}")
    logging.info(f"Affected binary files: {summary['affected_binaries']}")
    logging.info(f"Critical vulnerabilities: {summary['critical_count']}")
    
    logging.info("\nHigh-risk vulnerability type distribution:")
    for vuln_type, count in sorted(summary['vulnerability_types'].items()):
        description = get_cwe_description(vuln_type)
        logging.info(f"  • {description}: {count}")
    
    logging.info(f"\nAffected binary files:")
    for binary in sorted(summary['binary_list']):
        logging.info(f"  • {binary}")
    
    logging.info("\n" + "=" * 60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='CWE Vulnerability Analysis Script')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    
    args = parser.parse_args()
    
    log_directory = f"{args.input_prefix}/s17_cwe_checker"
    output_file = f"{args.output_prefix}/cwe.json"
    
    import logging
    log_file = os.path.join(args.log_prefix, 'cwe.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    logging.info("Analyzing high-risk CWE vulnerabilities...")
    logging.info("Excluded: CWE676(dangerous functions), CWE252(unchecked return values), CWE476(null pointers), CWE782(unknown types)")
    
    if not os.path.exists(log_directory):
        logging.error(f"Directory not found: {log_directory}")
        return
    
    vulnerabilities = extract_high_risk_vulnerabilities(log_directory)
    
    print_vulnerability_report(vulnerabilities)
    
    if save_to_json(vulnerabilities, output_file):
        logging.info(f"High-risk vulnerability analysis results saved to: {output_file}")
    else:
        logging.error(f"Failed to save file")

if __name__ == "__main__":
    main()

