#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Information Extraction Script
Extract component vulnerability information from CSV files in f17_cve_bin_tool folder, generate JSON file
Skip files containing kernel
"""

import os
import csv
import json
import glob
from pathlib import Path
from typing import Dict, List, Any


def parse_csv_file(csv_file_path: str) -> List[Dict[str, Any]]:
    """
    Parse CSV file and extract CVE information
    
    Args:
        csv_file_path: CSV file path
        
    Returns:
        List of dictionaries containing CVE information
    """
    vulnerabilities = []
    
    try:
        with open(csv_file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                cleaned_row = {k: v.strip() if isinstance(v, str) else v 
                             for k, v in row.items() 
                             if v and v.strip() and k != 'vendor'}
                
                if 'score' in cleaned_row:
                    try:
                        cleaned_row['score'] = float(cleaned_row['score'])
                    except (ValueError, TypeError):
                        cleaned_row['score'] = None
                
                vulnerabilities.append(cleaned_row)
                
    except Exception as e:
        print(f"Error parsing file {csv_file_path}: {e}")
        return []
    
    return vulnerabilities


def extract_component_info_from_filename(filename: str) -> Dict[str, str]:
    """
    Extract component information from filename
    
    Args:
        filename: CSV filename
        
    Returns:
        Dictionary containing component information
    """
    name_without_ext = filename.replace('.csv', '')
    
    parts = name_without_ext.split('_')
    
    component_info = {
        'component_name': '',
        'version': ''
    }
    
    if len(parts) >= 3:
        component_info['version'] = parts[-1]
        component_info['component_name'] = '_'.join(parts[1:-1])
    elif len(parts) == 2:
        component_info['component_name'] = parts[1]
    
    return component_info


def process_csv_files(csv_dir: str) -> Dict[str, Any]:
    """
    Process CSV files and return all data
    
    Args:
        csv_dir: CSV file directory
        
    Returns:
        Dictionary containing all component vulnerability information
    """
    csv_files = glob.glob(os.path.join(csv_dir, "*.csv"))
    
    print(f"Found {len(csv_files)} CSV files")
    
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
        
        if 'kernel' in filename.lower():
            skipped_count += 1
            continue
        
        component_info = extract_component_info_from_filename(filename)
        
        vulnerabilities = parse_csv_file(csv_file)
        
        if not vulnerabilities:
            continue
        
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'CRITICAL']),
            'high': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'HIGH']),
            'medium': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'MEDIUM']),
            'low': len([v for v in vulnerabilities if v.get('severity', '').upper() == 'LOW'])
        }
        
        component_data = {
            'component_name': component_info['component_name'],
            'version': component_info['version'],
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'vulnerabilities': vulnerabilities
        }
        
        all_data['components'].append(component_data)
        all_data['total_vulnerabilities'] += len(vulnerabilities)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            all_data['severity_summary'][severity] += severity_counts[severity]
        
        processed_count += 1
    
    all_data['total_components'] = len(all_data['components'])
    
    all_data['components'].sort(key=lambda x: x['total_vulnerabilities'], reverse=True)
    
    return all_data


def main():
    """Main function"""
    import argparse
    import logging
    
    parser = argparse.ArgumentParser(description='CVE Information Extraction Script')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    
    args = parser.parse_args()
    
    log_file = os.path.join(args.log_prefix, 'components_cve.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    csv_dir = f"{args.input_prefix}/f17_cve_bin_tool"
    output_file = f"{args.output_prefix}/components_cve.json"
    
    logging.info("CVE Information Extraction Script")
    logging.info("=" * 50)
    logging.info(f"CSV file directory: {csv_dir}")
    logging.info(f"Output file: {output_file}")
    
    if not os.path.exists(csv_dir):
        logging.error(f"Error: CSV directory not found: {csv_dir}")
        return
    
    all_data = process_csv_files(csv_dir)
    
    try:
        with open(output_file, 'w', encoding='utf-8') as json_file:
            json.dump(all_data, json_file, indent=2, ensure_ascii=False)
        
        logging.info(f"Generated: {output_file}")
        
    except Exception as e:
        logging.error(f"Error writing file: {e}")
    
    logging.info("Script execution completed!")


if __name__ == "__main__":
    main() 
