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
    
    pattern = r'\[\+\] Binary: (.+?) / Product: (.+?) / Version: (.+?) / License: (.+?)$'
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                
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
        print(f"Error: File not found {file_path}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
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
    license_groups = defaultdict(list)
    for info in binary_info_list:
        license_type = info['license']
        license_groups[license_type].append(info)
    
    license_summary = {}
    for license_type, items in license_groups.items():
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
    result_dir = os.path.dirname(output_file)
    if result_dir and not os.path.exists(result_dir):
        os.makedirs(result_dir)
    
    filtered_components = [comp for comp in binary_info_list if comp['license'] != 'No license identified']
    
    license_summary = generate_license_summary(filtered_components)
    
    json_data = {
        'metadata': {
            'total_components': len(filtered_components),
            'total_licenses': len(license_summary),
            'filtered_out_components': len(binary_info_list) - len(filtered_components),
            'generated_at': None
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
    
    logger = logging.getLogger()
    if not logger.handlers:
        logging.basicConfig(
            filename='../result/scripts.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            filemode='a',
            encoding='utf-8'
        )
    
    filtered_components = [comp for comp in binary_info_list if comp['license'] != 'No license identified']
    filtered_out_count = len(binary_info_list) - len(filtered_components)
    
    logging.info("Parsing license information file...")
    logging.info("="*60)
    logging.info(f"Successfully parsed {len(binary_info_list)} component information")
    logging.info(f"Found {len(license_summary)} different license types")
    logging.info(f"Filtered out {filtered_out_count} components with unidentified licenses")
    
    logging.info("License type statistics:")
    logging.info("-" * 40)
    for license_type, info in sorted(license_summary.items()):
        logging.info(f"  • {license_type}: {info['count']} components")

def main():
    import argparse
    import logging
    
    parser = argparse.ArgumentParser(description='License Analysis Script')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    
    args = parser.parse_args()
    
    log_file = os.path.join(args.log_prefix, 'license.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        filemode='a',
        encoding='utf-8'
    )
    
    input_file = f"{args.input_prefix}/f10_license_summary.txt"
    output_file = f"{args.output_prefix}/license.json"
    
    binary_info_list = parse_license_summary(input_file)
    
    if binary_info_list:
        license_summary = generate_license_summary(binary_info_list)
        
        print_summary_stats(binary_info_list, license_summary)
        
        if save_json_output(binary_info_list, output_file):
            logging.info(f"Processing complete! Results saved to {output_file}")
        else:
            logging.error("Failed to save JSON file")
    else:
        logging.error("No component information found")

if __name__ == "__main__":
    main()

