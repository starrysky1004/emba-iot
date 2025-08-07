#!/usr/bin/env python3
"""
Main script to run all analysis scripts - continuous running version
"""

import os
import sys
import subprocess
import logging
import time
import json
import re
from datetime import datetime
from pathlib import Path

def setup_logging(log_prefix):
    """Setup logging configuration"""
    os.makedirs(log_prefix, exist_ok=True)
    
    log_file = os.path.join(log_prefix, 'scripts.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filemode='w',
        encoding='utf-8'
    )

def parse_emba_log(emba_log_path):
    """Parse emba.log file to determine which modules are completed"""
    completed_modules = set()
    
    if not os.path.exists(emba_log_path):
        logging.warning(f"EMBA log file not found: {emba_log_path}")
        return completed_modules
    
    try:
        with open(emba_log_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        module_patterns = [
            'S24_kernel_bin_identifier finished',
            'S25_kernel_check finished', 
            'S26_kernel_vuln_verifier finished',
            'S17_cwe_checker finished',
            'F10_license_summary finished',
            'S106_deep_password_search finished',
            'S108_stacs_password_search finished',
            'S109_jtr_local_pw_cracking finished',
            'S21_python_check finished',
            'S22_php_check finished',
            'S27_perl_check finished',
            'F15_cyclonedx_sbom finished',
            'F17_cve_bin_tool finished'
        ]
        
        for pattern in module_patterns:
            if re.search(pattern, content):
                completed_modules.add(pattern)
                logging.info(f"Module completed detected: {pattern}")
        
        if re.search(r'Test ended', content):
            completed_modules.add('test_ended')
            logging.info("EMBA test ended detected")
            
    except Exception as e:
        logging.error(f"Error parsing EMBA log: {e}")
    
    return completed_modules

def should_run_script(script_name, completed_modules):
    """Determine whether to run script based on EMBA log results"""
    script_conditions = {
        'kernel.py': ['S24_kernel_bin_identifier finished', 'S25_kernel_check finished', 'S26_kernel_vuln_verifier finished'],
        'components_cve.py': ['F17_cve_bin_tool finished'],
        'cwe.py': ['S17_cwe_checker finished'],
        'license.py': ['F10_license_summary finished'],
        'passwd.py': ['S109_jtr_local_pw_cracking finished'],  
        'scripts_vul.py': ['S21_python_check finished', 'S22_php_check finished', 'S27_perl_check finished']
    }
    
    required_patterns = script_conditions.get(script_name, [])
    if not required_patterns:
        return True
    
    for pattern in required_patterns:
        if pattern not in completed_modules:
            return False
    
    return True

def run_script(script_name, input_prefix, output_prefix, log_prefix):
    """Run a single script"""
    try:
        logging.info(f"Starting: {script_name}")
        
        env = os.environ.copy()
        env['OUTPUT_PREFIX'] = output_prefix
        env['LOG_PREFIX'] = log_prefix
        
        os.makedirs(output_prefix, exist_ok=True)
        
        script_log_prefix = os.path.join(log_prefix, 'scripts_log')
        os.makedirs(script_log_prefix, exist_ok=True)
        
        cmd = [
            sys.executable, script_name,
            '--input-prefix', input_prefix,
            '--output-prefix', output_prefix,
            '--log-prefix', script_log_prefix
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd(), env=env)
        
        if result.returncode == 0:
            logging.info(f"Success: {script_name}")
            check_output_files(script_name, output_prefix)
        else:
            logging.error(f"Failed: {script_name}")
            logging.error(f"Error output: {result.stderr}")
            
        return result.returncode == 0
    except Exception as e:
        logging.error(f"Exception running {script_name}: {e}")
        return False

def check_output_files(script_name, output_prefix):
    """Check if script generated output files"""
    script_outputs = {
        'kernel.py': ['kernel.json'],
        'components_cve.py': ['components_cve.json'],
        'cwe.py': ['cwe.json'],
        'license.py': ['license.json'],
        'passwd.py': ['passwd.json'],
        'scripts_vul.py': ['scripts_vul.json']
    }
    
    expected_files = script_outputs.get(script_name, [])
    for filename in expected_files:
        file_path = os.path.join(output_prefix, filename)
        if os.path.exists(file_path):
            logging.info(f"Output file generated: {filename}")
        else:
            logging.warning(f"Output file not generated: {filename}")

def move_json_files_to_results(input_prefix, output_prefix):
    """Move JSON files generated by output scripts to results directory"""
    try:
        output_script_files = {
            'kernel.json',
            'components_cve.json', 
            'cwe.json',
            'license.json',
            'passwd.json',
            'scripts_vul.json'
        }
        
        for filename in output_script_files:
            source_path = os.path.join(input_prefix, filename)
            target_path = os.path.join(output_prefix, filename)
            
            if os.path.exists(source_path) and not os.path.exists(target_path):
                try:
                    import shutil
                    shutil.move(source_path, target_path)
                    logging.info(f"Moved output script file: {filename} -> results/")
                except Exception as e:
                    logging.error(f"Failed to move file {filename}: {e}")
            elif os.path.exists(source_path) and os.path.exists(target_path):
                logging.info(f"File already exists: {filename}")
            else:
                pass
                    
    except Exception as e:
        logging.error(f"Error moving JSON files: {e}")

def copy_sbom_file(input_prefix, output_prefix):
    """Copy SBOM file to results directory"""
    try:
        sbom_source = os.path.join(input_prefix, 'SBOM', 'EMBA_cyclonedx_sbom.json')
        sbom_target = os.path.join(output_prefix, 'SBOM.json')
        
        if os.path.exists(sbom_source) and not os.path.exists(sbom_target):
            try:
                import shutil
                shutil.copy2(sbom_source, sbom_target)
                logging.info(f"Copied SBOM file: EMBA_cyclonedx_sbom.json -> results/SBOM.json")
            except Exception as e:
                logging.error(f"Failed to copy SBOM file: {e}")
        elif os.path.exists(sbom_source) and os.path.exists(sbom_target):
            logging.info(f"SBOM file already exists: SBOM.json")
        else:
            logging.debug(f"SBOM file not found: {sbom_source}")
                    
    except Exception as e:
        logging.error(f"Error copying SBOM file: {e}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Main script to run all analysis scripts - continuous running version')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    parser.add_argument('--interval', type=int, default=30, help='Run interval (seconds)')
    
    args = parser.parse_args()
    
    setup_logging(args.log_prefix)
    
    logging.info("Starting continuous analysis scripts")
    logging.info(f"Run interval: {args.interval} seconds")
    logging.info("=" * 60)
    
    scripts = [
        "kernel.py",
        "components_cve.py", 
        "cwe.py",
        "license.py",
        "passwd.py",
        "scripts_vul.py"
    ]
    
    emba_log_path = os.path.join(args.input_prefix, 'emba.log')
    run_count = 0
    test_ended = False
    
    while True:
        run_count += 1
        logging.info(f"Run #{run_count} started")
        
        completed_modules = parse_emba_log(emba_log_path)
        
        if 'test_ended' in completed_modules:
            test_ended = True
            logging.info("EMBA test ended detected, this is the last run")
        
        success_count = 0
        total_count = 0
        
        for script in scripts:
            if should_run_script(script, completed_modules):
                total_count += 1
                if os.path.exists(script):
                    if run_script(script, args.input_prefix, args.output_prefix, args.log_prefix):
                        success_count += 1
                else:
                    logging.warning(f"Script not found: {script}")
        
        move_json_files_to_results(args.input_prefix, args.output_prefix)
        
        if 'F15_cyclonedx_sbom finished' in completed_modules:
            copy_sbom_file(args.input_prefix, args.output_prefix)
        
        logging.info(f"Run result: {success_count}/{total_count} successful")
        
        if test_ended:
            logging.info("Last run completed, program ending")
            break
        
        logging.info(f"Waiting {args.interval} seconds for next run...")
        time.sleep(args.interval)
    
    logging.info("=" * 60)
    logging.info("All runs completed!")

if __name__ == "__main__":
    main() 
