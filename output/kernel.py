#!/usr/bin/env python3
"""
Kernel vulnerability information extractor for EMBA
Extracts and consolidates kernel-related information from s25 and s26 modules
"""

import os
import re
import json
import argparse
import logging

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
            "kernel_analysis": {
                "kernel_version": "",
                "kernel_modules": [],
                "statistics": {
                    "version": "",
                    "total_modules": 0,
                    "other_count": 0
                }
            },
            "s25_vulnerabilities": [],
            "s26_vulnerabilities": []
        }

    def clean_ansi_codes(self, text):
        """Remove ANSI color codes from text"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def extract_s25_info(self, file_path):
        """Extract s25 kernel check information"""
        info = {
            "kernel_version": "",
            "kernel_modules": [],
            "statistics": {
                "version": "",
                "total_modules": 0,
                "other_count": 0
            },
            "vulnerabilities": []
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            content = self.clean_ansi_codes(content)
            
            # Extract kernel version
            version_match = re.search(r'Kernel version:\s*(\d+\.\d+\.\d+)', content)
            if version_match:
                info["kernel_version"] = version_match.group(1)
            
            # Extract kernel modules - look for "Found kernel module" lines
            module_pattern = r'Found kernel module ([^:]+) \([^)]+\) - License ([^-]+) - (.+)'
            modules = re.findall(module_pattern, content)
            for module in modules:
                info["kernel_modules"].append({
                    "path": self.clean_ansi_codes(module[0].strip()),
                    "license": self.clean_ansi_codes(module[1].strip()),
                    "status": self.clean_ansi_codes(module[2].strip())
                })
            
            # Extract statistics
            stats_pattern = r'Statistics:(\d+\.\d+\.\d+)'
            stats_match = re.search(stats_pattern, content)
            if stats_match:
                info["statistics"]["version"] = stats_match.group(1)
            
            stats_pattern2 = r'Statistics1:(\d+):(\d+)'
            stats_match2 = re.search(stats_pattern2, content)
            if stats_match2:
                info["statistics"]["total_modules"] = int(stats_match2.group(1))
                info["statistics"]["other_count"] = int(stats_match2.group(2))
            
            # Extract CVE vulnerabilities from s25 - look for [+] [CVE-XXXX-XXXX] pattern
            cve_pattern = r'\[\+\]\s*\[CVE-(\d{4}-\d+)\]\s*([^\n]+)'
            cve_matches = re.findall(cve_pattern, content)
            
            for cve_match in cve_matches:
                cve_id = f"CVE-{cve_match[0]}"
                description = cve_match[1].strip()
                
                # Extract exposure information - look for the Exposure line after the CVE
                exposure = "Unknown"
                cve_section_pattern = rf'\[\+\]\s*\[{re.escape(cve_id)}\][^\n]*\n(.*?)(?=\[\+\]\s*\[CVE-|$)'
                cve_section_match = re.search(cve_section_pattern, content, re.DOTALL)
                if cve_section_match:
                    cve_section = cve_section_match.group(1)
                    exposure_match = re.search(r'Exposure:\s*([^\n]+)', cve_section)
                    if exposure_match:
                        exposure = exposure_match.group(1).strip()
                
                # Extract exploit-db information
                exploit_db = ""
                if cve_section_match:
                    cve_section = cve_section_match.group(1)
                    exploit_match = re.search(r'exploit-db:\s*(\d+)', cve_section)
                    if exploit_match:
                        exploit_db = exploit_match.group(1)
                
                vuln_data = {
                    "cve_id": cve_id,
                    "description": description,
                    "exposure": exposure,
                    "exploit_db": exploit_db
                }
                
                info["vulnerabilities"].append(vuln_data)
                
        except Exception as e:
            print(f"Error reading s25 file: {e}")
        
        return info

    def extract_s26_info(self, file_path):
        """Extract s26 kernel vulnerability verification information"""
        vuln_info = {"vulnerabilities": []}
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            content = self.clean_ansi_codes(content)
            
            # First try to parse the CSV file if it exists
            # Look for CSV file in the same directory as the txt file
            import glob
            import os
            
            # Get the directory of the txt file
            txt_dir = os.path.dirname(file_path)
            if txt_dir:
                csv_pattern = os.path.join(txt_dir, "s26_kernel_vuln_verifier/cve_results_kernel_*.csv")
            else:
                csv_pattern = "cve_results_kernel_*.csv"
            
            csv_files = glob.glob(csv_pattern)
            
            if csv_files:
                # Parse CSV file for more detailed information
                csv_file_path = csv_files[0]
                with open(csv_file_path, 'r') as csv_f:
                    csv_content = csv_f.read()
                
                # Skip header line
                lines = csv_content.strip().split('\n')[1:]
                for line in lines:
                    parts = line.split(';')
                    if len(parts) >= 7:
                        kernel_version = parts[0]
                        architecture = parts[1]
                        cve_id = parts[2]
                        cvss_v2 = parts[3]
                        cvss_v3 = parts[4]
                        verified_symbols = parts[5]
                        verified_compile = parts[6]
                        
                        # Determine severity based on CVSS v3 score
                        severity = "Unknown"
                        cvss_score = cvss_v3 if cvss_v3 != "NA" else cvss_v2
                        if cvss_score != "NA":
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
                            except ValueError:
                                pass
                        
                        # Check if verified - only if either symbols or compile verification is successful
                        verified = verified_symbols == "1" or verified_compile == "1"
                        
                        vuln_data = {
                            "binary_name": "linux_kernel",
                            "version": kernel_version,
                            "cve_id": cve_id,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "source": "kernel_verification",
                            "exploit_info": "No exploit available",
                            "verified": verified
                        }

                        vuln_info["vulnerabilities"].append(vuln_data)
            else:
                vuln_pattern = r'\[\+\]\s*(CVE-\d{4}-\d+)\s*\(([^)]+)\)\s*-\s*([^\s]+)\s*verified\s*-\s*([^\n]+)'
                vuln_matches = re.findall(vuln_pattern, content)
                
                for match in vuln_matches:
                    cve_id = match[0].strip()
                    cvss_score = match[1].strip()
                    binary_path = match[2].strip()
                    verification_type = match[3].strip()
                    
                    # Determine severity based on CVSS score
                    severity = "Unknown"
                    try:
                        score = float(cvss_score)
                        if score >= 9.0:
                            severity = "Critical"
                        elif score >= 7.0:
                            severity = "High"
                        elif score >= 4.0:
                            severity = "Medium"
                        else:
                            severity = "Low"
                    except ValueError:
                        pass
                    
                    vuln_data = {
                        "binary_name": binary_path,
                        "version": "4.4.282",  # Default version
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "source": "s26_kernel_vuln_verifier",
                        "exploit_info": verification_type,
                        "verified": True  # These are verified since they appear in the verified list
                    }
                    
                    vuln_info["vulnerabilities"].append(vuln_data)
                
        except Exception as e:
            print(f"Error reading s26 file: {e}")
        
        return vuln_info

    def update_summary(self):
        """Update summary based on current vulnerabilities"""
        s25_count = len(self.kernel_info["s25_vulnerabilities"])
        s26_count = len(self.kernel_info["s26_vulnerabilities"])
        
        self.kernel_info["summary"]["total_vulnerabilities"] = s25_count + s26_count
        
        # Count only verified vulnerabilities from s26
        verified_count = sum(1 for vuln in self.kernel_info["s26_vulnerabilities"] if vuln.get("verified", False))
        self.kernel_info["summary"]["verified_vulnerabilities"] = verified_count
        
        # Reset severity distribution
        for severity in self.kernel_info["summary"]["severity_distribution"]:
            self.kernel_info["summary"]["severity_distribution"][severity] = 0
        
        # Count severity from s26 vulnerabilities
        for vuln in self.kernel_info["s26_vulnerabilities"]:
            severity = vuln.get("severity", "Unknown")
            if severity in self.kernel_info["summary"]["severity_distribution"]:
                self.kernel_info["summary"]["severity_distribution"][severity] += 1

    def process_s25(self, input_prefix="../"):
        """Process s25 data only"""
        s25_file = f"{input_prefix}/s25_kernel_check.txt"
        if os.path.exists(s25_file):
            print("Processing s25_kernel_check.txt...")
            s25_info = self.extract_s25_info(s25_file)
            
            # Update kernel_analysis (without vulnerabilities)
            self.kernel_info["kernel_analysis"] = {
                "kernel_version": s25_info["kernel_version"],
                "kernel_modules": s25_info["kernel_modules"],
                "statistics": s25_info["statistics"]
            }
            
            # Update s25_vulnerabilities
            self.kernel_info["s25_vulnerabilities"] = s25_info["vulnerabilities"]
            print(f"Extracted {len(s25_info['vulnerabilities'])} s25 vulnerabilities")
        else:
            print("Warning: s25_kernel_check.txt not found")
        
        self.update_summary()

    def process_s26(self, input_prefix="../"):
        """Process s26 data and regenerate complete JSON"""
        # Delete existing kernel.json
        output_file = "../result/kernel.json"
        if os.path.exists(output_file):
            os.remove(output_file)
            print("Deleted existing kernel.json file")
        
        # Process s25 first
        self.process_s25(input_prefix)
        
        # Process s26
        s26_file = f"{input_prefix}/s26_kernel_vuln_verifier.txt"
        if os.path.exists(s26_file):
            print("Processing s26_kernel_vuln_verifier.txt...")
            s26_info = self.extract_s26_info(s26_file)
            self.kernel_info["s26_vulnerabilities"] = s26_info["vulnerabilities"]
            print(f"Extracted {len(s26_info['vulnerabilities'])} s26 vulnerabilities")
        else:
            # Try alternative s26 files
            import glob
            alt_files = [
                f"{input_prefix}/kernel_verification_*_detailed.log",
                f"{input_prefix}/s26_kernel_vuln_verifier/kernel_verification_*_detailed.log"
            ]
            
            for pattern in alt_files:
                matching_files = glob.glob(pattern)
                if matching_files:
                    filename = matching_files[0]
                    print(f"Processing {filename}...")
                    s26_info = self.extract_s26_info(filename)
                    self.kernel_info["s26_vulnerabilities"] = s26_info["vulnerabilities"]
                    print(f"Extracted {len(s26_info['vulnerabilities'])} s26 vulnerabilities")
                    break
            else:
                print("Warning: No S26 kernel verification files found")
        
        self.update_summary()

    def save_json(self, output_file="../result/kernel.json"):
        """Save kernel information to JSON file"""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.kernel_info, f, indent=2, ensure_ascii=False)
            print(f"Kernel information saved to {output_file}")
        except Exception as e:
            print(f"Error saving JSON: {e}")

def main():
    parser = argparse.ArgumentParser(description='Kernel Information Extractor')
    parser.add_argument('--input-prefix', default='../', help='Input file path prefix')
    parser.add_argument('--output-prefix', default='../result/', help='Output file path prefix')
    parser.add_argument('--log-prefix', default='../result/', help='Log file path prefix')
    parser.add_argument('--process-s25', action='store_true', help='Process s25 kernel check data')
    parser.add_argument('--process-s26', action='store_true', help='Process s26 kernel vulnerability data')
    
    args = parser.parse_args()
    
    input_prefix = args.input_prefix
    output_prefix = args.output_prefix
    log_prefix = args.log_prefix
    
    # Set up logging
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
    
    if args.process_s25:
        logging.info("Processing S25 data only")
        extractor.process_s25(input_prefix)
        extractor.save_json(f'{output_prefix}/kernel.json')
    elif args.process_s26:
        logging.info("Processing S26 data and regenerating complete JSON")
        extractor.process_s26(input_prefix)
        extractor.save_json(f'{output_prefix}/kernel.json')
    else:
        print("Please specify --process-s25 or --process-s26")
        logging.error("No processing mode specified")
    
    logging.info("Processing Complete!")

if __name__ == "__main__":
    main()



