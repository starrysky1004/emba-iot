#!/usr/bin/env python3
"""
运行所有分析脚本的主脚本 - 持续运行版本
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
    """设置日志配置"""
    # 确保输出目录存在
    os.makedirs(log_prefix, exist_ok=True)
    
    # 使用 UTF-8 编码打开文件
    log_file = os.path.join(log_prefix, 'scripts.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,  # 改为DEBUG级别以显示调试信息
        format='%(asctime)s - %(levelname)s - %(message)s',
        filemode='w',  # 使用 'w' 模式覆盖之前的日志
        encoding='utf-8'  # 明确指定 UTF-8 编码
    )

def parse_emba_log(emba_log_path):
    """解析emba.log文件，确定哪些模块已完成"""
    completed_modules = set()
    
    if not os.path.exists(emba_log_path):
        logging.warning(f"EMBA log file not found: {emba_log_path}")
        return completed_modules
    
    try:
        with open(emba_log_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 检查各个模块的完成状态 - 使用完整的模式字符串
        module_patterns = [
            'S24_kernel_bin_identifier finished',
            'S25_kernel_check finished', 
            'S26_kernel_vuln_verifier finished',
            'S09_firmware_base_version_check finished',
            'S17_cwe_checker finished',
            'F10_license_summary finished',
            'S106_deep_password_search finished',
            'S108_stacs_password_search finished',
            'S109_jtr_local_pw_cracking finished',
            'S20_shell_check finished',
            'S21_python_check finished',
            'S22_php_check finished',
            'S23_lua_check finished',
            'S27_perl_check finished',
            'F15_cyclonedx_sbom finished'
        ]
        
        for pattern in module_patterns:
            if re.search(pattern, content):
                completed_modules.add(pattern)
                logging.info(f"检测到模块完成: {pattern}")
        
        # 检查是否有"Test ended"标记
        if re.search(r'Test ended', content):
            completed_modules.add('test_ended')
            logging.info("检测到EMBA测试结束")
            
    except Exception as e:
        logging.error(f"解析EMBA日志时出错: {e}")
    
    return completed_modules

def should_run_script(script_name, completed_modules):
    """根据EMBA日志结果决定是否运行脚本"""
    # 定义脚本运行条件
    script_conditions = {
        'kernel.py': ['S24_kernel_bin_identifier finished', 'S25_kernel_check finished', 'S26_kernel_vuln_verifier finished'],
        'components_cve.py': ['S09_firmware_base_version_check finished'],
        'cwe.py': ['S17_cwe_checker finished'],
        'license.py': ['F10_license_summary finished'],
        'passwd.py': ['S109_jtr_local_pw_cracking finished'],  
        'scripts_vul.py': ['S21_python_check finished', 'S22_php_check finished', 'S27_perl_check finished']
    }
    
    # 获取脚本的运行条件
    required_patterns = script_conditions.get(script_name, [])
    if not required_patterns:
        return True  # 未知脚本，默认运行
    
    # 检查所有必需的模式是否都存在
    for pattern in required_patterns:
        if pattern not in completed_modules:
            return False
    
    return True

def run_script(script_name, input_prefix, output_prefix, log_prefix):
    """运行单个脚本"""
    try:
        logging.info(f"🚀 开始运行: {script_name}")
        
        # 设置环境变量，确保输出到正确位置
        env = os.environ.copy()
        env['OUTPUT_PREFIX'] = output_prefix
        env['LOG_PREFIX'] = log_prefix
        
        # 确保output_prefix目录存在
        os.makedirs(output_prefix, exist_ok=True)
        
        # 为每个脚本创建独立的日志文件
        script_log_prefix = os.path.join(log_prefix, 'scripts')
        os.makedirs(script_log_prefix, exist_ok=True)
        
        cmd = [
            sys.executable, script_name,
            '--input-prefix', input_prefix,
            '--output-prefix', output_prefix,  # 直接输出到results目录
            '--log-prefix', script_log_prefix  # 使用独立的日志目录
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd(), env=env)
        
        if result.returncode == 0:
            logging.info(f"✅ {script_name} 运行成功")
            # 检查是否有输出文件生成
            check_output_files(script_name, output_prefix)
        else:
            logging.error(f"❌ {script_name} 运行失败")
            logging.error(f"错误输出: {result.stderr}")
            
        return result.returncode == 0
    except Exception as e:
        logging.error(f"❌ 运行 {script_name} 时发生异常: {e}")
        return False

def check_output_files(script_name, output_prefix):
    """检查脚本是否生成了输出文件"""
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
            logging.info(f"📄 输出文件已生成: {filename}")
        else:
            logging.warning(f"⚠️ 输出文件未生成: {filename}")

def move_json_files_to_results(input_prefix, output_prefix):
    """将output脚本生成的JSON文件移动到results目录"""
    try:
        # 只查找output脚本生成的特定JSON文件
        output_script_files = {
            'kernel.json',
            'components_cve.json', 
            'cwe.json',
            'license.json',
            'passwd.json',
            'scripts_vul.json'
        }
        
        # 在input_prefix目录中查找这些特定文件
        for filename in output_script_files:
            source_path = os.path.join(input_prefix, filename)
            target_path = os.path.join(output_prefix, filename)
            
            if os.path.exists(source_path) and not os.path.exists(target_path):
                try:
                    import shutil
                    shutil.move(source_path, target_path)
                    logging.info(f"📦 移动output脚本文件: {filename} -> results/")
                except Exception as e:
                    logging.error(f"❌ 移动文件失败 {filename}: {e}")
            elif os.path.exists(source_path) and os.path.exists(target_path):
                logging.info(f"📄 文件已存在: {filename}")
            else:
                pass
                    
    except Exception as e:
        logging.error(f"❌ 移动JSON文件时出错: {e}")

def copy_sbom_file(input_prefix, output_prefix):
    """复制SBOM文件到results目录"""
    try:
        sbom_source = os.path.join(input_prefix, 'SBOM', 'EMBA_cyclonedx_sbom.json')
        sbom_target = os.path.join(output_prefix, 'SBOM.json')
        
        if os.path.exists(sbom_source) and not os.path.exists(sbom_target):
            try:
                import shutil
                shutil.copy2(sbom_source, sbom_target)
                logging.info(f"📦 复制SBOM文件: EMBA_cyclonedx_sbom.json -> results/SBOM.json")
            except Exception as e:
                logging.error(f"❌ 复制SBOM文件失败: {e}")
        elif os.path.exists(sbom_source) and os.path.exists(sbom_target):
            logging.info(f"📄 SBOM文件已存在: SBOM.json")
        else:
            logging.debug(f"🔍 未找到SBOM文件: {sbom_source}")
                    
    except Exception as e:
        logging.error(f"❌ 复制SBOM文件时出错: {e}")

def main():
    """主函数"""
    import argparse
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='运行所有分析脚本的主脚本 - 持续运行版本')
    parser.add_argument('--input-prefix', default='../', help='输入文件路径前缀')
    parser.add_argument('--output-prefix', default='../result/', help='输出文件路径前缀')
    parser.add_argument('--log-prefix', default='../result/', help='日志文件路径前缀')
    parser.add_argument('--interval', type=int, default=30, help='运行间隔（秒）')
    
    args = parser.parse_args()
    
    setup_logging(args.log_prefix)
    
    logging.info("🎯 开始持续运行分析脚本")
    logging.info(f"⏰ 运行间隔: {args.interval}秒")
    logging.info("=" * 60)
    
    # 要运行的脚本列表
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
        logging.info(f"🔄 第 {run_count} 次运行开始")
        
        # 解析EMBA日志
        completed_modules = parse_emba_log(emba_log_path)
        
        # 检查是否测试结束
        if 'test_ended' in completed_modules:
            test_ended = True
            logging.info("🎯 检测到EMBA测试结束，这是最后一次运行")
        
        # 运行脚本
        success_count = 0
        total_count = 0
        
        for script in scripts:
            if should_run_script(script, completed_modules):
                total_count += 1
                if os.path.exists(script):
                    if run_script(script, args.input_prefix, args.output_prefix, args.log_prefix):
                        success_count += 1
                else:
                    logging.warning(f"⚠️ 脚本不存在: {script}")
        
        # 检查是否有output脚本生成的JSON文件需要移动（备用机制）
        # 如果脚本没有直接输出到results目录，则移动文件
        move_json_files_to_results(args.input_prefix, args.output_prefix)
        
        # 检查是否需要复制SBOM文件
        if 'F15_cyclonedx_sbom finished' in completed_modules:
            copy_sbom_file(args.input_prefix, args.output_prefix)
        
        logging.info(f"📊 本次运行: 成功 {success_count}/{total_count}")
        
        # 如果测试结束，运行最后一次后退出
        if test_ended:
            logging.info("🎉 最后一次运行完成，程序结束")
            break
        
        # 等待下次运行
        logging.info(f"⏳ 等待 {args.interval} 秒后进行下次运行...")
        time.sleep(args.interval)
    
    logging.info("=" * 60)
    logging.info("🎊 所有运行完成!")

if __name__ == "__main__":
    main() 