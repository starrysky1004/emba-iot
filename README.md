# EMBA-IOT

该项目改编自[EMBA](https://github.com/e-m-b-a/emba)，用于检测固件的供应链安全，目前支持对未加密固件及部分厂商加密固件的解包、扫描固件组件、检测组件关联cve、检测固件中的二进制程序与脚本文件的安全漏洞、识别固件包含的许可证，以及识别密钥字符并对部分识别到的密码进行爆破，具体功能介绍见下文。后续将在加密固件解包和静态分析方面进行进一步优化。

## 项目安装

操作系统：Ubuntu 22.04 / Ubuntu 24.04 / Kali

> [!NOTE]
>
> 安装该项目之前需要先安装 docker 和 docker compose 并且进行换源，最好 git 挂代理

clone 项目

```shell
git clone https://github.com/starrysky1004/emba-iot.git
```

安装 emba，这里可能跑不到最后就会报错退出，但不影响配置文件中的模块运行

```shell
sudo ./installer -D
```

创建一些文件夹，文件名随意，前两个文件用于存放实际固件和检测结果，最后一个文件夹用于给 emba 的 docker 临时存放固件检测结果

```shell
mkdir ~/firmware
mkdir ~/log
cd emba-iot
mkdir firmware_log
```

在 emba 文件夹中构建 docker，firmware 文件夹在项目中自带，firmware_log 是上一步创建的文件夹，由于这里要求是空文件夹所以没有在 github 中创建。这里可以根据需要修改 docker-compose.yml。

```shell
EMBA="." FIRMWARE=./firmware LOG=./firmware_log/ docker compose run emba
```

构建过程时间比较长，完成后如下，直接退出即可，后续使用的时候会自动在docker里运行

![image-20250806150229038](helpers/image-20250806150229038.png)

## 使用方法

主要项目文件结构：

- firmware / firmware_log：用于给docker临时存放固件文件和检测结果
- modules ：存放项目运行所需的不同模块源码
- output：存放用于输出转化的脚本，实时监测程序运行情况并将生成的结果转化成json文件
- scan-profiles：存放配置文件，用于指定使用modules中的哪些模块
- emba：项目主程序，bash脚本
- installer.sh / installer：安装程序和安装程序目录

使用指令：

- firmware 和 log 为安装过程中创建的文件路径，实际固件需要存放到 firmware 文件夹中，每次指定的 log_dirname 名字需要不一样，可以考虑命名方式为时间+固件名或随机生成字符串
- scan-profiles 的选择见功能介绍

```shell
./emba -f ~/firmware/firmware_name -l ~/log/log_dirname -p ./scan-profiles/profile
```

运行结果：

![image-20250806152321091](helpers/image-20250806152321091.png)

检测结果如下：最终只需要关注log/results中生成的json文件

![image-20250806152552480](helpers/image-20250806152552480.png)

## 功能介绍

### 配置文件

以下为 scan-profiles 中的配置文件，每个配置文件包含上一个配置文件的功能，不作重复描述

- quick_sbom.emba：识别固件相关组件和许可证，生成 SBOM.json 和 license.json

  - SBOM.json：emba自带生成的不包含漏洞信息的SBOM，可以不用这个直接从后续其他json中提取SBOM

    ```json
    {
      "$schema": "string",                    // JSON Schema定义
      "bomFormat": "string",                  // BOM格式版本
      "specVersion": "string",                // 规范版本
      "serialNumber": "string",               // 序列号
      "version": "int",                       // 版本号
      "metadata": {
        "timestamp": "string",                // 生成时间戳
        "tools": {
          "components": [...]                 // 工具组件信息
        },
        "component": {...},                   // 主组件信息
        "supplier": {...},                    // 供应商信息
        "lifecycles": [...]                   // 生命周期信息
      },
      "components": [
        {
          "type": "string",                   // 组件类型
          "name": "string",                   // 组件名称
          "version": "string",                // 组件版本
          "supplier": {...},                  // 供应商信息
          "group": "string",                  // 组件分组
          "bom-ref": "string",                // BOM引用ID
          "scope": "string",                  // 作用域
          "cpe": "string",                    // CPE标识符
          "purl": "string",                   // 包URL
          "properties": [...],                // 属性列表
          "hashes": [...]                     // 哈希值列表
        }
      ]
    }
    ```

  - license.json

    ```json
    {
      "metadata": {
        "total_components": "int",            // 总组件数量
        "total_licenses": "int",              // 总许可证类型数量
        "filtered_out_components": "int",     // 被过滤掉的组件数量
        "generated_at": "string|null"         // 生成时间戳
      },
      "components": [
        {
          "binary": "string",                 // 二进制文件名
          "product": "string",                // 产品名称
          "version": "string",                // 版本号
          "license": "string"                 // 许可证类型
        }
      ],
      "license_summary": {
        "license": {
          "count": "int",                     // 该许可证下的组件数量
          "components": [                     // 使用该许可证的组件列表
            {
              "binary": "string",             // 二进制文件名
              "product": "string",            // 产品名称
              "version": "string",            // 版本号
              "license": "string"             // 许可证类型
            }
          ]
        }
      }
    }
    ```

- sbom_link_cve.emba：识别固件组件关联的 cve，生成 components_cve.json

  - components_cve.json

    ```json
    {
      "total_components": "int",              // 总组件数量
      "total_vulnerabilities": "int",         // 总漏洞数量
      "severity_summary": {
        "critical": "int",                    // 严重级别漏洞数量
        "high": "int",                        // 高危级别漏洞数量
        "medium": "int",                      // 中危级别漏洞数量
        "low": "int"                          // 低危级别漏洞数量
      },
      "components": [
        {
          "component_name": "string",         // 组件名称
          "version": "string",                // 组件版本
          "total_vulnerabilities": "int",     // 该组件总漏洞数
          "severity_breakdown": {
            "critical": "int",                // 严重级别数量
            "high": "int",                    // 高危级别数量
            "medium": "int",                  // 中危级别数量
            "low": "int"                      // 低危级别数量
          },
          "vulnerabilities": [
            {
              "product": "string",            // 产品名称
              "version": "string",            // 版本号
              "cve_number": "string",         // CVE编号
              "severity": "string",           // 严重程度
              "score": "float",               // CVSS评分
              "source": "string",             // 数据来源
              "cvss_version": "string",       // CVSS版本
              "cvss_vector": "string",        // CVSS向量
              "remarks": "string"             // 备注信息
            }
          ]
        }
      ]
    }
    ```

- quick_scan.emba：检测 python / php / perl 脚本漏洞

  - scripts_vul.json

    ```json
    {
      "scan_summary": {
        "total_python_issues": "int",         // Python脚本问题总数
        "total_php_issues": "int",            // PHP脚本问题总数
        "total_perl_issues": "int",           // Perl脚本问题总数
        "total_all_issues": "int"             // 所有脚本问题总数
      },
      "statistics": {
        "python": {
          "total_issues": "int",              // Python问题总数
          "files_affected": "int"             // 受影响文件数
        },
        "php": {
          "total_issues": "int",              // PHP问题总数
          "progpilot_issues": "int",          // Progpilot检测问题数
          "files_affected": "int"             // 受影响文件数
        },
        "perl": {
          "total_issues": "int",              // Perl问题总数
          "files_affected": "int"             // 受影响文件数
        }
      },
      "detailed_results": {
        "s21_python_check": {
          "total_issues": "int",              // 总问题数
          "issues": [
            {
              "file_name": "string",          // 文件名
              "line_number": "int",           // 行号
              "column_number": "int",         // 列号
              "error_code": "string",         // 错误代码
              "error_message": "string",      // 错误信息
              "severity": "string",           // 严重程度
              "confidence": "string"          // 置信度
            }
          ]
        }
      }
    }
    ```

    检测漏洞类型包括：

    python

    ```python
    {
        'B101': 'assert_used - 使用了assert语句',
        'B102': 'exec_used - 使用了exec函数',
        'B103': 'set_bad_file_permissions - 设置了不安全的文件权限',
        'B104': 'hardcoded_bind_all_interfaces - 硬编码绑定所有接口',
        'B105': 'hardcoded_password_string - 硬编码密码字符串',
        'B106': 'hardcoded_password_funcarg - 硬编码密码函数参数',
        'B107': 'hardcoded_password_default - 硬编码密码默认值',
        'B108': 'hardcoded_tmp_directory - 硬编码临时目录',
        'B109': 'password_config_option_not_marked_secret - 密码配置选项未标记为秘密',
        'B110': 'try_except_pass - try-except块中使用了pass',
        'B111': 'execute_with_run_as_root_equals_true - 以root权限执行',
        'B112': 'try_except_continue - try-except块中使用了continue',
        'B113': 'request_without_timeout - 请求没有超时设置',
        'B201': 'flask_debug_true - Flask调试模式开启',
        'B202': 'tarfile_unsafe_members - tarfile不安全的成员',
        'B301': 'blacklist - 使用了不安全的pickle',
        'B306': 'blacklist - 使用了不安全的mktemp',
        'B307': 'blacklist - 使用了不安全的eval',
        'B310': 'blacklist - 使用了不安全的marshal',
        'B311': 'blacklist - 使用了不安全的random',
        'B323': 'blacklist - 使用了不安全的unverified_context',
        'B324': 'hashlib - 使用了hashlib',
        'B403': 'blacklist - 使用了不安全的import',
        'B404': 'blacklist - 使用了不安全的importlib',
        'B501': 'request_with_no_cert_validation - 请求没有证书验证',
        'B502': 'ssl_with_bad_version - SSL使用了错误的版本',
        'B503': 'ssl_with_bad_defaults - SSL使用了错误的默认值',
        'B504': 'ssl_with_no_version - SSL没有指定版本',
        'B505': 'weak_cryptographic_key - 弱加密密钥',
        'B506': 'yaml_load - 使用了yaml.load',
        'B507': 'ssh_no_host_key_verification - SSH没有主机密钥验证',
        'B508': 'snmp_insecure_version - SNMP不安全版本',
        'B509': 'snmp_weak_cryptography - SNMP弱加密',
        'B601': 'paramiko_calls - 使用了paramiko调用',
        'B602': 'subprocess_popen_with_shell_equals_true - subprocess使用shell=True',
        'B603': 'subprocess_without_shell_equals_true - subprocess没有使用shell=True',
        'B604': 'any_other_function_with_shell_equals_true - 其他函数使用shell=True',
        'B605': 'start_process_with_a_shell - 使用shell启动进程',
        'B606': 'start_process_with_no_shell - 不使用shell启动进程',
        'B607': 'start_process_with_partial_path - 使用部分路径启动进程',
        'B608': 'hardcoded_sql_expressions - 硬编码SQL表达式',
        'B609': 'linux_commands_wildcard_injection - Linux命令通配符注入',
        'B610': 'django_extra_used - 使用了Django extra',
        'B611': 'django_rawsql_used - 使用了Django raw SQL',
        'B612': 'logging_config_insecure_listen - 日志配置不安全监听',
        'B613': 'trojansource - 特洛伊木马源代码',
        'B614': 'pytorch_load - 使用了PyTorch load',
        'B615': 'huggingface_unsafe_download - HuggingFace不安全下载',
        'B701': 'jinja2_autoescape_false - Jinja2自动转义关闭',
        'B702': 'use_of_mako_templates - 使用了Mako模板',
        'B703': 'django_mark_safe - Django标记为安全',
        'B704': 'markupsafe_markup_xss - MarkupSafe标记XSS'
    }
    ```

    

- full_scan.emba：检测二进制程序中的漏洞、识别kernel版本相关cve并进行验证、密钥识别爆破

  > [!TIP]
  >
  > 爆破密钥功能个人认为用处不大且费时间，一个小时爆破失败会自动停止，不需要可以在emba中删除S109

  - cwe.json

    ```json
    {
      "scan_summary": {
        "total_high_risk_vulnerabilities": "int",  // 高风险漏洞总数
        "affected_binaries": "int",                // 受影响的二进制文件数
        "vulnerability_types": {
          "CWE code": "quantity"                   // CWE代码及数量
        },
        "critical_count": "int",                   // 严重漏洞数量
        "binary_list": ["string"]                  // 二进制文件列表
      },
      "high_risk_vulnerabilities": [
        {
          "binary_file": "string",                 // 二进制文件名
          "vulnerability_type": "string",          // 漏洞类型
          "addresses": ["string"],                 // 内存地址列表
          "symbols": ["string"],                   // 符号列表
          "description": "string",                 // 漏洞描述
          "vulnerability_description": "string"    // 漏洞详细描述
        }
      ]
    }
    ```

    检测漏洞类型包括

    python

    ```python
    	{
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
    ```

    php

    ```python
    	{
            'CWE_78': 'OS Command Injection - 操作系统命令注入',
            'CWE_79': 'Cross-site Scripting (XSS) - 跨站脚本攻击',
            'CWE_89': 'SQL Injection - SQL注入',
            'CWE_90': 'LDAP Injection - LDAP注入',
            'CWE_91': 'XML Injection - XML注入',
            'CWE_95': 'Code Injection - 代码注入',
            'CWE_98': 'PHP File Inclusion - PHP文件包含',
            'CWE_22': 'Path Traversal - 路径遍历',
            'CWE_384': 'Session Fixation - 会话固定',
            'CWE_601': 'URL Redirection to Untrusted Site - URL重定向到不可信站点',
            'CWE_1333': 'Regular Expression Denial of Service (ReDoS) - 正则表达式拒绝服务'
        }
        
    	{
            'external.semgrep-rules.php.lang.security.unlink-use': 'Unsafe File Deletion - 不安全的文件删除',
            'external.semgrep-rules.php.lang.security.unserialize-use': 'Unsafe Unserialize - 不安全的反序列化',
            'external.semgrep-rules.php.lang.security.weak-crypto': 'Weak Cryptography - 弱加密算法'
        }
    ```

    perl

    ```python
    	{
            'Debug module enabled': 'Debug module enabled - 调试模块启用',
            'Code Injection': 'Code Injection - 代码注入',
            'Path Traversal': 'Path Traversal - 路径遍历',
            'Weak Criptography Algorithm': 'Weak Criptography Algorithm - 弱加密算法',
            'Weak Random Value Generator': 'Weak Random Value Generator - 弱随机值生成器',
            'Error Suppression': 'Error Suppression - 错误抑制',
            'Cross Site Scripting (XSS)': 'Cross Site Scripting (XSS) - 跨站脚本攻击',
            'Command Injection': 'Command Injection - 命令注入',
            'Connection String Injection': 'Connection String Injection - 连接字符串注入',
            'LDAP Injection': 'LDAP Injection - LDAP注入',
            'XSS': 'XSS - 跨站脚本攻击',
            'Remote File Inclusion': 'Remote File Inclusion - 远程文件包含',
            'Resource Injection': 'Resource Injection - 资源注入',
            'SQL Injection': 'SQL Injection - SQL注入'
        }
    ```

  - kernel.json

    ```json
    {
      "kernel_analysis": {
        "kernel_version": "string",               // 内核版本
        "kernel_modules": [
          {
            "path": "string",                     // 模块路径
            "license": "string",                  // 许可证类型
            "status": "string"                    // 模块状态
          }
        ],
        "statistics": {
          "version": "string",                    // 版本信息
          "total_modules": "int",                 // 总模块数
          "other_count": "int"                    // 其他模块数
        }
      },
      "vulnerabilities": [
        {
          "binary_name": "string",                // 二进制名称
          "version": "string",                    // 版本号
          "cve_id": "string",                     // CVE编号
          "cvss_score": "string",                 // CVSS评分
          "severity": "string",                   // 严重程度
          "epss": "string",                       // EPSS评分
          "source": "string",                     // 数据来源
          "exploit_info": "string"                // 漏洞利用信息
        }
      ]
    }
    ```

  - passwd.json

    ```json
    {
      "scan_summary": {
        "total_key_files": "int",                // 密钥文件总数
        "total_credentials": "int",              // 凭据总数
        "total_passwords_found": "int",          // 发现的密码总数
        "total_hashes_cracked": "int"            // 破解的哈希总数
      },
      "modules": {
        "s106_deep_key_search": {
          "total_files_with_keys": "int",        // 包含密钥的文件数
          "key_files": [
            {
              "file_path": "string",             // 文件路径
              "pattern": "string",               // 匹配模式
              "content_length": "int"            // 内容长度
            }
          ]
        },
        "s108_stacs_password_search": {
          "total_credentials": "int",            // 凭据总数
          "credentials": [
            {
              "path": "string",                  // 文件路径
              "hash": "string"                   // 密码哈希
            }
          ]
        },
        "s109_jtr_password_cracking": {
          "total_passwords_found": "int",        // 发现的密码数
          "total_hashes_cracked": "int",         // 破解的哈希数
          "found_passwords": ["string"],         // 发现的密码列表
          "cracked_passwords": ["string"]        // 破解的密码列表
        }
      }
    }
    ```

- 其他输出文件：

  - log/results/scripts.log：output 中的脚本的日志文件，运行出错的时候可以根据日志文件判断问题

## 运行性能

| 配置文件               | 配置环境 | 耗时       |
| ---------------------- | -------- | ---------- |
| **quick_sbom.emba**    | 2c4G     | 7min27s    |
|                        | 4c4G     | 25min34s   |
|                        | 8c8G     | 15min28s   |
|                        | 16c16G   | 8min19s    |
| **sbom_link_cve.emba** | 2c4G     | 27min57s   |
|                        | 4c4G     | 30min03s   |
|                        | 8c8G     | 17min52s   |
|                        | 16c16G   | 9min31s    |
| **quick_scan.emba**    | 2c4G     | 29min32s   |
|                        | 4c4G     | 34min08s   |
|                        | 8c8G     | 20min03s   |
|                        | 16c16G   | 9min57s    |
| **full_scan.emba**     | 2c4G     | 2h01min09s |
|                        | 4c4G     | 57min47s   |
|                        | 8c8G     | 29min29s   |
|                        | 16c16G   | 12min44s   |


