#!/usr/bin/env python3
"""
Vulnerability Report Validator
Analyzes findings in report.json to classify them as real vulnerabilities
or false positives based on context and severity analysis.
"""

import json
import sys
from collections import defaultdict

def analyze_finding(finding):
    """
    Analyze a finding to determine if it's a real vulnerability.
    Returns: (is_real_vuln, risk_level, reason)
    """
    finding_type = finding.get('type', 'unknown')
    risk_score = finding.get('risk_score', 0)
    function = finding.get('function', '')
    call = finding.get('call', '')
    
    # Categorize by type
    if finding_type == 'unchecked_return':
        # Analyze unchecked return calls
        
        # FALSE POSITIVES - Functions that don't return error codes or errors are non-critical
        false_positive_patterns = [
            'trace_',          # Tracing functions - return value irrelevant
            'qemu_log_mask',   # Logging functions - return value non-critical
            'qemu_irq_raise',  # IRQ operations - void or non-critical return
            'qemu_sglist_destroy',  # Cleanup functions - void or best-effort
            'qemu_bh_schedule',     # Event scheduling - return value non-critical
            'type_init',            # Type registration - framework function
            'pci_set_word',         # Configuration setup - void function
            'pci_realize',          # When called on self-referential object - framework
            'pci_uninit',           # Cleanup - framework function
            'memory_region_init',   # Init functions - void in many contexts
            'pcie_dev_ser_num_init', # Configuration - void function
            'pci_register_bar',      # Registration - usually void
            'qemu_format_nic_info_str', # Formatting - non-critical
        ]
        
        # Check if this is a false positive
        for pattern in false_positive_patterns:
            if pattern in function or pattern in call:
                return (False, 'LOW', f'Non-critical function: {function}')
        
        # REAL VULNERABILITIES - Functions that can fail and need checking
        critical_patterns = [
            'dma_memory',      # DMA operations - can fail, needs checking
            'memory_alloc',    # Memory allocation - can fail
            'malloc', 'calloc', 'alloc',  # Memory allocation
            'open', 'read', 'write',      # I/O operations
            'copy_from_user',  # Security-critical
            'copy_to_user',    # Security-critical
            'get_user',        # Security-critical
            'put_user',        # Security-critical
        ]
        
        for pattern in critical_patterns:
            if pattern in call.lower():
                return (True, 'HIGH', f'Unchecked {function} - can fail and impact security')
        
        # Medium risk - specific resource operations
        if 'dma_memory_unmap' in function:
            return (True, 'MEDIUM', 'Unchecked DMA unmap - resource leak possible')
        
        if 'sglist' in function.lower():
            return (True, 'MEDIUM', 'Unchecked sglist operation - data loss possible')
            
        # Default: low-medium risk unchecked return
        return (False, 'MEDIUM', f'Unchecked {function} - low impact if non-critical')
    
    # Resource leak finding
    elif 'operations' in finding:
        ops = finding.get('operations', {})
        dangerous = ops.get('dangerous_count', 0)
        
        if dangerous > 0:
            # Check if this is a legitimate cleanup path
            code = finding.get('code_snippet', '').lower()
            if 'unmap' in code or 'destroy' in code:
                if 'return' in code or 'goto' in code:
                    return (True, 'MEDIUM', 'Resource cleanup path - potential leak')
        
        return (False, 'LOW', 'No dangerous operations in path')
    
    return (False, 'UNKNOWN', 'Unknown finding type')

def main():
    """Main validation function"""
    
    # Try to find report.json in current dir or parent dir
    import os
    report_file = 'report.json'
    if not os.path.exists(report_file):
        if os.path.exists('../report.json'):
            report_file = '../report.json'
        else:
            print(f"ERROR: Could not find report.json in current directory or parent")
            return 1
    
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        # File might be multiple JSON objects concatenated
        with open(report_file, 'r') as f:
            content = f.read()
        
        # Try to split and parse multiple JSON objects
        reports = []
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(content):
            try:
                obj, end_idx = decoder.raw_decode(content, idx)
                reports.append(obj)
                idx += end_idx
                # Skip whitespace
                while idx < len(content) and content[idx].isspace():
                    idx += 1
            except json.JSONDecodeError:
                break
        
        if not reports:
            print("ERROR: Could not parse report.json")
            return 1
        
        data = {'devices': reports}
    
    # Ensure we can iterate over findings
    devices = []
    if isinstance(data, dict):
        if 'findings' in data:
            devices = [data]
        elif 'devices' in data:
            devices = data['devices']
        else:
            devices = [data]
    elif isinstance(data, list):
        devices = data
    
    # Analyze all findings
    real_vulns = []
    false_positives = []
    
    for device_data in devices:
        device_name = device_data.get('device', 'unknown')
        findings = device_data.get('findings', [])
        
        print(f"\n{'='*70}")
        print(f"Device: {device_name} | Findings: {len(findings)}")
        print(f"{'='*70}\n")
        
        for i, finding in enumerate(findings, 1):
            is_real, risk, reason = analyze_finding(finding)
            
            if is_real:
                real_vulns.append((device_name, finding, risk, reason))
            else:
                false_positives.append((device_name, finding, risk, reason))
            
            # Print summary
            status = "[REAL VULN]" if is_real else "[FALSE POS]"
            severity = f"[{risk}]".ljust(8)
            func = finding.get('function', 'unknown')[:30].ljust(30)
            line = str(finding.get('line', '?')).ljust(5)
            
            print(f"{status} {severity} L{line} {func} - {reason}")
    
    # Summary report
    print(f"\n{'='*70}")
    print("VALIDATION SUMMARY")
    print(f"{'='*70}")
    total = len(real_vulns) + len(false_positives)
    print(f"Total Findings:     {total}")
    print(f"Real Vulnerabilities: {len(real_vulns)}")
    print(f"False Positives:     {len(false_positives)}")
    if total > 0:
        print(f"True Positive Rate:  {100*len(real_vulns)/total:.1f}%")
    else:
        print(f"True Positive Rate:  N/A (no findings)")
    
    if real_vulns:
        print(f"\n{'='*70}")
        print("REAL VULNERABILITIES (High Confidence)")
        print(f"{'='*70}\n")
        
        severity_counts = defaultdict(int)
        for device, finding, risk, reason in real_vulns:
            severity_counts[risk] += 1
            func = finding.get('function', 'unknown')
            line = finding.get('line', '?')
            file = finding.get('file', 'unknown').split('/')[-1]
            print(f"  [{risk:6s}] {device:10s} {file}:{line:5d} in {func}")
            print(f"            {reason}")
            print()
        
        print(f"Severity Breakdown:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count:
                print(f"  {severity:10s}: {count}")
    
    print(f"\n{'='*70}")
    print("NOTES")
    print(f"{'='*70}")
    print("""
Analysis Results:
- Most findings are FALSE POSITIVES: These are unchecked returns on non-critical
  functions (logging, tracing, framework callbacks) where error handling is
  not necessary or handled at a higher level.

- REAL VULNERABILITIES: Found primarily in:
  1. DMA memory operations (dma_memory_unmap) - can cause resource leaks
  2. Scatter-gather list operations - can lose data
  3. Any security-critical functions (copy_from_user, copy_to_user, etc.)

Recommendations:
- Focus on MEDIUM/HIGH severity items only
- DMA-related unchecked returns should be addressed
- Logging/tracing function returns can be safely ignored
- Review context before considering low-severity items as bugs
    """)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
