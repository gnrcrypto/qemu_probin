#!/usr/bin/env python3
"""
KVM Probe Interface - Python wrapper for kvm_pwn CLI tool

This module provides a Python interface to all 54 IOCTLs available
in the kvm_probe_drv kernel module via the kvm_pwn userspace tool.

Usage:
    from kvm_probe_interface import KVMProbe
    
    probe = KVMProbe()
    
    # Memory operations
    data = probe.read_physical(0x1000, 64)
    data = probe.read_kernel(0xffffffff81000000, 64)
    probe.write_physical(0x1000, b'\\x41\\x41\\x41\\x41')
    
    # Hypercalls
    result = probe.hypercall(100, 0, 0, 0, 0)
    batch = probe.hypercall_batch()
    
    # Address translation
    phys = probe.virt_to_phys(0xffffffff81000000)
    hva = probe.gpa_to_hva(0x1000)
    
    # Symbol lookup
    addr = probe.lookup_symbol("init_task")
    
    # KASLR info
    info = probe.get_kaslr_info()
    
    # AHCI operations
    probe.ahci_init()
    val = probe.ahci_read(0, 0x00)
"""

import os
import sys
import subprocess
import struct
import json
import shutil
from typing import Optional, Dict, List, Tuple, Union
from dataclasses import dataclass

# ============================================================================
# Configuration
# ============================================================================

# Paths to search for kvm_pwn binary
KVM_PWN_PATHS = [
    './kvm_pwn',
    '/home/claude/kvm_pwn',
    '/usr/local/bin/kvm_pwn',
    '/opt/kvm_pwn',
    os.path.expanduser('~/kvm_pwn'),
]

# Device file for direct IOCTL fallback
DEVICE_FILE = "/dev/kvm_probe_dev"

# IOCTL definitions (for fallback mode)
IOCTL_BASE = 0x4000

# Symbol operations
IOCTL_LOOKUP_SYMBOL       = IOCTL_BASE + 0x01
IOCTL_GET_SYMBOL_COUNT    = IOCTL_BASE + 0x02
IOCTL_GET_SYMBOL_BY_INDEX = IOCTL_BASE + 0x03
IOCTL_GET_VMX_HANDLERS    = IOCTL_BASE + 0x05
IOCTL_GET_SVM_HANDLERS    = IOCTL_BASE + 0x06
IOCTL_SEARCH_SYMBOLS      = IOCTL_BASE + 0x07

# Memory read
IOCTL_READ_KERNEL_MEM     = IOCTL_BASE + 0x10
IOCTL_READ_PHYSICAL_MEM   = IOCTL_BASE + 0x11
IOCTL_READ_GUEST_MEM      = IOCTL_BASE + 0x12
IOCTL_SCAN_MEMORY_REGION  = IOCTL_BASE + 0x13
IOCTL_FIND_MEMORY_PATTERN = IOCTL_BASE + 0x14
IOCTL_READ_CR_REGISTER    = IOCTL_BASE + 0x15
IOCTL_READ_MSR            = IOCTL_BASE + 0x16
IOCTL_DUMP_PAGE_TABLES    = IOCTL_BASE + 0x17
IOCTL_GET_KASLR_INFO      = IOCTL_BASE + 0x1A
IOCTL_READ_PFN_DATA       = IOCTL_BASE + 0x1C

# Memory write
IOCTL_WRITE_KERNEL_MEM    = IOCTL_BASE + 0x20
IOCTL_WRITE_PHYSICAL_MEM  = IOCTL_BASE + 0x21
IOCTL_WRITE_GUEST_MEM     = IOCTL_BASE + 0x22
IOCTL_WRITE_MSR           = IOCTL_BASE + 0x23
IOCTL_WRITE_CR_REGISTER   = IOCTL_BASE + 0x24
IOCTL_MEMSET_KERNEL       = IOCTL_BASE + 0x25
IOCTL_MEMSET_PHYSICAL     = IOCTL_BASE + 0x26
IOCTL_PATCH_BYTES         = IOCTL_BASE + 0x28
IOCTL_WRITE_AND_FLUSH     = IOCTL_BASE + 0x42

# Address conversion
IOCTL_GPA_TO_HVA          = IOCTL_BASE + 0x30
IOCTL_GFN_TO_HVA          = IOCTL_BASE + 0x31
IOCTL_GFN_TO_PFN          = IOCTL_BASE + 0x32
IOCTL_GPA_TO_GFN          = IOCTL_BASE + 0x33
IOCTL_GFN_TO_GPA          = IOCTL_BASE + 0x34
IOCTL_HVA_TO_PFN          = IOCTL_BASE + 0x35
IOCTL_HVA_TO_GFN          = IOCTL_BASE + 0x36
IOCTL_PFN_TO_HVA          = IOCTL_BASE + 0x37
IOCTL_VIRT_TO_PHYS        = IOCTL_BASE + 0x38
IOCTL_PHYS_TO_VIRT        = IOCTL_BASE + 0x39
IOCTL_VIRT_TO_PFN         = IOCTL_BASE + 0x3A
IOCTL_PAGE_TO_PFN         = IOCTL_BASE + 0x3B
IOCTL_PFN_TO_PAGE         = IOCTL_BASE + 0x3C
IOCTL_SPTE_TO_PFN         = IOCTL_BASE + 0x3D
IOCTL_WALK_EPT            = IOCTL_BASE + 0x3E
IOCTL_TRANSLATE_GVA       = IOCTL_BASE + 0x3F

# Cache
IOCTL_WBINVD              = IOCTL_BASE + 0x40
IOCTL_CLFLUSH             = IOCTL_BASE + 0x41

# AHCI
IOCTL_AHCI_INIT           = IOCTL_BASE + 0x50
IOCTL_AHCI_READ_REG       = IOCTL_BASE + 0x51
IOCTL_AHCI_WRITE_REG      = IOCTL_BASE + 0x52
IOCTL_AHCI_SET_FIS_BASE   = IOCTL_BASE + 0x53
IOCTL_AHCI_INFO           = IOCTL_BASE + 0x54

# Hypercall
IOCTL_HYPERCALL           = IOCTL_BASE + 0x60
IOCTL_HYPERCALL_BATCH     = IOCTL_BASE + 0x61
IOCTL_HYPERCALL_DETECT    = IOCTL_BASE + 0x62

# ============================================================================
# Helper Functions
# ============================================================================

def is_kernel_virtual_addr(addr: int) -> bool:
    """Check if address is a kernel virtual address"""
    return addr >= 0xffff800000000000 or (0xffffffff80000000 <= addr <= 0xffffffffffffffff)

def is_physical_addr(addr: int) -> bool:
    """Check if address looks like a physical address"""
    return addr < 0x100000000000 and not is_kernel_virtual_addr(addr)

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for CLI"""
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    # Remove common prefixes
    hex_str = hex_str.strip()
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    # Remove spaces
    hex_str = hex_str.replace(' ', '')
    return bytes.fromhex(hex_str)

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class KASLRInfo:
    """KASLR and memory layout information"""
    kernel_base: int = 0
    kaslr_slide: int = 0
    physmap_base: int = 0
    vmalloc_base: int = 0
    vmemmap_base: int = 0

@dataclass
class PageTableInfo:
    """Page table dump result"""
    virtual_addr: int = 0
    pml4e: int = 0
    pdpte: int = 0
    pde: int = 0
    pte: int = 0
    physical_addr: int = 0
    flags: int = 0

@dataclass
class EPTWalkInfo:
    """EPT walk result"""
    eptp: int = 0
    gpa: int = 0
    hpa: int = 0
    pml4e: int = 0
    pdpte: int = 0
    pde: int = 0
    pte: int = 0
    page_size: int = 0

@dataclass
class SPTEInfo:
    """SPTE decode result"""
    spte: int = 0
    pfn: int = 0
    flags: int = 0
    present: bool = False
    writable: bool = False
    executable: bool = False

@dataclass
class AHCIInfo:
    """AHCI controller information"""
    cap: int = 0
    ghc: int = 0
    pi: int = 0
    vs: int = 0
    port_ssts: List[int] = None
    
    def __post_init__(self):
        if self.port_ssts is None:
            self.port_ssts = [0] * 6

# ============================================================================
# KVM Probe Interface
# ============================================================================

class KVMProbe:
    """
    Python interface to kvm_pwn CLI tool and kvm_probe_drv kernel module.
    
    Provides access to all 54 IOCTLs:
    - Symbol operations (lookup, search, enumerate, VMX/SVM handlers)
    - Memory read (kernel, physical, guest, PFN)
    - Memory write (kernel, physical, guest, with cache flush)
    - Address translations (full guest/host/physical conversion)
    - CR/MSR read/write
    - Page table and EPT walking
    - Cache operations (WBINVD, CLFLUSH)
    - AHCI device operations
    - Hypercall execution
    """
    
    def __init__(self, kvm_pwn_path: str = None, verbose: bool = False):
        """
        Initialize KVM probe interface.
        
        Args:
            kvm_pwn_path: Path to kvm_pwn binary (auto-detected if None)
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.kvm_pwn = self._find_kvm_pwn(kvm_pwn_path)
        self._kaslr_cache = None
        
        if self.kvm_pwn:
            if self.verbose:
                print(f"[+] Using kvm_pwn: {self.kvm_pwn}")
        else:
            if self.verbose:
                print("[!] kvm_pwn not found, some features may be limited")
    
    def _find_kvm_pwn(self, path: str = None) -> Optional[str]:
        """Find kvm_pwn binary"""
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
        
        for p in KVM_PWN_PATHS:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        
        # Try which
        result = shutil.which('kvm_pwn')
        if result:
            return result
        
        return None
    
    def _run_cmd(self, *args, raw: bool = False, json_output: bool = False, 
                 timeout: int = 10) -> Optional[str]:
        """Run kvm_pwn command and return output"""
        if not self.kvm_pwn:
            return None
        
        cmd = ['sudo', self.kvm_pwn]
        
        if raw:
            cmd.append('-r')
        if json_output:
            cmd.append('-j')
        
        cmd.extend(str(a) for a in args)
        
        if self.verbose:
            print(f"[*] Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                if self.verbose:
                    print(f"[-] Command failed: {result.stderr}")
                return None
            
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"[-] Command timed out")
            return None
        except Exception as e:
            if self.verbose:
                print(f"[-] Command error: {e}")
            return None
    
    def _parse_hex(self, output: str) -> Optional[int]:
        """Parse hex value from output"""
        if not output:
            return None
        
        # Handle raw output (just hex)
        output = output.strip()
        try:
            if output.startswith('0x'):
                return int(output, 16)
            return int(output, 16)
        except ValueError:
            # Try to extract hex from formatted output
            import re
            match = re.search(r'0x([0-9a-fA-F]+)', output)
            if match:
                return int(match.group(1), 16)
            return None
    
    def _parse_hexdump(self, output: str) -> Optional[bytes]:
        """Parse hexdump output to bytes"""
        if not output:
            return None
        
        # Raw mode returns just hex bytes
        output = output.strip()
        if all(c in '0123456789abcdefABCDEF' for c in output):
            return bytes.fromhex(output)
        
        # Parse formatted hexdump
        data = bytearray()
        for line in output.split('\n'):
            # Skip non-data lines
            if ':' not in line:
                continue
            
            # Extract hex bytes between address and ASCII
            parts = line.split(':')
            if len(parts) < 2:
                continue
            
            hex_part = parts[1]
            # Remove ASCII section (after |)
            if '|' in hex_part:
                hex_part = hex_part.split('|')[0]
            
            # Parse hex bytes
            hex_bytes = hex_part.split()
            for hb in hex_bytes:
                if len(hb) == 2 and all(c in '0123456789abcdefABCDEF' for c in hb):
                    data.append(int(hb, 16))
        
        return bytes(data) if data else None
    
    # ========================================================================
    # Symbol Operations
    # ========================================================================
    
    def lookup_symbol(self, name: str) -> Optional[int]:
        """
        Look up kernel symbol address.
        
        Args:
            name: Symbol name (e.g., "init_task", "commit_creds")
            
        Returns:
            Symbol address or None if not found
        """
        output = self._run_cmd('sym', name, raw=True)
        return self._parse_hex(output)
    
    def get_symbol_count(self) -> int:
        """Get total number of KVM symbols"""
        output = self._run_cmd('sym-count', raw=True)
        if output:
            try:
                return int(output.strip())
            except ValueError:
                pass
        return 0
    
    def list_symbols(self) -> List[Tuple[str, int]]:
        """
        List all KVM symbols.
        
        Returns:
            List of (name, address) tuples
        """
        output = self._run_cmd('sym-list')
        if not output:
            return []
        
        symbols = []
        import re
        for line in output.split('\n'):
            match = re.search(r'(\S+)\s+0x([0-9a-fA-F]+)', line)
            if match:
                symbols.append((match.group(1), int(match.group(2), 16)))
        
        return symbols
    
    def search_symbols(self, pattern: str) -> List[Tuple[str, int]]:
        """Search symbols by pattern"""
        output = self._run_cmd('sym-search', pattern)
        if not output:
            return []
        
        symbols = []
        import re
        for line in output.split('\n'):
            match = re.search(r'(\S+)\s+0x([0-9a-fA-F]+)', line)
            if match:
                symbols.append((match.group(1), int(match.group(2), 16)))
        
        return symbols
    
    def get_vmx_handlers(self) -> List[Tuple[str, int]]:
        """Get Intel VMX exit handlers"""
        output = self._run_cmd('vmx-handlers')
        if not output:
            return []
        
        handlers = []
        import re
        for line in output.split('\n'):
            match = re.search(r'(\S+)\s+0x([0-9a-fA-F]+)', line)
            if match:
                handlers.append((match.group(1), int(match.group(2), 16)))
        
        return handlers
    
    def get_svm_handlers(self) -> List[Tuple[str, int]]:
        """Get AMD SVM exit handlers"""
        output = self._run_cmd('svm-handlers')
        if not output:
            return []
        
        handlers = []
        import re
        for line in output.split('\n'):
            match = re.search(r'(\S+)\s+0x([0-9a-fA-F]+)', line)
            if match:
                handlers.append((match.group(1), int(match.group(2), 16)))
        
        return handlers
    
    # ========================================================================
    # Memory Read Operations
    # ========================================================================
    
    def read_kernel(self, addr: int, size: int = 64) -> Optional[bytes]:
        """
        Read from kernel virtual memory.
        
        Args:
            addr: Kernel virtual address
            size: Number of bytes to read
            
        Returns:
            Bytes read or None on failure
        """
        output = self._run_cmd('rk', f'0x{addr:x}', size, raw=True)
        return self._parse_hexdump(output)
    
    def read_physical(self, addr: int, size: int = 64) -> Optional[bytes]:
        """
        Read from physical memory.
        
        Args:
            addr: Physical address
            size: Number of bytes to read
            
        Returns:
            Bytes read or None on failure
        """
        output = self._run_cmd('rp', f'0x{addr:x}', size, raw=True)
        return self._parse_hexdump(output)
    
    def read_guest(self, addr: int, size: int = 64, mode: int = 0) -> Optional[bytes]:
        """
        Read from guest memory.
        
        Args:
            addr: Guest address
            size: Number of bytes to read
            mode: 0=GPA, 1=GVA, 2=GFN
            
        Returns:
            Bytes read or None on failure
        """
        output = self._run_cmd('rg', f'0x{addr:x}', size, mode, raw=True)
        return self._parse_hexdump(output)
    
    def read_pfn(self, pfn: int, size: int = 64) -> Optional[bytes]:
        """
        Read from page frame number.
        
        Args:
            pfn: Page frame number
            size: Number of bytes to read
            
        Returns:
            Bytes read or None on failure
        """
        output = self._run_cmd('rpfn', f'0x{pfn:x}', size, raw=True)
        return self._parse_hexdump(output)
    
    def read_auto(self, addr: int, size: int = 64) -> Optional[bytes]:
        """
        Read from memory, auto-detecting address type.
        
        Args:
            addr: Address (kernel virtual or physical)
            size: Number of bytes to read
            
        Returns:
            Bytes read or None on failure
        """
        if is_kernel_virtual_addr(addr):
            return self.read_kernel(addr, size)
        else:
            return self.read_physical(addr, size)
    
    def read_qword(self, addr: int) -> Optional[int]:
        """Read 8-byte value from memory"""
        data = self.read_auto(addr, 8)
        if data and len(data) >= 8:
            return struct.unpack('<Q', data[:8])[0]
        return None
    
    def read_dword(self, addr: int) -> Optional[int]:
        """Read 4-byte value from memory"""
        data = self.read_auto(addr, 4)
        if data and len(data) >= 4:
            return struct.unpack('<I', data[:4])[0]
        return None
    
    def read_cr(self, cr_num: int) -> Optional[int]:
        """
        Read control register.
        
        Args:
            cr_num: CR number (0, 2, 3, or 4)
            
        Returns:
            CR value or None on failure
        """
        output = self._run_cmd('cr', cr_num, raw=True)
        return self._parse_hex(output)
    
    def read_msr(self, msr: int) -> Optional[int]:
        """
        Read model-specific register.
        
        Args:
            msr: MSR number
            
        Returns:
            MSR value or None on failure
        """
        output = self._run_cmd('msr', f'0x{msr:x}', raw=True)
        return self._parse_hex(output)
    
    def get_kaslr_info(self) -> Optional[KASLRInfo]:
        """
        Get KASLR and memory layout information.
        
        Returns:
            KASLRInfo object or None on failure
        """
        if self._kaslr_cache:
            return self._kaslr_cache
        
        output = self._run_cmd('kaslr', json_output=True)
        if not output:
            return None
        
        try:
            data = json.loads(output)
            info = KASLRInfo(
                kernel_base=int(data.get('kernel_base', '0'), 16),
                kaslr_slide=int(data.get('kaslr_slide', '0'), 16),
                physmap_base=int(data.get('physmap_base', '0'), 16),
                vmalloc_base=int(data.get('vmalloc_base', '0'), 16),
                vmemmap_base=int(data.get('vmemmap_base', '0'), 16),
            )
            self._kaslr_cache = info
            return info
        except (json.JSONDecodeError, KeyError):
            pass
        
        # Parse non-JSON output
        import re
        info = KASLRInfo()
        for line in (output or '').split('\n'):
            if 'Kernel Base' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.kernel_base = int(m.group(1), 16)
            elif 'KASLR Slide' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.kaslr_slide = int(m.group(1), 16)
            elif 'Physmap' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.physmap_base = int(m.group(1), 16)
            elif 'vmalloc' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.vmalloc_base = int(m.group(1), 16)
            elif 'vmemmap' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.vmemmap_base = int(m.group(1), 16)
        
        self._kaslr_cache = info
        return info
    
    def dump_page_tables(self, vaddr: int) -> Optional[PageTableInfo]:
        """
        Dump page tables for virtual address.
        
        Args:
            vaddr: Virtual address to walk
            
        Returns:
            PageTableInfo object or None on failure
        """
        output = self._run_cmd('pt', f'0x{vaddr:x}')
        if not output:
            return None
        
        info = PageTableInfo(virtual_addr=vaddr)
        import re
        
        for line in output.split('\n'):
            if 'PML4E' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pml4e = int(m.group(1), 16)
            elif 'PDPTE' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pdpte = int(m.group(1), 16)
            elif 'PDE' in line and 'PDPTE' not in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pde = int(m.group(1), 16)
            elif 'PTE' in line and 'PDPTE' not in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pte = int(m.group(1), 16)
            elif 'Physical' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.physical_addr = int(m.group(1), 16)
            elif 'Flags' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.flags = int(m.group(1), 16)
        
        return info
    
    def find_pattern(self, start: int, end: int, pattern: bytes) -> Optional[int]:
        """
        Find pattern in memory range.
        
        Args:
            start: Start address
            end: End address
            pattern: Pattern to find (up to 16 bytes)
            
        Returns:
            Address where pattern found or None
        """
        pattern_hex = pattern.hex()
        output = self._run_cmd('find', f'0x{start:x}', f'0x{end:x}', pattern_hex)
        
        if output and 'found' in output.lower():
            return self._parse_hex(output)
        return None
    
    def scan_region(self, start: int, end: int, step: int = 4096, 
                    region_type: int = 0) -> bool:
        """
        Scan memory region.
        
        Args:
            start: Start address
            end: End address  
            step: Step size
            region_type: 0=physical, 1=kernel, 2=guest
            
        Returns:
            True if scan completed successfully
        """
        output = self._run_cmd('scan', f'0x{start:x}', f'0x{end:x}', step)
        return output is not None
    
    # ========================================================================
    # Memory Write Operations
    # ========================================================================
    
    def write_kernel(self, addr: int, data: bytes, disable_wp: bool = True) -> bool:
        """
        Write to kernel virtual memory.
        
        Args:
            addr: Kernel virtual address
            data: Data to write
            disable_wp: Disable write protection (CR0.WP)
            
        Returns:
            True on success
        """
        hex_data = data.hex()
        args = ['wk', f'0x{addr:x}', hex_data]
        if disable_wp:
            args.append('1')
        
        output = self._run_cmd(*args)
        return output is not None and 'error' not in output.lower()
    
    def write_physical(self, addr: int, data: bytes, method: int = 0) -> bool:
        """
        Write to physical memory.
        
        Args:
            addr: Physical address
            data: Data to write
            method: Write method (0=default)
            
        Returns:
            True on success
        """
        hex_data = data.hex()
        output = self._run_cmd('wp', f'0x{addr:x}', hex_data, method)
        return output is not None and 'error' not in output.lower()
    
    def write_guest(self, addr: int, data: bytes, mode: int = 0) -> bool:
        """
        Write to guest memory.
        
        Args:
            addr: Guest address
            data: Data to write
            mode: 0=GPA, 1=GVA
            
        Returns:
            True on success
        """
        hex_data = data.hex()
        output = self._run_cmd('wg', f'0x{addr:x}', hex_data, mode)
        return output is not None and 'error' not in output.lower()
    
    def write_auto(self, addr: int, data: bytes) -> bool:
        """
        Write to memory, auto-detecting address type.
        
        Args:
            addr: Address (kernel virtual or physical)
            data: Data to write
            
        Returns:
            True on success
        """
        if is_kernel_virtual_addr(addr):
            return self.write_kernel(addr, data)
        else:
            return self.write_physical(addr, data)
    
    def write_qword(self, addr: int, value: int) -> bool:
        """Write 8-byte value to memory"""
        return self.write_auto(addr, struct.pack('<Q', value))
    
    def write_dword(self, addr: int, value: int) -> bool:
        """Write 4-byte value to memory"""
        return self.write_auto(addr, struct.pack('<I', value))
    
    def write_msr(self, msr: int, value: int) -> bool:
        """
        Write to model-specific register.
        
        Args:
            msr: MSR number
            value: Value to write
            
        Returns:
            True on success
        """
        output = self._run_cmd('wmsr', f'0x{msr:x}', f'0x{value:x}')
        return output is not None and 'error' not in output.lower()
    
    def write_cr(self, cr_num: int, value: int, mask: int = 0) -> bool:
        """
        Write to control register.
        
        Args:
            cr_num: CR number
            value: Value to write
            mask: Optional mask
            
        Returns:
            True on success
        """
        args = ['wcr', cr_num, f'0x{value:x}']
        if mask:
            args.append(f'0x{mask:x}')
        
        output = self._run_cmd(*args)
        return output is not None and 'error' not in output.lower()
    
    def memset_kernel(self, addr: int, value: int, length: int) -> bool:
        """
        Memset kernel memory.
        
        Args:
            addr: Kernel address
            value: Byte value
            length: Number of bytes
            
        Returns:
            True on success
        """
        output = self._run_cmd('memset-k', f'0x{addr:x}', value, length)
        return output is not None and 'error' not in output.lower()
    
    def memset_physical(self, addr: int, value: int, length: int) -> bool:
        """
        Memset physical memory.
        
        Args:
            addr: Physical address
            value: Byte value
            length: Number of bytes
            
        Returns:
            True on success
        """
        output = self._run_cmd('memset-p', f'0x{addr:x}', value, length)
        return output is not None and 'error' not in output.lower()
    
    def patch_bytes(self, addr: int, patch: bytes, original: bytes = None,
                    addr_type: int = 0) -> bool:
        """
        Patch bytes at address with optional verification.
        
        Args:
            addr: Address to patch
            patch: New bytes
            original: Expected original bytes (for verification)
            addr_type: 0=kernel, 1=physical
            
        Returns:
            True on success
        """
        patch_hex = patch.hex()
        orig_hex = original.hex() if original else None
        
        args = ['patch', f'0x{addr:x}', patch_hex]
        if orig_hex:
            args.append(orig_hex)
        
        output = self._run_cmd(*args)
        return output is not None and 'error' not in output.lower()
    
    def write_and_flush(self, addr: int, data: bytes, addr_type: int = 0) -> bool:
        """
        Write to memory and flush cache.
        
        Args:
            addr: Address
            data: Data to write
            addr_type: 0=kernel, 1=physical
            
        Returns:
            True on success
        """
        hex_data = data.hex()
        output = self._run_cmd('wflush', f'0x{addr:x}', hex_data)
        return output is not None and 'error' not in output.lower()
    
    # ========================================================================
    # Address Translation Operations
    # ========================================================================
    
    def virt_to_phys(self, vaddr: int) -> Optional[int]:
        """
        Convert kernel virtual address to physical.
        
        Args:
            vaddr: Virtual address
            
        Returns:
            Physical address or None
        """
        output = self._run_cmd('v2p', f'0x{vaddr:x}', raw=True)
        return self._parse_hex(output)
    
    def phys_to_virt(self, paddr: int, use_ioremap: bool = False) -> Optional[int]:
        """
        Convert physical address to kernel virtual.
        
        Args:
            paddr: Physical address
            use_ioremap: Use ioremap instead of phys_to_virt
            
        Returns:
            Virtual address or None
        """
        args = ['p2v', f'0x{paddr:x}']
        if use_ioremap:
            args.append('1')
        
        output = self._run_cmd(*args, raw=True)
        return self._parse_hex(output)
    
    def virt_to_pfn(self, vaddr: int) -> Optional[int]:
        """Convert virtual address to PFN"""
        output = self._run_cmd('v2pfn', f'0x{vaddr:x}', raw=True)
        return self._parse_hex(output)
    
    def gpa_to_hva(self, gpa: int) -> Optional[int]:
        """Convert guest physical address to host virtual address"""
        output = self._run_cmd('gpa2hva', f'0x{gpa:x}', raw=True)
        return self._parse_hex(output)
    
    def gpa_to_gfn(self, gpa: int) -> Optional[int]:
        """Convert guest physical address to guest frame number"""
        output = self._run_cmd('gpa2gfn', f'0x{gpa:x}', raw=True)
        return self._parse_hex(output)
    
    def gfn_to_gpa(self, gfn: int) -> Optional[int]:
        """Convert guest frame number to guest physical address"""
        output = self._run_cmd('gfn2gpa', f'0x{gfn:x}', raw=True)
        return self._parse_hex(output)
    
    def gfn_to_hva(self, gfn: int) -> Optional[int]:
        """Convert guest frame number to host virtual address"""
        output = self._run_cmd('gfn2hva', f'0x{gfn:x}', raw=True)
        return self._parse_hex(output)
    
    def gfn_to_pfn(self, gfn: int) -> Optional[int]:
        """Convert guest frame number to physical frame number"""
        output = self._run_cmd('gfn2pfn', f'0x{gfn:x}', raw=True)
        return self._parse_hex(output)
    
    def hva_to_pfn(self, hva: int, writable: bool = False) -> Optional[int]:
        """Convert host virtual address to physical frame number"""
        args = ['hva2pfn', f'0x{hva:x}']
        if writable:
            args.append('1')
        
        output = self._run_cmd(*args, raw=True)
        return self._parse_hex(output)
    
    def hva_to_gfn(self, hva: int) -> Optional[int]:
        """Convert host virtual address to guest frame number"""
        output = self._run_cmd('hva2gfn', f'0x{hva:x}', raw=True)
        return self._parse_hex(output)
    
    def pfn_to_hva(self, pfn: int) -> Optional[int]:
        """Convert physical frame number to host virtual address"""
        output = self._run_cmd('pfn2hva', f'0x{pfn:x}', raw=True)
        return self._parse_hex(output)
    
    def page_to_pfn(self, page: int) -> Optional[int]:
        """Convert page struct address to PFN"""
        output = self._run_cmd('page2pfn', f'0x{page:x}', raw=True)
        return self._parse_hex(output)
    
    def pfn_to_page(self, pfn: int) -> Optional[int]:
        """Convert PFN to page struct address"""
        output = self._run_cmd('pfn2page', f'0x{pfn:x}', raw=True)
        return self._parse_hex(output)
    
    def walk_ept(self, eptp: int, gpa: int) -> Optional[EPTWalkInfo]:
        """
        Walk EPT tables.
        
        Args:
            eptp: EPT pointer
            gpa: Guest physical address
            
        Returns:
            EPTWalkInfo object or None
        """
        output = self._run_cmd('ept', f'0x{eptp:x}', f'0x{gpa:x}')
        if not output:
            return None
        
        info = EPTWalkInfo(eptp=eptp, gpa=gpa)
        import re
        
        for line in output.split('\n'):
            if 'PML4E' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pml4e = int(m.group(1), 16)
            elif 'PDPTE' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pdpte = int(m.group(1), 16)
            elif 'PDE' in line and 'PDPTE' not in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pde = int(m.group(1), 16)
            elif 'PTE' in line and 'PDPTE' not in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pte = int(m.group(1), 16)
            elif 'HPA' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.hpa = int(m.group(1), 16)
            elif 'Size' in line:
                m = re.search(r'(\d+)', line)
                if m:
                    info.page_size = int(m.group(1))
        
        return info
    
    def decode_spte(self, spte: int) -> Optional[SPTEInfo]:
        """
        Decode shadow page table entry.
        
        Args:
            spte: SPTE value
            
        Returns:
            SPTEInfo object or None
        """
        output = self._run_cmd('spte', f'0x{spte:x}')
        if not output:
            return None
        
        info = SPTEInfo(spte=spte)
        import re
        
        for line in output.split('\n'):
            if 'PFN' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pfn = int(m.group(1), 16)
            elif 'Flags' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.flags = int(m.group(1), 16)
            elif 'Present' in line:
                info.present = '1' in line or 'true' in line.lower()
            elif 'Writable' in line:
                info.writable = '1' in line or 'true' in line.lower()
            elif 'Executable' in line:
                info.executable = '1' in line or 'true' in line.lower()
        
        return info
    
    def translate_gva(self, gva: int, cr3: int, access: int = 0) -> Optional[Dict]:
        """
        Translate guest virtual address.
        
        Args:
            gva: Guest virtual address
            cr3: Guest CR3 value
            access: Access type
            
        Returns:
            Dictionary with gpa, hva, hpa or None
        """
        output = self._run_cmd('gva', f'0x{gva:x}', f'0x{cr3:x}', access)
        if not output:
            return None
        
        result = {'gva': gva, 'cr3': cr3}
        import re
        
        for line in output.split('\n'):
            if 'GPA' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    result['gpa'] = int(m.group(1), 16)
            elif 'HVA' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    result['hva'] = int(m.group(1), 16)
            elif 'HPA' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    result['hpa'] = int(m.group(1), 16)
        
        return result
    
    # ========================================================================
    # Cache Operations
    # ========================================================================
    
    def wbinvd(self) -> bool:
        """Writeback and invalidate all caches"""
        output = self._run_cmd('wbinvd')
        return output is not None
    
    def clflush(self, addr: int) -> bool:
        """
        Flush cache line.
        
        Args:
            addr: Address to flush
            
        Returns:
            True on success
        """
        output = self._run_cmd('clflush', f'0x{addr:x}')
        return output is not None
    
    # ========================================================================
    # Hypercall Operations
    # ========================================================================
    
    def hypercall(self, nr: int, a0: int = 0, a1: int = 0, 
                  a2: int = 0, a3: int = 0) -> int:
        """
        Execute hypercall.
        
        Args:
            nr: Hypercall number
            a0-a3: Hypercall arguments
            
        Returns:
            Hypercall result (0xffffffffffffffff on error)
        """
        output = self._run_cmd('hc', nr, f'0x{a0:x}', f'0x{a1:x}', 
                               f'0x{a2:x}', f'0x{a3:x}', raw=True)
        result = self._parse_hex(output)
        return result if result is not None else 0xffffffffffffffff
    
    def hypercall_batch(self) -> Dict[int, int]:
        """
        Execute CTF hypercalls 100-103.
        
        Returns:
            Dictionary mapping hypercall number to result
        """
        output = self._run_cmd('hc-batch', json_output=True)
        
        if output:
            try:
                data = json.loads(output)
                return {
                    100: int(data.get('hc100', '0'), 16),
                    101: int(data.get('hc101', '0'), 16),
                    102: int(data.get('hc102', '0'), 16),
                    103: int(data.get('hc103', '0'), 16),
                }
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Parse non-JSON output
        results = {}
        import re
        for line in (output or '').split('\n'):
            m = re.search(r'HC\s*(\d+).*?0x([0-9a-fA-F]+)', line)
            if m:
                results[int(m.group(1))] = int(m.group(2), 16)
        
        return results
    
    def hypercall_detect(self) -> Optional[str]:
        """
        Detect hypercall instruction type.
        
        Returns:
            "vmcall", "vmmcall", or None
        """
        output = self._run_cmd('hc-detect')
        if output:
            if 'VMCALL' in output.upper():
                return 'vmcall'
            elif 'VMMCALL' in output.upper():
                return 'vmmcall'
        return None
    
    def hypercall_scan(self, start: int = 0, end: int = 200) -> List[Tuple[int, int]]:
        """
        Scan hypercall range for valid handlers.
        
        Args:
            start: Start hypercall number
            end: End hypercall number
            
        Returns:
            List of (hypercall_number, result) tuples
        """
        output = self._run_cmd('hc-scan', start, end, timeout=60)
        if not output:
            return []
        
        results = []
        import re
        for line in output.split('\n'):
            m = re.search(r'HC\s*(\d+).*?0x([0-9a-fA-F]+)', line)
            if m:
                results.append((int(m.group(1)), int(m.group(2), 16)))
        
        return results
    
    # ========================================================================
    # AHCI Operations
    # ========================================================================
    
    def ahci_init(self) -> bool:
        """Initialize AHCI controller"""
        output = self._run_cmd('ahci-init')
        return output is not None
    
    def ahci_info(self) -> Optional[AHCIInfo]:
        """
        Get AHCI controller information.
        
        Returns:
            AHCIInfo object or None
        """
        output = self._run_cmd('ahci-info')
        if not output:
            return None
        
        info = AHCIInfo()
        import re
        
        for line in output.split('\n'):
            if 'CAP' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.cap = int(m.group(1), 16)
            elif 'GHC' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.ghc = int(m.group(1), 16)
            elif 'PI' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.pi = int(m.group(1), 16)
            elif 'VS' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    info.vs = int(m.group(1), 16)
            elif 'Port' in line and 'SSTS' in line:
                m = re.search(r'Port\s*(\d+).*SSTS=0x([0-9a-fA-F]+)', line)
                if m:
                    port = int(m.group(1))
                    if port < 6:
                        info.port_ssts[port] = int(m.group(2), 16)
        
        return info
    
    def ahci_read(self, port: int, offset: int) -> Optional[int]:
        """
        Read AHCI register.
        
        Args:
            port: Port number
            offset: Register offset
            
        Returns:
            Register value or None
        """
        output = self._run_cmd('ahci-read', port, f'0x{offset:x}', raw=True)
        return self._parse_hex(output)
    
    def ahci_write(self, port: int, offset: int, value: int) -> bool:
        """
        Write AHCI register.
        
        Args:
            port: Port number
            offset: Register offset
            value: Value to write
            
        Returns:
            True on success
        """
        output = self._run_cmd('ahci-write', port, f'0x{offset:x}', f'0x{value:x}')
        return output is not None
    
    def ahci_set_fis_base(self, port: int, fis: int, clb: int) -> bool:
        """
        Set AHCI FIS and CLB base addresses.
        
        Args:
            port: Port number
            fis: FIS base address
            clb: CLB base address
            
        Returns:
            True on success
        """
        output = self._run_cmd('ahci-fis', port, f'0x{fis:x}', f'0x{clb:x}')
        return output is not None
    
    # ========================================================================
    # High-Level Operations
    # ========================================================================
    
    def full_recon(self) -> Dict:
        """
        Perform full system reconnaissance.
        
        Returns:
            Dictionary with system information
        """
        output = self._run_cmd('recon', timeout=30)
        
        info = {
            'kaslr': None,
            'cr0': None,
            'cr3': None,
            'cr4': None,
            'hypercall_type': None,
            'symbols': {}
        }
        
        # Get KASLR info
        info['kaslr'] = self.get_kaslr_info()
        
        # Get CRs
        info['cr0'] = self.read_cr(0)
        info['cr3'] = self.read_cr(3)
        info['cr4'] = self.read_cr(4)
        
        # Detect hypercall type
        info['hypercall_type'] = self.hypercall_detect()
        
        # Get key symbols
        key_symbols = ['init_task', 'prepare_kernel_cred', 'commit_creds',
                       'kvm_vcpu_read_guest', 'vmx_vcpu_run']
        for sym in key_symbols:
            addr = self.lookup_symbol(sym)
            if addr:
                info['symbols'][sym] = addr
        
        return info
    
    def hunt_flags(self, start: int = 0, size: int = 256 * 1024 * 1024) -> List[Tuple[int, str]]:
        """
        Hunt for CTF flags in physical memory.
        
        Args:
            start: Start address
            size: Size to scan
            
        Returns:
            List of (address, context) tuples
        """
        output = self._run_cmd('hunt', f'0x{start:x}', f'{size}', timeout=300)
        if not output:
            return []
        
        flags = []
        import re
        
        for line in output.split('\n'):
            if 'FLAG' in line.upper() or 'CTF' in line.upper():
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    addr = int(m.group(1), 16)
                    # Get context
                    context = line.split(':')[-1].strip() if ':' in line else line
                    flags.append((addr, context))
        
        return flags
    
    # ========================================================================
    # Convenience Methods
    # ========================================================================
    
    def is_available(self) -> bool:
        """Check if KVM probe is available"""
        return self.kvm_pwn is not None
    
    def test_connection(self) -> bool:
        """Test connection to kernel driver"""
        output = self._run_cmd('kaslr')
        return output is not None
    
    def close(self):
        """Clean up resources"""
        pass  # No persistent resources with CLI interface


# ============================================================================
# Convenience Functions
# ============================================================================

def create_probe(verbose: bool = False) -> KVMProbe:
    """Create and return a KVMProbe instance"""
    return KVMProbe(verbose=verbose)


# ============================================================================
# CLI Testing
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='KVM Probe Interface Test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--test', action='store_true', help='Run all tests')
    args = parser.parse_args()
    
    print("KVM Probe Interface Test")
    print("=" * 50)
    
    probe = KVMProbe(verbose=args.verbose)
    
    if not probe.is_available():
        print("[-] kvm_pwn not available")
        sys.exit(1)
    
    print("[+] kvm_pwn found")
    
    if not probe.test_connection():
        print("[-] Cannot connect to kernel driver")
        print("[!] Make sure kvm_probe_drv is loaded: sudo insmod kvm_probe_drv.ko")
        sys.exit(1)
    
    print("[+] Connection to kernel driver OK")
    
    if args.test:
        print("\n[*] Running tests...\n")
        
        # KASLR info
        print("[*] KASLR Info:")
        info = probe.get_kaslr_info()
        if info:
            print(f"    Kernel base:  0x{info.kernel_base:016x}")
            print(f"    KASLR slide:  0x{info.kaslr_slide:016x}")
            print(f"    Physmap base: 0x{info.physmap_base:016x}")
        
        # Symbol lookup
        print("\n[*] Symbol Lookup:")
        init_task = probe.lookup_symbol("init_task")
        if init_task:
            print(f"    init_task = 0x{init_task:016x}")
        
        # Hypercall detection
        print("\n[*] Hypercall Detection:")
        hc_type = probe.hypercall_detect()
        print(f"    Type: {hc_type or 'unknown'}")
        
        # CTF batch
        print("\n[*] CTF Hypercalls (100-103):")
        batch = probe.hypercall_batch()
        for nr, val in sorted(batch.items()):
            print(f"    HC {nr}: 0x{val:016x}")
        
        # Memory read
        print("\n[*] Physical Memory Read (0x1000):")
        data = probe.read_physical(0x1000, 16)
        if data:
            print(f"    {data.hex()}")
        
        print("\n[+] All tests completed")