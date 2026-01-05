#!/usr/bin/env python3
"""
Consolidated KVM probe interface: IOCTL constants and MemoryInterface.
"""

import os
import fcntl
import struct
import ctypes

# Device
DEVICE_FILE = "/dev/kvm_probe_dev"
IOCTL_BASE = 0x4000

# Memory read/write
IOCTL_READ_KERNEL_MEM    = IOCTL_BASE + 0x10
IOCTL_READ_PHYSICAL_MEM  = IOCTL_BASE + 0x11
IOCTL_READ_GUEST_MEM     = IOCTL_BASE + 0x12
IOCTL_WRITE_KERNEL_MEM   = IOCTL_BASE + 0x20
IOCTL_WRITE_PHYSICAL_MEM = IOCTL_BASE + 0x21
IOCTL_WRITE_GUEST_MEM    = IOCTL_BASE + 0x22

# Hypercall
IOCTL_HYPERCALL          = IOCTL_BASE + 0x60
IOCTL_HYPERCALL_BATCH    = IOCTL_BASE + 0x61

# Other
IOCTL_GET_KASLR_INFO     = IOCTL_BASE + 0x1A


def is_kernel_virtual_addr(addr: int) -> bool:
    return addr >= 0xffff800000000000 or (0xffffffff80000000 <= addr < 0xffffffffffffffff)


def is_physical_addr(addr: int) -> bool:
    return addr < 0x100000000000 and not is_kernel_virtual_addr(addr)


class MemoryInterface:
    """Unified memory interface to /dev/kvm_probe_dev"""

    def __init__(self, device: str = DEVICE_FILE):
        self.device = device
        try:
            self.fd = os.open(self.device, os.O_RDWR)
        except Exception as e:
            self.fd = None
            raise

    def __del__(self):
        try:
            if hasattr(self, 'fd') and self.fd is not None:
                os.close(self.fd)
        except:
            pass

    def read_phys(self, addr: int, size: int):
        if is_kernel_virtual_addr(addr):
            ioctl = IOCTL_READ_KERNEL_MEM
        else:
            ioctl = IOCTL_READ_PHYSICAL_MEM
        buf = ctypes.create_string_buffer(size)
        req = struct.pack('QQQ', addr, size, ctypes.addressof(buf))
        try:
            fcntl.ioctl(self.fd, ioctl, req)
            return buf.raw
        except Exception:
            return None

    def write_phys(self, addr: int, data: bytes) -> bool:
        if is_kernel_virtual_addr(addr):
            ioctl = IOCTL_WRITE_KERNEL_MEM
        else:
            ioctl = IOCTL_WRITE_PHYSICAL_MEM
        buf = ctypes.create_string_buffer(data)
        req = struct.pack('QQQ', addr, len(data), ctypes.addressof(buf))
        try:
            fcntl.ioctl(self.fd, ioctl, req)
            return True
        except Exception:
            return False

    def read_dword(self, addr: int) -> int:
        data = self.read_phys(addr, 4)
        return struct.unpack('<I', data)[0] if data else 0

    def write_dword(self, addr: int, value: int) -> bool:
        return self.write_phys(addr, struct.pack('<I', value))

    def read_qword(self, addr: int) -> int:
        data = self.read_phys(addr, 8)
        return struct.unpack('<Q', data)[0] if data else 0

    def write_qword(self, addr: int, value: int) -> bool:
        return self.write_phys(addr, struct.pack('<Q', value))

    def hypercall(self, nr: int, a0: int = 0, a1: int = 0, a2: int = 0, a3: int = 0) -> int:
        req = struct.pack('QQQQQQ', nr, a0, a1, a2, a3, 0)
        try:
            result = fcntl.ioctl(self.fd, IOCTL_HYPERCALL, req)
            if isinstance(result, bytes) and len(result) >= 48:
                vals = struct.unpack('QQQQQQ', result)
                return vals[5]
            return 0xffffffffffffffff
        except Exception:
            return 0xffffffffffffffff

    def batch_hypercalls(self):
        req = struct.pack('QQQQ', 0, 0, 0, 0)
        try:
            result = fcntl.ioctl(self.fd, IOCTL_HYPERCALL_BATCH, req)
            if isinstance(result, bytes) and len(result) >= 32:
                r = struct.unpack('QQQQ', result)
                return {100: r[0], 101: r[1], 102: r[2], 103: r[3]}
            return {}
        except Exception:
            return {}
