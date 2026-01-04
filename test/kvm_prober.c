/*
 * KVM Prober - Userspace Tool for KVM Probe Driver
 * Complete interface for all driver operations
 *
 * Step 1: Symbol Operations
 * Step 2: Memory Read Operations
 * Step 3: Memory Write Operations
 * Step 4: Address Conversion Operations
 * Step 5: Hypercall Operations
 * Step 6: AHCI Direct Access
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>

/* ========================================================================
 * Constants
 * ======================================================================== */

#define DEVICE_PATH "/dev/kvm_probe_dev"
#define MAX_SYMBOL_NAME 128
#define PAGE_SIZE 4096

/* Colors for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

/* ========================================================================
 * Data Structures (must match kernel driver)
 * ======================================================================== */

/* Symbol lookup request */
struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
};

/* KVM handler info */
struct handler_info {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char type[32];
};

/* Kernel memory read request */
struct kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

/* Physical memory read request */
struct physical_mem_read {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

/* Guest memory read request */
struct guest_mem_read {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char *user_buffer;
    int mode;
};

/* Memory region descriptor */
struct mem_region {
    unsigned long start;
    unsigned long end;
    unsigned long step;
    unsigned char *buffer;
    size_t buffer_size;
    int region_type;
};

/* MSR read request */
struct msr_read_request {
    unsigned int msr;
    unsigned long long value;
};

/* Pattern search request */
struct pattern_search_request {
    unsigned long start;
    unsigned long end;
    unsigned char pattern[16];
    size_t pattern_len;
    unsigned long found_addr;
};

/* Page table dump request */
struct page_table_dump {
    unsigned long virtual_addr;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    unsigned long physical_addr;
    unsigned int flags;
};

/* EPT pointer request */
struct ept_pointer_request {
    unsigned long eptp;
    unsigned long root_hpa;
    int level;
};

/* Guest register dump */
struct guest_registers {
    unsigned long rax, rbx, rcx, rdx;
    unsigned long rsi, rdi, rbp, rsp;
    unsigned long r8, r9, r10, r11;
    unsigned long r12, r13, r14, r15;
    unsigned long rip, rflags;
    unsigned long cr0, cr2, cr3, cr4;
    unsigned long dr0, dr1, dr2, dr3, dr6, dr7;
};

/* KASLR info request */
struct kaslr_info {
    unsigned long kernel_base;
    unsigned long kaslr_slide;
    unsigned long physmap_base;
    unsigned long vmalloc_base;
    unsigned long vmemmap_base;
};

/* Kernel memory write request */
struct kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buffer;
    int disable_wp;
};

/* Physical memory write request */
struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
    int method;
};

/* Guest memory write request */
struct guest_mem_write {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char *user_buffer;
    int mode;
};

/* MSR write request */
struct msr_write_request {
    unsigned int msr;
    unsigned long long value;
};

/* CR write request */
struct cr_write_request {
    int cr_num;
    unsigned long value;
    unsigned long mask;
};

/* Memory set request */
struct memset_request {
    unsigned long addr;
    unsigned char value;
    unsigned long length;
    int addr_type;
};

/* Memory copy request */
struct memcpy_request {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned long length;
    int src_type;
    int dst_type;
};

/* Byte patch request */
struct patch_request {
    unsigned long addr;
    unsigned char original[32];
    unsigned char patch[32];
    size_t length;
    int verify_original;
    int addr_type;
};

/* Generic address conversion request */
struct addr_conv_request {
    unsigned long input_addr;
    unsigned long output_addr;
    int status;
};

/* GPA to HVA conversion */
struct gpa_to_hva_request {
    unsigned long gpa;
    unsigned long hva;
    unsigned long gfn;
    int vm_fd;
    int status;
};

/* GFN to HVA conversion */
struct gfn_to_hva_request {
    unsigned long gfn;
    unsigned long hva;
    int vm_fd;
    int status;
};

/* GFN to PFN conversion */
struct gfn_to_pfn_request {
    unsigned long gfn;
    unsigned long pfn;
    int vm_fd;
    int status;
};

/* HVA to PFN conversion */
struct hva_to_pfn_request {
    unsigned long hva;
    unsigned long pfn;
    int writable;
    int status;
};

/* Virtual to Physical conversion */
struct virt_to_phys_request {
    unsigned long virt_addr;
    unsigned long phys_addr;
    unsigned long pfn;
    unsigned long offset;
    int status;
};

/* Physical to Virtual conversion */
struct phys_to_virt_request {
    unsigned long phys_addr;
    unsigned long virt_addr;
    int use_ioremap;
    int status;
};

/* SPTE to PFN extraction */
struct spte_to_pfn_request {
    unsigned long spte;
    unsigned long pfn;
    unsigned long flags;
    int present;
    int writable;
    int executable;
    int status;
};

/* EPT walk request */
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

/* GVA translation request */
struct gva_translate_request {
    unsigned long gva;
    unsigned long gpa;
    unsigned long hva;
    unsigned long hpa;
    unsigned long cr3;
    int access_type;
    int status;
};

/* AHCI register request */
struct ahci_reg_request {
    uint32_t port;
    uint32_t offset;
    uint32_t value;
    int is_write;
};

/* AHCI FIS base request */
struct ahci_fis_request {
    uint32_t port;
    uint64_t fis_base;
    uint64_t clb_base;
};

/* AHCI info structure */
struct ahci_info {
    uint32_t cap;
    uint32_t ghc;
    uint32_t pi;
    uint32_t vs;
    uint32_t port_ssts[6];
};

/* Single hypercall request */
struct hypercall_request {
    uint64_t nr;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t result;
};

/* Batch hypercall request (100-103) */
struct hypercall_batch_request {
    uint64_t r100;
    uint64_t r101;
    uint64_t r102;
    uint64_t r103;
};

/* ========================================================================
 * IOCTL Definitions (must match kernel driver)
 * ======================================================================== */

#define IOCTL_BASE 0x4000

/* Symbol operations (Step 1) */
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_FIND_SYMBOL_BY_NAME    (IOCTL_BASE + 0x04)
#define IOCTL_GET_VMX_HANDLERS       (IOCTL_BASE + 0x05)
#define IOCTL_GET_SVM_HANDLERS       (IOCTL_BASE + 0x06)
#define IOCTL_SEARCH_SYMBOLS         (IOCTL_BASE + 0x07)

/* Memory read operations (Step 2) */
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

/* Memory write operations (Step 3) */
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

/* Address conversion operations (Step 4) */
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

/* Cache Operations */
#define IOCTL_WBINVD                  (IOCTL_BASE + 0x40)
#define IOCTL_CLFLUSH                 (IOCTL_BASE + 0x41)
#define IOCTL_WRITE_AND_FLUSH         (IOCTL_BASE + 0x42)

/* AHCI Direct Access */
#define IOCTL_AHCI_INIT               (IOCTL_BASE + 0x50)
#define IOCTL_AHCI_READ_REG           (IOCTL_BASE + 0x51)
#define IOCTL_AHCI_WRITE_REG          (IOCTL_BASE + 0x52)
#define IOCTL_AHCI_SET_FIS_BASE       (IOCTL_BASE + 0x53)
#define IOCTL_AHCI_INFO               (IOCTL_BASE + 0x54)

/* Hypercall Operations (Step 5) */
#define IOCTL_HYPERCALL               (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_BATCH         (IOCTL_BASE + 0x61)
#define IOCTL_HYPERCALL_DETECT        (IOCTL_BASE + 0x62)

/* ========================================================================
 * Global Variables
 * ======================================================================== */

static int g_fd = -1;
static int g_verbose = 0;

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

static void hexdump(const void *data, size_t size, unsigned long base_addr)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%s0x%016lx%s: ", COLOR_CYAN, base_addr + i, COLOR_RESET);

        /* Hex bytes */
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", p[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        printf(" |");

        /* ASCII representation */
        for (j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = p[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }

        printf("|\n");
    }
}

static int open_device(void)
{
    if (g_fd >= 0) {
        return 0;
    }

    g_fd = open(DEVICE_PATH, O_RDWR);
    if (g_fd < 0) {
        fprintf(stderr, "%s[ERROR]%s Failed to open %s: %s\n",
                COLOR_RED, COLOR_RESET, DEVICE_PATH, strerror(errno));
        return -1;
    }

    if (g_verbose) {
        printf("%s[INFO]%s Opened device %s (fd=%d)\n",
               COLOR_GREEN, COLOR_RESET, DEVICE_PATH, g_fd);
    }

    return 0;
}

static void close_device(void)
{
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}

/* ========================================================================
 * Step 1: Symbol Operations
 * ======================================================================== */

unsigned long lookup_symbol(const char *name)
{
    struct symbol_request req;
    int ret;

    if (open_device() < 0) return 0;

    memset(&req, 0, sizeof(req));
    strncpy(req.name, name, MAX_SYMBOL_NAME - 1);

    ret = ioctl(g_fd, IOCTL_LOOKUP_SYMBOL, &req);
    if (ret < 0 && errno != ENOENT) {
        fprintf(stderr, "%s[ERROR]%s Symbol lookup failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return 0;
    }

    return req.address;
}

int lookup_symbol_verbose(const char *name, struct symbol_request *out)
{
    int ret;

    if (open_device() < 0) return -1;

    memset(out, 0, sizeof(*out));
    strncpy(out->name, name, MAX_SYMBOL_NAME - 1);

    ret = ioctl(g_fd, IOCTL_LOOKUP_SYMBOL, out);
    if (ret < 0 && errno != ENOENT) {
        fprintf(stderr, "%s[ERROR]%s Symbol lookup failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    if (out->address) {
        printf("%s[SYMBOL]%s %s = %s0x%016lx%s",
               COLOR_GREEN, COLOR_RESET, name, COLOR_YELLOW, out->address, COLOR_RESET);
        if (out->description[0]) {
            printf(" (%s)", out->description);
        }
        printf("\n");
    } else {
        printf("%s[SYMBOL]%s %s = %s(not found)%s\n",
               COLOR_YELLOW, COLOR_RESET, name, COLOR_RED, COLOR_RESET);
    }

    return out->address ? 0 : -1;
}

unsigned int get_symbol_count(void)
{
    unsigned int count = 0;

    if (open_device() < 0) return 0;

    if (ioctl(g_fd, IOCTL_GET_SYMBOL_COUNT, &count) < 0) {
        fprintf(stderr, "%s[ERROR]%s Get symbol count failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return 0;
    }

    return count;
}

int list_all_symbols(void)
{
    unsigned int count, i;
    struct symbol_request req;
    int found = 0;

    if (open_device() < 0) return -1;

    count = get_symbol_count();
    printf("%s[INFO]%s Total KVM symbols found: %u\n", COLOR_CYAN, COLOR_RESET, count);

    for (i = 0; i < count + 100; i++) {  /* Iterate a bit more to find all */
        memset(&req, 0, sizeof(req));

        if (ioctl(g_fd, IOCTL_GET_SYMBOL_BY_INDEX, &i) < 0) {
            continue;
        }

        /* Try to get symbol by index */
        unsigned int idx = i;
        if (ioctl(g_fd, IOCTL_GET_SYMBOL_BY_INDEX, &idx) == 0) {
            found++;
        }
    }

    return 0;
}

/* ========================================================================
 * Step 2: Memory Read Operations
 * ======================================================================== */

int read_kernel_memory(unsigned long addr, void *buffer, size_t length)
{
    struct kernel_mem_read req;

    if (open_device() < 0) return -1;

    req.kernel_addr = addr;
    req.length = length;
    req.user_buffer = buffer;

    if (ioctl(g_fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
        if (g_verbose) {
            fprintf(stderr, "%s[ERROR]%s Read kernel memory failed at 0x%lx: %s\n",
                    COLOR_RED, COLOR_RESET, addr, strerror(errno));
        }
        return -1;
    }

    return 0;
}

int read_physical_memory(unsigned long addr, void *buffer, size_t length)
{
    struct physical_mem_read req;

    if (open_device() < 0) return -1;

    req.phys_addr = addr;
    req.length = length;
    req.user_buffer = buffer;

    if (ioctl(g_fd, IOCTL_READ_PHYSICAL_MEM, &req) < 0) {
        if (g_verbose) {
            fprintf(stderr, "%s[ERROR]%s Read physical memory failed at 0x%lx: %s\n",
                    COLOR_RED, COLOR_RESET, addr, strerror(errno));
        }
        return -1;
    }

    return 0;
}

int read_msr(unsigned int msr, uint64_t *value)
{
    struct msr_read_request req;

    if (open_device() < 0) return -1;

    req.msr = msr;
    req.value = 0;

    if (ioctl(g_fd, IOCTL_READ_MSR, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Read MSR 0x%x failed: %s\n",
                COLOR_RED, COLOR_RESET, msr, strerror(errno));
        return -1;
    }

    *value = req.value;
    return 0;
}

int get_kaslr_info(struct kaslr_info *info)
{
    if (open_device() < 0) return -1;

    if (ioctl(g_fd, IOCTL_GET_KASLR_INFO, info) < 0) {
        fprintf(stderr, "%s[ERROR]%s Get KASLR info failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return 0;
}

int dump_page_tables(unsigned long vaddr, struct page_table_dump *dump)
{
    if (open_device() < 0) return -1;

    dump->virtual_addr = vaddr;

    if (ioctl(g_fd, IOCTL_DUMP_PAGE_TABLES, dump) < 0) {
        fprintf(stderr, "%s[ERROR]%s Dump page tables failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return 0;
}

/* ========================================================================
 * Step 3: Memory Write Operations
 * ======================================================================== */

int write_kernel_memory(unsigned long addr, void *buffer, size_t length, int disable_wp)
{
    struct kernel_mem_write req;

    if (open_device() < 0) return -1;

    req.kernel_addr = addr;
    req.length = length;
    req.user_buffer = buffer;
    req.disable_wp = disable_wp;

    if (ioctl(g_fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Write kernel memory failed at 0x%lx: %s\n",
                COLOR_RED, COLOR_RESET, addr, strerror(errno));
        return -1;
    }

    return 0;
}

int write_physical_memory(unsigned long addr, void *buffer, size_t length, int method)
{
    struct physical_mem_write req;

    if (open_device() < 0) return -1;

    req.phys_addr = addr;
    req.length = length;
    req.user_buffer = buffer;
    req.method = method;

    if (ioctl(g_fd, IOCTL_WRITE_PHYSICAL_MEM, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Write physical memory failed at 0x%lx: %s\n",
                COLOR_RED, COLOR_RESET, addr, strerror(errno));
        return -1;
    }

    return 0;
}

int write_msr(unsigned int msr, uint64_t value)
{
    struct msr_write_request req;

    if (open_device() < 0) return -1;

    req.msr = msr;
    req.value = value;

    if (ioctl(g_fd, IOCTL_WRITE_MSR, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Write MSR 0x%x failed: %s\n",
                COLOR_RED, COLOR_RESET, msr, strerror(errno));
        return -1;
    }

    return 0;
}

/* ========================================================================
 * Step 4: Address Conversion Operations
 * ======================================================================== */

int virt_to_phys(unsigned long vaddr, struct virt_to_phys_request *req)
{
    if (open_device() < 0) return -1;

    req->virt_addr = vaddr;

    if (ioctl(g_fd, IOCTL_VIRT_TO_PHYS, req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Virt to phys failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return req->status;
}

int phys_to_virt(unsigned long paddr, struct phys_to_virt_request *req)
{
    if (open_device() < 0) return -1;

    req->phys_addr = paddr;

    if (ioctl(g_fd, IOCTL_PHYS_TO_VIRT, req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Phys to virt failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return req->status;
}

int walk_ept(unsigned long eptp, unsigned long gpa, struct ept_walk_request *req)
{
    if (open_device() < 0) return -1;

    req->eptp = eptp;
    req->gpa = gpa;

    if (ioctl(g_fd, IOCTL_WALK_EPT, req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Walk EPT failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return req->status;
}

int hva_to_pfn(unsigned long hva, struct hva_to_pfn_request *req)
{
    if (open_device() < 0) return -1;

    req->hva = hva;

    if (ioctl(g_fd, IOCTL_HVA_TO_PFN, req) < 0) {
        fprintf(stderr, "%s[ERROR]%s HVA to PFN failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return req->status;
}

/* ========================================================================
 * Step 5: Hypercall Operations
 * ======================================================================== */

uint64_t do_hypercall(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    struct hypercall_request req;

    if (open_device() < 0) return (uint64_t)-1;

    req.nr = nr;
    req.a0 = a0;
    req.a1 = a1;
    req.a2 = a2;
    req.a3 = a3;
    req.result = 0;

    if (ioctl(g_fd, IOCTL_HYPERCALL, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Hypercall %lu failed: %s\n",
                COLOR_RED, COLOR_RESET, nr, strerror(errno));
        return (uint64_t)-1;
    }

    return req.result;
}

int hypercall_verbose(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t *result)
{
    struct hypercall_request req;

    if (open_device() < 0) return -1;

    req.nr = nr;
    req.a0 = a0;
    req.a1 = a1;
    req.a2 = a2;
    req.a3 = a3;
    req.result = 0;

    printf("%s[HYPERCALL]%s nr=%lu a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx\n",
           COLOR_BLUE, COLOR_RESET, nr, a0, a1, a2, a3);

    if (ioctl(g_fd, IOCTL_HYPERCALL, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s Hypercall %lu failed: %s\n",
                COLOR_RED, COLOR_RESET, nr, strerror(errno));
        return -1;
    }

    printf("%s[RESULT]%s 0x%016lx (%ld)\n",
           COLOR_GREEN, COLOR_RESET, req.result, (long)req.result);

    if (result) {
        *result = req.result;
    }

    return 0;
}

int hypercall_batch(struct hypercall_batch_request *batch)
{
    if (open_device() < 0) return -1;

    memset(batch, 0, sizeof(*batch));

    printf("%s[HYPERCALL_BATCH]%s Executing HC 100-103...\n", COLOR_BLUE, COLOR_RESET);

    if (ioctl(g_fd, IOCTL_HYPERCALL_BATCH, batch) < 0) {
        fprintf(stderr, "%s[ERROR]%s Hypercall batch failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    printf("%s[RESULTS]%s\n", COLOR_GREEN, COLOR_RESET);
    printf("  HC 100: 0x%016lx (%ld)\n", batch->r100, (long)batch->r100);
    printf("  HC 101: 0x%016lx (%ld)\n", batch->r101, (long)batch->r101);
    printf("  HC 102: 0x%016lx (%ld)\n", batch->r102, (long)batch->r102);
    printf("  HC 103: 0x%016lx (%ld)\n", batch->r103, (long)batch->r103);

    return 0;
}

int hypercall_detect(int *type)
{
    if (open_device() < 0) return -1;

    if (ioctl(g_fd, IOCTL_HYPERCALL_DETECT, type) < 0) {
        fprintf(stderr, "%s[ERROR]%s Hypercall detect failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    printf("%s[HYPERCALL_TYPE]%s ", COLOR_CYAN, COLOR_RESET);
    switch (*type) {
        case 1:
            printf("%sVMCALL (Intel VMX)%s\n", COLOR_GREEN, COLOR_RESET);
            break;
        case 2:
            printf("%sVMMCALL (AMD SVM)%s\n", COLOR_GREEN, COLOR_RESET);
            break;
        default:
            printf("%sUnknown/Not detected%s\n", COLOR_YELLOW, COLOR_RESET);
            break;
    }

    return 0;
}

/* Test CTF-specific hypercalls (100-103) */
int test_ctf_hypercalls(void)
{
    struct hypercall_batch_request batch;
    uint64_t result;
    int type;

    printf("\n%s========================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s  CTF Hypercall Testing Suite%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s========================================%s\n\n", COLOR_CYAN, COLOR_RESET);

    /* Detect hypercall type */
    printf("%s[1] Detecting hypercall instruction type...%s\n", COLOR_YELLOW, COLOR_RESET);
    hypercall_detect(&type);
    printf("\n");

    /* Test individual hypercalls */
    printf("%s[2] Testing individual hypercalls...%s\n", COLOR_YELLOW, COLOR_RESET);

    printf("\n  HC 100 (typically: read flag or status):\n");
    hypercall_verbose(100, 0, 0, 0, 0, &result);

    printf("\n  HC 101 (typically: write/modify):\n");
    hypercall_verbose(101, 0, 0, 0, 0, &result);

    printf("\n  HC 102 (typically: relative read):\n");
    hypercall_verbose(102, 0, 0, 0, 0, &result);

    printf("\n  HC 103 (typically: special command):\n");
    hypercall_verbose(103, 0, 0, 0, 0, &result);

    /* Test with arguments */
    printf("\n%s[3] Testing hypercalls with arguments...%s\n", COLOR_YELLOW, COLOR_RESET);

    printf("\n  HC 100 with offset 0x10:\n");
    hypercall_verbose(100, 0x10, 0, 0, 0, &result);

    printf("\n  HC 102 with offset -8:\n");
    hypercall_verbose(102, (uint64_t)-8, 0, 0, 0, &result);

    /* Batch test */
    printf("\n%s[4] Batch hypercall test...%s\n", COLOR_YELLOW, COLOR_RESET);
    hypercall_batch(&batch);

    /* Check for flag patterns */
    printf("\n%s[5] Analyzing results for flag patterns...%s\n", COLOR_YELLOW, COLOR_RESET);

    uint64_t results[] = {batch.r100, batch.r101, batch.r102, batch.r103};
    const char *names[] = {"r100", "r101", "r102", "r103"};

    for (int i = 0; i < 4; i++) {
        printf("  %s: ", names[i]);

        /* Check for common patterns */
        if (results[i] == 0) {
            printf("Zero (likely unimplemented or no data)\n");
        } else if (results[i] == (uint64_t)-1) {
            printf("Error (-1)\n");
        } else if ((results[i] & 0xFFFFFFFF00000000ULL) == 0) {
            printf("32-bit value: 0x%08lx\n", results[i]);
        } else {
            printf("64-bit value: 0x%016lx\n", results[i]);

            /* Try to interpret as ASCII */
            unsigned char *bytes = (unsigned char *)&results[i];
            int printable = 1;
            for (int j = 0; j < 8 && bytes[j]; j++) {
                if (bytes[j] < 32 || bytes[j] > 126) {
                    printable = 0;
                    break;
                }
            }
            if (printable && bytes[0]) {
                printf("         ASCII: \"%.8s\"\n", bytes);
            }
        }
    }

    printf("\n%s========================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s  CTF Hypercall Testing Complete%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s========================================%s\n\n", COLOR_CYAN, COLOR_RESET);

    return 0;
}

/* Probe hypercall range for valid handlers */
int probe_hypercalls(uint64_t start, uint64_t end)
{
    uint64_t result;
    int found = 0;

    printf("\n%s[PROBE]%s Scanning hypercall range %lu - %lu\n",
           COLOR_CYAN, COLOR_RESET, start, end);

    for (uint64_t nr = start; nr <= end; nr++) {
        result = do_hypercall(nr, 0, 0, 0, 0);

        /* Skip if error or common "not implemented" values */
        if (result == (uint64_t)-1 ||
            result == (uint64_t)-38 ||  /* -ENOSYS */
            result == (uint64_t)-22) {  /* -EINVAL */
            continue;
        }

        /* Found a potentially valid hypercall */
        printf("  %s[FOUND]%s HC %3lu: result = 0x%016lx\n",
               COLOR_GREEN, COLOR_RESET, nr, result);
        found++;
    }

    printf("\n%s[PROBE]%s Found %d potentially valid hypercalls\n",
           COLOR_CYAN, COLOR_RESET, found);

    return found;
}

/* ========================================================================
 * Step 6: AHCI Operations
 * ======================================================================== */

int ahci_init(void)
{
    if (open_device() < 0) return -1;

    if (ioctl(g_fd, IOCTL_AHCI_INIT, NULL) < 0) {
        fprintf(stderr, "%s[ERROR]%s AHCI init failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    printf("%s[AHCI]%s Controller initialized\n", COLOR_GREEN, COLOR_RESET);
    return 0;
}

int ahci_read_reg(uint32_t port, uint32_t offset, uint32_t *value)
{
    struct ahci_reg_request req;

    if (open_device() < 0) return -1;

    req.port = port;
    req.offset = offset;
    req.value = 0;
    req.is_write = 0;

    if (ioctl(g_fd, IOCTL_AHCI_READ_REG, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s AHCI read reg failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    *value = req.value;
    return 0;
}

int ahci_write_reg(uint32_t port, uint32_t offset, uint32_t value)
{
    struct ahci_reg_request req;

    if (open_device() < 0) return -1;

    req.port = port;
    req.offset = offset;
    req.value = value;
    req.is_write = 1;

    if (ioctl(g_fd, IOCTL_AHCI_WRITE_REG, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s AHCI write reg failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    return 0;
}

int ahci_set_fis_base(uint32_t port, uint64_t fis_base, uint64_t clb_base)
{
    struct ahci_fis_request req;

    if (open_device() < 0) return -1;

    req.port = port;
    req.fis_base = fis_base;
    req.clb_base = clb_base;

    if (ioctl(g_fd, IOCTL_AHCI_SET_FIS_BASE, &req) < 0) {
        fprintf(stderr, "%s[ERROR]%s AHCI set FIS base failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    printf("%s[AHCI]%s Port %u: FIS base = 0x%lx, CLB = 0x%lx\n",
           COLOR_GREEN, COLOR_RESET, port, fis_base, clb_base);
    return 0;
}

int ahci_get_info(struct ahci_info *info)
{
    if (open_device() < 0) return -1;

    if (ioctl(g_fd, IOCTL_AHCI_INFO, info) < 0) {
        fprintf(stderr, "%s[ERROR]%s AHCI get info failed: %s\n",
                COLOR_RED, COLOR_RESET, strerror(errno));
        return -1;
    }

    printf("%s[AHCI INFO]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  CAP:  0x%08x\n", info->cap);
    printf("  GHC:  0x%08x\n", info->ghc);
    printf("  PI:   0x%08x\n", info->pi);
    printf("  VS:   0x%08x (AHCI %d.%d)\n", info->vs,
           (info->vs >> 16) & 0xFFFF, info->vs & 0xFFFF);

    printf("  Ports:\n");
    for (int i = 0; i < 6; i++) {
        if (info->pi & (1 << i)) {
            printf("    Port %d: SSTS = 0x%08x %s\n", i, info->port_ssts[i],
                   (info->port_ssts[i] & 0xF) == 3 ? "(device present)" : "");
        }
    }

    return 0;
}

/* ========================================================================
 * Comprehensive Testing Functions
 * ======================================================================== */

int test_symbols(void)
{
    struct symbol_request req;
    unsigned int count;

    printf("\n%s=== Symbol Operations Test ===%s\n\n", COLOR_CYAN, COLOR_RESET);

    /* Get symbol count */
    count = get_symbol_count();
    printf("Found %u KVM symbols in database\n\n", count);

    /* Look up some important symbols */
    const char *test_symbols[] = {
        "kvm_vcpu_read_guest",
        "kvm_vcpu_write_guest",
        "kvm_read_guest_page",
        "kvm_write_guest_page",
        "kvm_mmu_page_fault",
        "vmx_vcpu_run",
        "svm_vcpu_run",
        "handle_ept_violation",
        NULL
    };

    printf("Looking up key symbols:\n");
    for (int i = 0; test_symbols[i]; i++) {
        lookup_symbol_verbose(test_symbols[i], &req);
    }

    return 0;
}

int test_memory_read(void)
{
    struct kaslr_info kaslr;
    unsigned char buffer[64];

    printf("\n%s=== Memory Read Operations Test ===%s\n\n", COLOR_CYAN, COLOR_RESET);

    /* Get KASLR info */
    if (get_kaslr_info(&kaslr) == 0) {
        printf("KASLR Information:\n");
        printf("  Kernel base:  0x%016lx\n", kaslr.kernel_base);
        printf("  KASLR slide:  0x%016lx\n", kaslr.kaslr_slide);
        printf("  Physmap base: 0x%016lx\n", kaslr.physmap_base);
        printf("  vmalloc base: 0x%016lx\n", kaslr.vmalloc_base);
        printf("  vmemmap base: 0x%016lx\n", kaslr.vmemmap_base);
        printf("\n");
    }

    /* Read some kernel memory */
    if (kaslr.kernel_base) {
        printf("Reading kernel text at base:\n");
        if (read_kernel_memory(kaslr.kernel_base, buffer, 64) == 0) {
            hexdump(buffer, 64, kaslr.kernel_base);
        }
        printf("\n");
    }

    /* Read some physical memory */
    printf("Reading physical memory at 0x0:\n");
    if (read_physical_memory(0, buffer, 64) == 0) {
        hexdump(buffer, 64, 0);
    }

    return 0;
}

int test_address_conversion(void)
{
    struct virt_to_phys_request v2p;
    struct kaslr_info kaslr;

    printf("\n%s=== Address Conversion Test ===%s\n\n", COLOR_CYAN, COLOR_RESET);

    if (get_kaslr_info(&kaslr) < 0) {
        return -1;
    }

    /* Test virt to phys conversion */
    printf("Testing virt_to_phys on kernel base:\n");
    if (virt_to_phys(kaslr.kernel_base, &v2p) == 0) {
        printf("  Virtual:  0x%016lx\n", v2p.virt_addr);
        printf("  Physical: 0x%016lx\n", v2p.phys_addr);
        printf("  PFN:      0x%lx\n", v2p.pfn);
        printf("  Offset:   0x%lx\n", v2p.offset);
    }

    return 0;
}

int test_hypercalls(void)
{
    printf("\n%s=== Hypercall Operations Test ===%s\n\n", COLOR_CYAN, COLOR_RESET);
    return test_ctf_hypercalls();
}

int test_ahci(void)
{
    struct ahci_info info;

    printf("\n%s=== AHCI Operations Test ===%s\n\n", COLOR_CYAN, COLOR_RESET);

    if (ahci_init() < 0) {
        printf("AHCI controller not available or initialization failed\n");
        return -1;
    }

    ahci_get_info(&info);

    return 0;
}

int run_all_tests(void)
{
    printf("\n%s╔════════════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║     KVM Prober - Full Test Suite       ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s╚════════════════════════════════════════╝%s\n", COLOR_CYAN, COLOR_RESET);

    test_symbols();
    test_memory_read();
    test_address_conversion();
    test_hypercalls();
    test_ahci();

    printf("\n%s=== All Tests Complete ===%s\n\n", COLOR_GREEN, COLOR_RESET);
    return 0;
}

/* ========================================================================
 * Main Program
 * ======================================================================== */

void print_usage(const char *progname)
{
    printf("Usage: %s [options] <command> [args]\n\n", progname);
    printf("Commands:\n");
    printf("  test                    Run all tests\n");
    printf("  test_symbols            Test symbol operations\n");
    printf("  test_memory             Test memory read operations\n");
    printf("  test_addr               Test address conversion\n");
    printf("  test_hypercalls         Test hypercall operations\n");
    printf("  test_ctf_hypercalls     Run CTF hypercall test suite\n");
    printf("  test_ahci               Test AHCI operations\n");
    printf("\n");
    printf("  lookup <symbol>         Look up a kernel symbol\n");
    printf("  read_kmem <addr> <len>  Read kernel memory\n");
    printf("  read_phys <addr> <len>  Read physical memory\n");
    printf("  read_msr <msr>          Read MSR\n");
    printf("  kaslr                   Show KASLR information\n");
    printf("\n");
    printf("  hypercall <nr> [a0-a3]  Execute single hypercall\n");
    printf("  hypercall_batch         Execute CTF hypercalls 100-103\n");
    printf("  hypercall_detect        Detect hypercall instruction type\n");
    printf("  probe_hc <start> <end>  Probe hypercall range\n");
    printf("\n");
    printf("  ahci_init               Initialize AHCI controller\n");
    printf("  ahci_info               Show AHCI controller info\n");
    printf("  ahci_read <port> <off>  Read AHCI register\n");
    printf("  ahci_write <p> <o> <v>  Write AHCI register\n");
    printf("\n");
    printf("Options:\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                g_verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[optind];

    /* Test commands */
    if (strcmp(cmd, "test") == 0) {
        return run_all_tests();
    }
    if (strcmp(cmd, "test_symbols") == 0) {
        return test_symbols();
    }
    if (strcmp(cmd, "test_memory") == 0) {
        return test_memory_read();
    }
    if (strcmp(cmd, "test_addr") == 0) {
        return test_address_conversion();
    }
    if (strcmp(cmd, "test_hypercalls") == 0 || strcmp(cmd, "test_ctf_hypercalls") == 0) {
        return test_ctf_hypercalls();
    }
    if (strcmp(cmd, "test_ahci") == 0) {
        return test_ahci();
    }

    /* Symbol lookup */
    if (strcmp(cmd, "lookup") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: %s lookup <symbol>\n", argv[0]);
            return 1;
        }
        struct symbol_request req;
        return lookup_symbol_verbose(argv[optind + 1], &req);
    }

    /* Memory read */
    if (strcmp(cmd, "read_kmem") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: %s read_kmem <addr> <len>\n", argv[0]);
            return 1;
        }
        unsigned long addr = strtoull(argv[optind + 1], NULL, 0);
        size_t len = strtoul(argv[optind + 2], NULL, 0);
        unsigned char *buf = malloc(len);
        if (!buf) {
            perror("malloc");
            return 1;
        }
        if (read_kernel_memory(addr, buf, len) == 0) {
            hexdump(buf, len, addr);
        }
        free(buf);
        close_device();
        return 0;
    }

    if (strcmp(cmd, "read_phys") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: %s read_phys <addr> <len>\n", argv[0]);
            return 1;
        }
        unsigned long addr = strtoull(argv[optind + 1], NULL, 0);
        size_t len = strtoul(argv[optind + 2], NULL, 0);
        unsigned char *buf = malloc(len);
        if (!buf) {
            perror("malloc");
            return 1;
        }
        if (read_physical_memory(addr, buf, len) == 0) {
            hexdump(buf, len, addr);
        }
        free(buf);
        close_device();
        return 0;
    }

    if (strcmp(cmd, "read_msr") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: %s read_msr <msr>\n", argv[0]);
            return 1;
        }
        unsigned int msr = strtoul(argv[optind + 1], NULL, 0);
        uint64_t value;
        if (read_msr(msr, &value) == 0) {
            printf("MSR 0x%x = 0x%016lx\n", msr, value);
        }
        close_device();
        return 0;
    }

    if (strcmp(cmd, "kaslr") == 0) {
        struct kaslr_info info;
        if (get_kaslr_info(&info) == 0) {
            printf("KASLR Information:\n");
            printf("  Kernel base:  0x%016lx\n", info.kernel_base);
            printf("  KASLR slide:  0x%016lx\n", info.kaslr_slide);
            printf("  Physmap base: 0x%016lx\n", info.physmap_base);
            printf("  vmalloc base: 0x%016lx\n", info.vmalloc_base);
            printf("  vmemmap base: 0x%016lx\n", info.vmemmap_base);
        }
        close_device();
        return 0;
    }

    /* Hypercall commands */
    if (strcmp(cmd, "hypercall") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: %s hypercall <nr> [a0] [a1] [a2] [a3]\n", argv[0]);
            return 1;
        }
        uint64_t nr = strtoull(argv[optind + 1], NULL, 0);
        uint64_t a0 = (optind + 2 < argc) ? strtoull(argv[optind + 2], NULL, 0) : 0;
        uint64_t a1 = (optind + 3 < argc) ? strtoull(argv[optind + 3], NULL, 0) : 0;
        uint64_t a2 = (optind + 4 < argc) ? strtoull(argv[optind + 4], NULL, 0) : 0;
        uint64_t a3 = (optind + 5 < argc) ? strtoull(argv[optind + 5], NULL, 0) : 0;
        uint64_t result;
        hypercall_verbose(nr, a0, a1, a2, a3, &result);
        close_device();
        return 0;
    }

    if (strcmp(cmd, "hypercall_batch") == 0) {
        struct hypercall_batch_request batch;
        hypercall_batch(&batch);
        close_device();
        return 0;
    }

    if (strcmp(cmd, "hypercall_detect") == 0) {
        int type;
        hypercall_detect(&type);
        close_device();
        return 0;
    }

    if (strcmp(cmd, "probe_hc") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: %s probe_hc <start> <end>\n", argv[0]);
            return 1;
        }
        uint64_t start = strtoull(argv[optind + 1], NULL, 0);
        uint64_t end = strtoull(argv[optind + 2], NULL, 0);
        probe_hypercalls(start, end);
        close_device();
        return 0;
    }

    /* AHCI commands */
    if (strcmp(cmd, "ahci_init") == 0) {
        int ret = ahci_init();
        close_device();
        return ret;
    }

    if (strcmp(cmd, "ahci_info") == 0) {
        struct ahci_info info;
        int ret = ahci_get_info(&info);
        close_device();
        return ret;
    }

    if (strcmp(cmd, "ahci_read") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: %s ahci_read <port> <offset>\n", argv[0]);
            return 1;
        }
        uint32_t port = strtoul(argv[optind + 1], NULL, 0);
        uint32_t offset = strtoul(argv[optind + 2], NULL, 0);
        uint32_t value;
        if (ahci_read_reg(port, offset, &value) == 0) {
            printf("AHCI Port %u Offset 0x%x = 0x%08x\n", port, offset, value);
        }
        close_device();
        return 0;
    }

    if (strcmp(cmd, "ahci_write") == 0) {
        if (optind + 3 >= argc) {
            fprintf(stderr, "Usage: %s ahci_write <port> <offset> <value>\n", argv[0]);
            return 1;
        }
        uint32_t port = strtoul(argv[optind + 1], NULL, 0);
        uint32_t offset = strtoul(argv[optind + 2], NULL, 0);
        uint32_t value = strtoul(argv[optind + 3], NULL, 0);
        int ret = ahci_write_reg(port, offset, value);
        if (ret == 0) {
            printf("AHCI Port %u Offset 0x%x <- 0x%08x\n", port, offset, value);
        }
        close_device();
        return ret;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}