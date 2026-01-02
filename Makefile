# KVM Probe Driver and Tools Makefile
# 
# USAGE:
# 1. Build: make
# 2. Load: sudo insmod kvm_probe_drv.ko
# 3. Use: ./kvm_prober help
# 4. Exploit: ./ahci_exploit --help
#
# The driver runs hypercalls 100-103 after every read/write/scan
# and reports interesting results to dmesg.

obj-m := kvm_probe_drv.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: driver tools

driver:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools: kvm_prober ahci_exploit

kvm_prober: kvm_prober.c
	gcc -o kvm_prober kvm_prober.c -Wall -O2

ahci_exploit: ahci_exploit.c
	gcc -o ahci_exploit ahci_exploit.c -Wall -O2

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f kvm_prober ahci_exploit

load: driver
	sudo rmmod kvm_probe_drv 2>/dev/null || true
	sudo insmod kvm_probe_drv.ko
	@echo "Module loaded. Device: /dev/kvm_probe_dev"

unload:
	sudo rmmod kvm_probe_drv

# Run AHCI exploit with hypercall-only mode first
test-ahci: load tools
	@echo "=== Full exploit run ==="
	cp ./ahci_exploit /bin
	ahci_exploit --probe
	@echo ""
	@echo "=== Check dmesg for CTF results ==="
	sudo dmesg | tail -30 || echo "(no CTF results)"

# Watch dmesg for CTF results in real-time
watch-ctf:
	sudo dmesg -w | grep --line-buffered -E "CTF|Hypercall"

.PHONY: all driver tools clean load unload test-ahci watch-ctf
