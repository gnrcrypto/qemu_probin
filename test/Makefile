# KVM Probe Framework Makefile
# Builds kernel module and userspace tools

# Kernel module settings
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
MODULE_NAME = kvm_probe_drv
obj-m := $(MODULE_NAME).o

# Userspace tool settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = 
PROBER = kvm_prober
EXPLOIT = kvm_exploit

# Default target
all: module prober exploit

# Build kernel module
module:
	@echo "Building kernel module..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

# Build userspace tool
prober: kvm_prober.c
	@echo "Building userspace prober..."
	$(CC) $(CFLAGS) -o $(PROBER) kvm_prober.c $(LDFLAGS)

# Build exploit framework
exploit: kvm_exploit.c
	@echo "Building exploit framework..."
	$(CC) $(CFLAGS) -o $(EXPLOIT) kvm_exploit.c $(LDFLAGS)

# Install module
install: module
	@echo "Installing kernel module..."
	sudo insmod $(MODULE_NAME).ko

# Uninstall module
uninstall:
	@echo "Removing kernel module..."
	-sudo rmmod $(MODULE_NAME) 2>/dev/null || true

# Reload module (uninstall then install)
reload: uninstall install

# Run tests
test: prober install
	@echo "Running tests..."
	sudo ./$(PROBER) test

# Run CTF hypercall tests
test_hypercalls: prober install
	@echo "Running hypercall tests..."
	sudo ./$(PROBER) test_ctf_hypercalls

# Run exploit framework interactive shell
run_exploit: exploit install
	@echo "Running exploit framework..."
	sudo ./$(EXPLOIT) shell

# Run full exploitation chain
hunt: exploit install
	@echo "Running full exploitation chain..."
	sudo ./$(EXPLOIT) exploit

# Hunt for flags in physical memory
hunt_phys: exploit install
	@echo "Hunting for flags in physical memory..."
	sudo ./$(EXPLOIT) hunt_phys 0 0x10000000

# Hunt for flags in kernel memory
hunt_kern: exploit install
	@echo "Hunting for flags in kernel memory..."
	sudo ./$(EXPLOIT) hunt_kern

# Extract flags via hypercalls
hc_flags: exploit install
	@echo "Extracting flags via hypercalls..."
	sudo ./$(EXPLOIT) hypercalls

# Show system info
sysinfo: exploit install
	@echo "Gathering system information..."
	sudo ./$(EXPLOIT) sysinfo

# List processes
procs: exploit install
	sudo ./$(EXPLOIT) procs

# Show dmesg logs
log:
	@dmesg | tail -50

# Watch dmesg logs
watch:
	@dmesg -w

# Clean build artifacts
clean:
	-$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean 2>/dev/null || true
	rm -f $(PROBER) $(EXPLOIT)
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

# Help
help:
	@echo "KVM Probe Framework Build System"
	@echo ""
	@echo "Build Targets:"
	@echo "  all            - Build kernel module and all userspace tools"
	@echo "  module         - Build kernel module only"
	@echo "  prober         - Build basic prober tool"
	@echo "  exploit        - Build exploit framework"
	@echo ""
	@echo "Module Management:"
	@echo "  install        - Install (insmod) kernel module"
	@echo "  uninstall      - Remove (rmmod) kernel module"
	@echo "  reload         - Reload kernel module"
	@echo ""
	@echo "Testing & Exploitation:"
	@echo "  test           - Run all tests with prober"
	@echo "  test_hypercalls- Run CTF hypercall tests"
	@echo "  run_exploit    - Launch exploit framework shell"
	@echo "  hunt           - Run full exploitation chain"
	@echo "  hunt_phys      - Hunt for flags in physical memory"
	@echo "  hunt_kern      - Hunt for flags in kernel memory"
	@echo "  hc_flags       - Extract flags via hypercalls"
	@echo ""
	@echo "Information:"
	@echo "  sysinfo        - Show system information (KASLR, etc.)"
	@echo "  procs          - List running processes"
	@echo "  log            - Show recent dmesg output"
	@echo "  watch          - Watch dmesg in real-time"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Quick start:"
	@echo "  make && sudo make install && sudo ./kvm_exploit shell"
	@echo ""
	@echo "CTF Quick hunt:"
	@echo "  make hunt"

.PHONY: all module prober exploit install uninstall reload test test_hypercalls \
        run_exploit hunt hunt_phys hunt_kern hc_flags sysinfo procs log watch clean help