CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
ARCH := x86
TARGET := xdp_monitor

BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -O2 -g -Wall
LDLIBS := -lelf -lz -lbpf

all: $(TARGET)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdp_monitor.bpf.o: xdp_monitor.bpf.c xdp_monitor_common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

xdp_monitor.skel.h: xdp_monitor.bpf.o
	$(BPFTOOL) gen skeleton xdp_monitor.bpf.o > xdp_monitor.skel.h

$(TARGET): xdp_monitor.c xdp_monitor.skel.h xdp_monitor_common.h
	$(CC) $(USER_CFLAGS) $< $(LDLIBS) -o $(TARGET)

clean:
	rm -f $(TARGET) xdp_monitor.bpf.o xdp_monitor.skel.h
	rm -f vmlinux.h