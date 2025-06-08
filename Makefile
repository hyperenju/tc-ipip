BPF_TARGETS = ipip
BPF_OBJS = $(BPF_TARGETS:=.o)

CC = gcc
CLANG = clang
CFLAGS = -g -Wall -O2
BPF_CFLAGS = -g -target bpf -Wall -O2
LDLIBS = -lbpf

# Configuration file (can be overridden with CONFIG=file.yml)
CONFIG ?= ipip.yml

# Load configuration from YAML file if it exists
ifneq ($(wildcard $(CONFIG)),)
  TRANSPORT_NIC := $(shell yq '.tunnel.transport_nic' $(CONFIG) 2>/dev/null || echo "ens7")
  DEST_CIDR := $(shell yq '.tunnel.dest_cidr' $(CONFIG) 2>/dev/null || echo "192.168.1.0/24")
  TRANSPORT_LOCAL_ADDR := $(shell yq '.tunnel.local_addr' $(CONFIG) 2>/dev/null || echo "10.0.0.1")
  TRANSPORT_REMOTE_ADDR := $(shell yq '.tunnel.remote_addr' $(CONFIG) 2>/dev/null || echo "10.0.0.2")
else
  # Fallback defaults if no config file
  TRANSPORT_NIC ?= ens7
  DEST_CIDR ?= 192.168.1.0/24
  TRANSPORT_LOCAL_ADDR ?= 10.0.0.1
  TRANSPORT_REMOTE_ADDR ?= 10.0.0.2
endif

# CIDRからネットワークアドレスとプレフィックス長を分離
NETWORK_ADDR := $(word 1,$(subst /, ,$(DEST_CIDR)))
PREFIX_LEN := $(word 2,$(subst /, ,$(DEST_CIDR)))

# IPアドレスを16進数に変換する関数
define ip_to_hex
$(shell echo "$(1)" | awk -F'.' '{printf "0x%02x%02x%02x%02x\n", $$1, $$2, $$3, $$4}')
endef

# プレフィックス長からサブネットマスクを計算する関数
define prefix_to_mask
$(shell python3 -c "import sys; mask = (0xffffffff << (32 - $(1))) & 0xffffffff; print('0x%08x' % mask)")
endef

TUNNEL_NIC = ipip0

# 計算結果
DEST_SUBNET_ADDR := $(call ip_to_hex,$(NETWORK_ADDR))
DEST_SUBNET_MASK := $(call prefix_to_mask,$(PREFIX_LEN))

TRANSPORT_NIC_INDEX = $(shell cat /sys/class/net/$(TRANSPORT_NIC)/ifindex)

TRANSPORT_LOCAL_ADDR_HEX := $(call ip_to_hex,$(TRANSPORT_LOCAL_ADDR))
TRANSPORT_REMOTE_ADDR_HEX := $(call ip_to_hex,$(TRANSPORT_REMOTE_ADDR))


.PHONY: all clean trace config

all: compile-bpf setup-tunnel load-bpf

compile-bpf: $(BPF_OBJS)

setup-tunnel:
	- ping -c 1 $(TRANSPORT_REMOTE_ADDR)
	sysctl -w net.ipv4.ip_forward=1
	ip link add $(TUNNEL_NIC) type dummy
	ip link set $(TUNNEL_NIC) up
	ip route add $(DEST_CIDR) dev $(TUNNEL_NIC)
	tc qdisc add dev $(TUNNEL_NIC) clsact
	tc qdisc add dev $(TRANSPORT_NIC) clsact

load-bpf:
	$(eval TUNNEL_NIC_INDEX := $(shell cat /sys/class/net/$(TUNNEL_NIC)/ifindex))
	$(CLANG) $(BPF_CFLAGS) -o ipip.o -c ipip.c \
		-DDEST_SUBNET_ADDR=$(DEST_SUBNET_ADDR) \
		-DDEST_SUBNET_MASK=$(DEST_SUBNET_MASK) \
		-DTRANSPORT_LOCAL_ADDR=$(TRANSPORT_LOCAL_ADDR_HEX) \
		-DTRANSPORT_REMOTE_ADDR=$(TRANSPORT_REMOTE_ADDR_HEX) \
		-DTRANSPORT_NIC_INDEX=$(TRANSPORT_NIC_INDEX) \
		-DTUNNEL_NIC_INDEX=$(TUNNEL_NIC_INDEX)
	tc filter add dev $(TUNNEL_NIC) egress bpf direct-action obj $(BPF_TARGETS).o sec tc/encap
	tc filter add dev $(TRANSPORT_NIC) ingress bpf direct-action obj $(BPF_TARGETS).o sec tc/decap

%.o: %.c $(HEADERS)
	$(CLANG) $(BPF_CFLAGS) -o $@ -c $< \
		-DDEST_SUBNET_ADDR=$(DEST_SUBNET_ADDR) \
		-DDEST_SUBNET_MASK=$(DEST_SUBNET_MASK) \
		-DTRANSPORT_LOCAL_ADDR=$(TRANSPORT_LOCAL_ADDR_HEX) \
		-DTRANSPORT_REMOTE_ADDR=$(TRANSPORT_REMOTE_ADDR_HEX) \
		-DTRANSPORT_NIC_INDEX=$(TRANSPORT_NIC_INDEX)

clean:
	- tc qdisc del dev $(TUNNEL_NIC) clsact
	- tc qdisc del dev $(TRANSPORT_NIC) clsact
	- ip link del $(TUNNEL_NIC)
	- rm -f $(BPF_OBJS)

config:
	@echo "Current configuration (from $(CONFIG)):"
	@echo "  Transport NIC: $(TRANSPORT_NIC)"
	@echo "  Destination CIDR: $(DEST_CIDR)"
	@echo "  Local Address: $(TRANSPORT_LOCAL_ADDR)"
	@echo "  Remote Address: $(TRANSPORT_REMOTE_ADDR)"


trace:
	cat /sys/kernel/tracing/trace_pipe | perl -pe 's/^.+?bpf_trace_printk: //'
