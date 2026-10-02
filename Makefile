# lldpnd - LLDP (IEEE 802.1AB) neighbour discovery daemon
#
#   make               build lldpnd, lldpnd-ctl and the tests      (build/)
#   make test          run unit tests
#   make asan          build + run unit tests under ASan/UBSan      (build/asan/)
#   make valgrind      run unit tests under valgrind memcheck
#   make fuzz          run the parser fuzz driver (ASan/UBSan)
#   make libfuzzer     run the clang libFuzzer target (needs clang)
#   make rawsock-test  raw socket integration test   (root; private netns)
#   make testbed       3-namespace bridge testbed     (root)
#   make interop       interoperability test vs lldpd (root; needs lldpd)
#   make check         test + valgrind + asan + fuzz (no root needed)
#   make install       install binaries, man pages, systemd unit
#                      (PREFIX=/usr/local, DESTDIR=)

ifeq ($(origin CC),default)
CC      = gcc
endif
BUILD   ?= build
EXTRA_CFLAGS  ?=
EXTRA_LDFLAGS ?=

WARN    = -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes \
          -Wmissing-prototypes -Wvla -Wformat=2 -Wpointer-arith
CFLAGS  = -std=c11 -D_GNU_SOURCE -O2 -g $(WARN) $(EXTRA_CFLAGS)
LDFLAGS = $(EXTRA_LDFLAGS)

SAN_FLAGS = -fsanitize=address,undefined -fno-sanitize-recover=all \
            -fno-omit-frame-pointer -O1

# everything except the two main() files
LIB     = tlv frame lldpdu neigh txsched rawsock netmon localinfo \
          agent ctl report privdrop
LIB_O   = $(LIB:%=$(BUILD)/%.o)

UNIT    = test_tlv test_frame test_lldpdu test_neigh test_txsched \
          test_report test_netmon
UNIT_BIN = $(UNIT:%=$(BUILD)/%)

PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man
UNITDIR ?= /lib/systemd/system

.SECONDARY:

.PHONY: all test asan valgrind fuzz libfuzzer rawsock-test testbed interop \
        check install uninstall clean

all: $(BUILD)/lldpnd $(BUILD)/lldpnd-ctl $(UNIT_BIN) $(BUILD)/test_rawsock \
     $(BUILD)/fuzz_lldpdu

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/t_%.o: tests/%.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/lldpnd: $(LIB_O) $(BUILD)/main.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/lldpnd-ctl: $(BUILD)/lldpnd_ctl.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/test_%: $(BUILD)/t_test_%.o $(LIB_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/fuzz_lldpdu: $(BUILD)/t_fuzz_lldpdu.o $(LIB_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: $(UNIT_BIN)
	@set -e; for t in $(UNIT_BIN); do ./$$t; done

asan:
	$(MAKE) BUILD=build/asan EXTRA_CFLAGS="$(SAN_FLAGS)" \
	        EXTRA_LDFLAGS="-fsanitize=address,undefined" all test

valgrind: $(UNIT_BIN)
	@set -e; for t in $(UNIT_BIN); do \
	    valgrind -q --leak-check=full --show-leak-kinds=all \
	        --errors-for-leak-kinds=all --error-exitcode=99 ./$$t; done

FUZZ_ITERS ?= 2000000
fuzz:
	$(MAKE) BUILD=build/asan EXTRA_CFLAGS="$(SAN_FLAGS)" \
	        EXTRA_LDFLAGS="-fsanitize=address,undefined" build/asan/fuzz_lldpdu
	./build/asan/fuzz_lldpdu $(FUZZ_ITERS)

FUZZ_SECS ?= 60
libfuzzer: | $(BUILD)
	mkdir -p $(BUILD)/libfuzzer-corpus
	clang -std=c11 -D_GNU_SOURCE -g -O1 -DLIBFUZZER $(WARN) \
	    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
	    tests/fuzz_lldpdu.c $(LIB:%=src/%.c) -o $(BUILD)/libfuzz_lldpdu
	./$(BUILD)/libfuzz_lldpdu -max_total_time=$(FUZZ_SECS) -print_final_stats=1 \
	    $(BUILD)/libfuzzer-corpus

rawsock-test: $(BUILD)/test_rawsock
	unshare --net sh -c '\
	    ip link set lo up && \
	    ip link add rsA type veth peer name rsB && \
	    ip link set rsA address 02:00:00:00:aa:01 && \
	    ip link set rsB address 02:00:00:00:bb:01 && \
	    ip link set rsA up && ip link set rsB up && \
	    ./$(BUILD)/test_rawsock rsA rsB'

testbed: $(BUILD)/lldpnd $(BUILD)/lldpnd-ctl
	BIN=$(abspath $(BUILD)/lldpnd) CTL=$(abspath $(BUILD)/lldpnd-ctl) \
	    bash scripts/testbed.sh

interop: $(BUILD)/lldpnd $(BUILD)/lldpnd-ctl
	BIN=$(abspath $(BUILD)/lldpnd) CTL=$(abspath $(BUILD)/lldpnd-ctl) \
	    bash scripts/interop_lldpd.sh

check: all test valgrind asan fuzz

install: $(BUILD)/lldpnd $(BUILD)/lldpnd-ctl
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	install -m 0755 $(BUILD)/lldpnd $(DESTDIR)$(SBINDIR)/lldpnd
	install -m 0755 $(BUILD)/lldpnd-ctl $(DESTDIR)$(BINDIR)/lldpnd-ctl
	install -m 0644 man/lldpnd.8 man/lldpnd-ctl.8 $(DESTDIR)$(MANDIR)/man8/
	install -d $(DESTDIR)$(UNITDIR)
	sed 's|@SBINDIR@|$(SBINDIR)|g' contrib/lldpnd.service \
	    > $(DESTDIR)$(UNITDIR)/lldpnd.service
	chmod 0644 $(DESTDIR)$(UNITDIR)/lldpnd.service

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/lldpnd $(DESTDIR)$(BINDIR)/lldpnd-ctl \
	      $(DESTDIR)$(MANDIR)/man8/lldpnd.8 $(DESTDIR)$(MANDIR)/man8/lldpnd-ctl.8 \
	      $(DESTDIR)$(UNITDIR)/lldpnd.service

clean:
	rm -rf build

-include $(wildcard $(BUILD)/*.d)
