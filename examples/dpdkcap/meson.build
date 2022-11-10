# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

allow_experimental_apis = true
deps += ['hash', 'lpm', 'fib', 'eventdev']
sources = files(
         'dpdkcap.c', 'core_write.c', 'core_capture.c', 'statistics_ncurses.c', 'pcap.c', 'utils.c', 'lzo/minilzo/minilzo.c', 'lzo/lzowrite.c'
)
