# SIGSEGV Monitor

Trace `tracepoint/signal/signal_generate` waiting SIGSEGV and print LBR (Last Branch Record) and registers.

## Build

Dependencies:
```
zypper install \
	bpftool \
	libbpf-devel \
	make \
	clang17
```

`bpftool` is in `sbin`; therefore `make` must be run as root, or you need to add `sbin` to `PATH`.
The `pathmake` is a `make` wrapper which deals with `sbin`.


## Run

To load the eBPF program, you need some capabilities, hence:

`sudo ./sigsegv-monitor`

## Example

```
marco@linux:~> sudo ./sigsegv_monitor 
[*] Activating LBR hardware on 16 CPUs...
Monitoring for SIGSEGV... (Ctrl+C to stop)
```

*Running a user-space application that trigger a SIGSEGV, produces...*

```
------------ SIGSEGV Detected ----------------
PID: 325439 | COMM: x64id

--- Registers ---
RAX: 0x000000000040419d  RBX: 0x0000000000000000
RCX: 0x00007ff933df702c  RDX: 0x0000000000000000
RSI: 0x00007ffd93458354  RDI: 0x00007ff933df76a0
RBP: 0x00007ffd934583a0  RSP: 0x00007ffd93458380
R8 : 0x00007ff933df7038  R9 : 0x00007ff933df70a0
R10: 0x0000000000000000  R11: 0x0000000000000202
R12: 0x0000000000000001  R13: 0x00007ff933e6d000
R14: 0x00007ffd93458578  R15: 0x0000000000407df0

RIP: 0x0000000000404223  FLG: 0x0000000000010202
CR2: 0x000000000040419d

--- LBR Branch History (Last 16 Jumps) ---
#0 : 0x7ff933c48301  ->  0x404218
#1 : 0x7ff933c485b9  ->  0x7ff933c482fd
#2 : 0x7ff933c485d6  ->  0x7ff933c485a5
#3 : 0x7ff933c4878c  ->  0x7ff933c485d1
#4 : 0x7ff933c48737  ->  0x7ff933c48758
#5 : 0x7ff933c485cc  ->  0x7ff933c4871e
#6 : 0x7ff933c4856f  ->  0x7ff933c485c0
#7 : 0x7ff933c482f8  ->  0x7ff933c4854e
#8 : 0x401130  ->  0x7ff933c482ee
#9 : 0x404213  ->  0x401130
#10: 0x7ff933c5ef26  ->  0x404213
#11: 0x7ff933c6a9a8  ->  0x7ff933c5ef0f
#12: 0x7ff933c6ab09  ->  0x7ff933c6a980
#13: 0x7ff933c5f3ee  ->  0x7ff933c6ab09
#14: 0x7ff933c5f962  ->  0x7ff933c5f3be
#15: 0x7ff933c5f77e  ->  0x7ff933c5f959
--------------------------------------------

```
