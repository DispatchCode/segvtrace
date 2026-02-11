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

This will produce output on stdout,
so you might want to redirect that to a file.
It will print warnings and errors on stderr.

The output is a bunch of JSON objects, without enclosing `[]` array brackets.


## Example

```
marco@linux:~> sudo ./sigsegv_monitor 
[*] Activating LBR hardware on 16 CPUs...
Monitoring for SIGSEGV... (Ctrl+C to stop)
```

*Running a user-space application that trigger a SIGSEGV, produces...*

```
{"cpu":33,"process":{"pid":6897,"comm":"bash"},"thread":{"tid":6897,"comm":"bash"},"si_code":0,"registers":{"rax":"0xffffffffffffffda","rbx":"0x0000000000001b1e","rcx":"0x00007f08fd257b47","rdx":"0x000055f0fff18a50","rsi":"0x000000000000000b","rdi":"0x00000000ffffe4e2","rbp":"0x000000000000000b","rsp":"0x00007fff61a6ab78","r8":"0x0000000000000008","r9":"0x000055f0fff18a50","r10":"0x00007f08fd20bfb0","r11":"0x0000000000000297","r12":"0x00007fff61a6ac10","r13":"0x000055f100007630","r14":"0x00007fff61a6ad80","r15":"0x0000000000001b1e","rip":"0x00007f08fd257b47","flags":"0x0000000000000297","trapno":"0x0000000000000000","err":"0x0000000000000000","cr2":"0x0000000000000000","cr2_fault":null},"lbr":[]}
{"cpu":35,"process":{"pid":6942,"comm":"bash"},"thread":{"tid":6942,"comm":"bash"},"si_code":0,"registers":{"rax":"0xffffffffffffffda","rbx":"0x000055f0fff39540","rcx":"0x00007f08fd257b47","rdx":"0x0000000000000000","rsi":"0x000000000000000b","rdi":"0x0000000000001b1e","rbp":"0x0000000000000020","rsp":"0x00007fff61a6ae48","r8":"0x00007fff61a6ad80","r9":"0x0000000000000007","r10":"0x00007f08fd217380","r11":"0x0000000000000206","r12":"0x000055f0fff3e3b0","r13":"0x0000000000000000","r14":"0x0000000000000000","r15":"0x0000000000000001","rip":"0x00007f08fd257b47","flags":"0x0000000000000206","trapno":"0x0000000000000000","err":"0x0000000000000000","cr2":"0x0000000000000000","cr2_fault":null},"lbr":[]}

```
