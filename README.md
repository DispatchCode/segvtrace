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

To manage the output, you can use the `lines2file` helper,
which writes full lines from stdin to a file named as its argument:
```
sudo ./sigsegv-monitor | ./lines2file sigsegv_output.json
```
You can then send `SIGUSR1` or `SIGHUP` to the `lines2file` process (**not** the `sigsegv-monitor` process!)
to have `lines2file` reopen the output file descriptor.
This ties in nicely with tools like `logrotate`
which can be configured to send `SIGHUP` to the `lines2file` process after rotating the log file.
The core idea: logrotate moves the output file to a different filename, then sends the signal, and lines2file writes to
a new file with the original name.
The lines2file program ensures that this happens in between lines, so lines get never split between files.
It also implements the "signal, then reopen" logic, keeping `sigsegv-monitor` simple.

To collect Last Branch Records (LBR), you either need to run on a bare-metal machine,
or your hypervisor needs to support and have LBR enabled.
If you see output on stderr like
```
[*] Activating LBR hardware on 40 CPUs...
Failed to enable LBR on CPU 0 (Root required?)
Failed to enable LBR on CPU 1 (Root required?)
Failed to enable LBR on CPU 2 (Root required?)
Failed to enable LBR on CPU 3 (Root required?)
Failed to enable LBR on CPU 4 (Root required?)
Failed to enable LBR on CPU 5 (Root required?)
Failed to enable LBR on CPU 6 (Root required?)
Failed to enable LBR on CPU 7 (Root required?)
Failed to enable LBR on CPU 8 (Root required?)
Failed to enable LBR on CPU 9 (Root required?)
...
```
despite running as root, then the problem is most likely lack of LBR support or having LBR disabled in the hypervisor.


## Example

```
marco@linux:~> sudo ./sigsegv_monitor
[*] Activating LBR hardware on 16 CPUs...
Monitoring for SIGSEGV... (Ctrl+C to stop)
```

*Running a user-space application that trigger a SIGSEGV, produces...*

```
{"version":{"rev":"edc826f","date":"2026-04-01T14:51:21Z"},"cpu":13,"tai":1775055881655080750,"process":{"rootns_pid":89095,"ns_pid":89095,"comm":"bash"},"thread":{"rootns_tid":89095,"ns_tid":89095,"comm":"bash"},"signal":"SIGSEGV","si_code":0,"registers":{"rax":"0xffffffffffffffda","rbx":"0x0000000000015c88","rcx":"0x00007f46ee657bc7","rdx":"0x000055f56c49a150","rsi":"0x000000000000000b","rdi":"0x00000000fffea378","rbp":"0x000000000000000b","rsp":"0x00007ffe1f001198","r8":"0x0000000000000008","r9":"0x000055f56c49a150","r10":"0x00007f46ee60c030","r11":"0x0000000000000297","r12":"0x00007ffe1f001230","r13":"0x000055f56c6a4b80","r14":"0x00007ffe1f0013a0","r15":"0x0000000000015c88","rip":"0x00007f46ee657bc7","flags":"0x0000000000000297","trapno":"0x0000000000000000","err":"0x0000000000000000","cr2":"0x0000000000000000"},"page_faults": [{"cr2":"0x000055f56c63a1c8","err":"0x0000000000000007","tai":1775055881654866715},{"cr2":"0x000055f56c62d7f8","err":"0x0000000000000007","tai":1775055881654875562},{"cr2":"0x000055f56c63bf18","err":"0x0000000000000007","tai":1775055881654882780},{"cr2":"0x000055f56c4b13e0","err":"0x0000000000000007","tai":1775055881654891345},{"cr2":"0x000055f56c475c20","err":"0x0000000000000007","tai":1775055881654898809},{"cr2":"0x000055f56c5d0ac8","err":"0x0000000000000007","tai":1775055881654906565},{"cr2":"0x000055f56c4c334c","err":"0x0000000000000007","tai":1775055881654920189},{"cr2":"0x000055f56c584928","err":"0x0000000000000007","tai":1775055881654945169},{"cr2":"0x000055f56c4af6c8","err":"0x0000000000000007","tai":1775055881654955723},{"cr2":"0x000055f56c4e036c","err":"0x0000000000000007","tai":1775055881654964648},{"cr2":"0x000055f56c6471b8","err":"0x0000000000000007","tai":1775055881654972563},{"cr2":"0x000055f56c637c58","err":"0x0000000000000007","tai":1775055881654987569},{"cr2":"0x00007f46ee807db0","err":"0x0000000000000007","tai":1775055881654997254},{"cr2":"0x000055f56c49fb00","err":"0x0000000000000007","tai":1775055881655005364},{"cr2":"0x000055f56c48075c","err":"0x0000000000000007","tai":1775055881655017393},{"cr2":"0x00007f46eeaa1a98","err":"0x0000000000000007","tai":1775055881655059806}],"lbr":[]}
```
