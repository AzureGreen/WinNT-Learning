# ReloadNtkrnl
## Reload kernel module in system space<br/>

1. Get information of first kernel module.

2. Read file in system memory

3. Allocate NonPagedPool and fix IAT, BaseReloc, SSDT

4. (We can hook kifastcall to make syscall jmp to our "Kernel space")





