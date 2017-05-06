# ReloadNtkrnl
### Platform in Win7 x86<br/>
## Reload kernel module in system space<br/>

1. Get information of first kernel module.

2. Read file in system memory

3. Allocate NonPagedPool and fix IAT, BaseReloc, SSDT

4. (We can hook kifastcall to make syscall jmp to our "Kernel space")

 <h3>BeforeReloc</h3>
 <img src="https://github.com/AzureGreen/WinNT-Learning/blob/master/Ring0/KernelHook/ReloadNtkrnl/BeforeReloc.jpg" width = "663" height = "466" alt="BeforeReloc" align=center />
 <h3>AfterReloc</h3>
 <img src="https://github.com/AzureGreen/WinNT-Learning/blob/master/Ring0/KernelHook/ReloadNtkrnl/AfterReloc.jpg" width = "663" height = "466" alt="AfterReloc" align=center />




