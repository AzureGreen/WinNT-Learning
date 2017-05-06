# EnumSsdtHook
### Platform in Win7 x86/x64<br/>
## Enum Ssdt Hook in Current OS<br/>

1. Get current ssdt address.

2. Initialize ssdt function name array from ntdll's exporttable.

3. Reload Ntoskrnl & ssdt in new memory to get original ssdt function address.

4. Now, we can enum ssdt hook just by compare offset in Win7 x64 or function address in Win7 x86!

 <h3>Win7 x64</h3>
 <img src="https://github.com/AzureGreen/WinNT-Learning/blob/master/Ring0/KernelHook/EnumSsdtHook/Win7x64.jpg" width = "800" height = "533" alt="Win7 x64" align=center />
 <h3>Win7 x86</h3>
 <img src="https://github.com/AzureGreen/WinNT-Learning/blob/master/Ring0/KernelHook/EnumSsdtHook/Win7x86.jpg" width = "800" height = "533" alt="Win7 x86" align=center />
