# HookKiFastCallEntry
### Platform in Win7 x86/x64<br/>
## Hook KiFastCallEntry which is the entry of syscall<br/>
### The main task is to get the address of KiFastCallEntry

1 To hook one of the commonly used SSDT function, the stackback(ebp+4) to reach the space of KiFastCallEntry

2 Use MSR(Model Specific Registers) to get CS and EIP, then we can get KiFastCallEntry address.(see [this one](https://github.com/AzureGreen/WinNT-Learning/tree/master/Ring0/KernelHook/ReloadNtkrnl) to get realization of this method)





