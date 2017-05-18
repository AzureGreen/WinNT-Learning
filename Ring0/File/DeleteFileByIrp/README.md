# DeleteFileByIrp
### Platform in Win7 x86<br/>
## Delete file by allocate an irp<br/>

1. FilePath --> FileHandle --> FileObject --> DeviceObject.

2. Allocate irp & assign it.

3. Call `IoCallDriver` to send the irp.


