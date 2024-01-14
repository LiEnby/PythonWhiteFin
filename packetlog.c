#include <stdio.h>
#include <stdarg.h>
#include <vitasdkkern.h>
#include <taihen.h>

static int kernelGetSysTime = -1;
static tai_hook_ref_t kernelGetSysTimeRef;

uint64_t sceKernelGetSystemTimeWide_Patched(){
  return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{

	// undo cobra blackfin patch
	kernelGetSysTime = taiHookFunctionImportForKernel(KERNEL_PID,
		&kernelGetSysTimeRef, 
		"SceSblGcAuthMgr",
		0xE2C40624, // SceThreadmgrForDriver
		0xF4EE4FA9, // sceKernelGetSystemTimeWide
		sceKernelGetSystemTimeWide_Patched);
	ksceKernelPrintf("[started] %x %x\n", kernelGetSysTime, kernelGetSysTimeRef);

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	if (kernelGetSysTime >= 0)  taiHookReleaseForKernel(kernelGetSysTime, kernelGetSysTimeRef);
		
	return SCE_KERNEL_STOP_SUCCESS;
}
