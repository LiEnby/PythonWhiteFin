#include <stdio.h>
#include <stdarg.h>
#include <vitasdkkern.h>
#include <taihen.h>

#include "pcap.h"

static int sendHook = -1;
static tai_hook_ref_t sendHookRef;

static int recvHook = -1;
static tai_hook_ref_t recvHookRef;

static int kernelGetSysTime = -1;
static tai_hook_ref_t kernelGetSysTimeRef;

uint64_t sceKernelGetSystemTimeWide_Patched(){
  return 0;
}

int SceSdifSendGcPacket_Patched(void* instance, char* buffer, int bufferSz) {
	write_pcap_packet(buffer, bufferSz, 1);
	int ret = TAI_CONTINUE(int, sendHookRef, instance, buffer, bufferSz);
	return ret;
}	

int SceSdifReceiveGcPacket_Patched(void* instance, char* buffer, int bufferSz) {
	int ret = TAI_CONTINUE(int, recvHookRef, instance, buffer, bufferSz);
	write_pcap_packet(buffer, bufferSz, 0);
	return ret;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{

	write_pcap_hdr();
	
	sendHook = taiHookFunctionImportForKernel(KERNEL_PID,
		&sendHookRef, 
		"SceSblGcAuthMgr",
		0x96D306FA, // SceSdifForDriver
		0xB0996641, // SceSdifSendGcPacket
		SceSdifSendGcPacket_Patched);
	ksceKernelPrintf("[started] %x %x\n", sendHook, sendHookRef);
		
	recvHook = taiHookFunctionImportForKernel(KERNEL_PID,
		&recvHookRef, 
		"SceSblGcAuthMgr",
		0x96D306FA, // SceSdifForDriver
		0x134E06C4, // SceSdifReceiveGcPacket
		SceSdifReceiveGcPacket_Patched);
	ksceKernelPrintf("[started] %x %x\n", recvHook, recvHookRef);

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
	if (recvHook >= 0)			taiHookReleaseForKernel(recvHook, recvHookRef);
	if (sendHook >= 0)			taiHookReleaseForKernel(sendHook, sendHookRef);
	if (kernelGetSysTime >= 0)  taiHookReleaseForKernel(kernelGetSysTime, kernelGetSysTimeRef);
		
	return SCE_KERNEL_STOP_SUCCESS;
}
