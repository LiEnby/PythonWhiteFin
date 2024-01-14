#include "pcap.h"
#include <vitasdkkern.h>

static char* pcapFile = "ux0:/data/gc.pcap";

void write_pcap_hdr() {
	SceUID pcapfd = ksceIoOpen(pcapFile, SCE_O_WRONLY | SCE_O_CREAT , 0777);
	
	pcap_hdr_t pcapHdr;
	pcapHdr.magic_number = 0xa1b2c3d4;
	pcapHdr.version_major = 0x2;
	pcapHdr.version_minor = 0x4;
	pcapHdr.thiszone = 0;
	pcapHdr.sigfigs = 0;
	pcapHdr.snaplen = 65535;
	pcapHdr.network = 147;
	
	ksceIoWrite(pcapfd, &pcapHdr, sizeof(pcap_hdr_t));
	
	ksceIoClose(pcapfd);
	return;
}

void write_pcap_packet(char* packetData, size_t packetLength, int direction) {
	if(packetData == NULL) return;

	SceRtcTick time;
	ksceRtcGetCurrentSecureTick(&time);
	
	SceUID pcapfd = ksceIoOpen(pcapFile, SCE_O_WRONLY | SCE_O_APPEND , 0777);
	
	pcaprec_hdr_t packetHdr;
	packetHdr.incl_len = packetLength + sizeof(int);
	packetHdr.orig_len = packetLength + sizeof(int);
	packetHdr.ts_sec = (uint32_t)((time.tick / 1000000) - 62135596800);
	packetHdr.ts_usec = (uint32_t)(time.tick % 1000000);

	
	ksceIoWrite(pcapfd, &packetHdr, sizeof(pcaprec_hdr_t));
	ksceIoWrite(pcapfd, &direction, sizeof(int));
	ksceIoWrite(pcapfd, packetData, packetLength);
	
	ksceIoClose(pcapfd);
	
	return;
}