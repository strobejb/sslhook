//
//  pcap.cpp
//
//	Simple routines for writing socket data into PCAP format
//
//  www.catch22.net
//
//  Copyright (C) 2012 James Brown
//  Please refer to the file LICENCE.TXT for copying permission
//

#include <WinSock2.h>
#include <stdio.h>
#include <time.h>

#include "pcap.h"

#pragma pack(push, 1)

typedef unsigned int		uint32;
typedef unsigned short		uint16;
typedef unsigned char		uint8;
typedef int					int32;

#define PCAP_MAGIC			0xa1b2c3d4
#define PCAP_VER_MAJOR		2
#define PCAP_VER_MINOR		4

#define LINKTYPE_NULL		0
#define LINKTYPE_ETHERNET	1
#define LINKTYPE_IPV4		228
#define LINKTYPE_IPV6		229

#define IP_PROTO_TCP		6

#define PCAP_SENDING		1
#define PCAP_RECEIVING		2

// PCAP file header
typedef struct pcap_hdr_s {
        uint32 magic_number;   // magic number
        uint16 version_major;  // major version number
        uint16 version_minor;  // minor version number
        int32  thiszone;       // GMT to local correction
        uint32 sigfigs;        // accuracy of timestamps
        uint32 snaplen;        // max length of captured packets, in octets
        uint32 network;        // data link type
} pcap_hdr_t;

// PCAP packet header
typedef struct pcaprec_hdr_s {
        uint32 ts_sec;         // timestamp seconds
        uint32 ts_usec;        // timestamp microseconds
        uint32 incl_len;       // number of octets of packet saved in file
        uint32 orig_len;       // actual length of packet
} pcaprec_hdr_t;

// IP header
typedef struct ip_hdr_s {
	uint8  verlen;		// 4bits version, 4bits header len
	uint8  service;		// 0
	uint16 len;			// 
	uint16 id;			
	uint8  flags;
	uint8  fragoff;
	uint8  ttl;
	uint8  protocol;
	uint16 checksum;
	uint32 source;
	uint32 dest;
} ip_hdr;

// TCP header
typedef struct tcp_hdr_s 
{
	uint16 srcport;
	uint16 dstport;
	uint32 seq;
	uint32 ack;
	uint8  len;
	uint8  flags;
	uint16 winsize;
	uint16 checksum;
	uint16 padding;
} tcp_hdr;

#pragma pack(pop)

//
//	Initialize the PCAP file using an existing FILE* 
//	The returned PCAP object must be used in future
//	calls to write_pcap
//
PCAP * pcap_init(FILE *fp)
{
	PCAP *p;

	if((p = (PCAP*)malloc(sizeof(PCAP))) == 0)
		return 0;

	p->fp  = fp;
	p->ack = 1;
	p->seq = 1;

	// pcap file header
	pcap_hdr_t hdr =
	{
		PCAP_MAGIC,			// magic
		PCAP_VER_MAJOR,		// version major
		PCAP_VER_MINOR,		// version minor
		0,					// GMT timezone offset
		0,					// timestamp accuracy
		0xFFFF,				// max length of packets
		LINKTYPE_IPV4		// data link type
	};

	fwrite(&hdr, sizeof(hdr), 1, fp);
	return p;
}

static void pcap_write(PCAP *p, int flags, void *buf, size_t len, SOCKADDR_IN *source, SOCKADDR_IN *dest)
{
	size_t total_len = sizeof(ip_hdr) + sizeof(tcp_hdr) + len;
	short id = 0;

	clock_t t = clock();

	// write pcap header
	pcaprec_hdr_t hdr = 
	{	
		(int32)(t / CLOCKS_PER_SEC),
		(int32)(t % CLOCKS_PER_SEC) * CLOCKS_PER_SEC,
		total_len,
		total_len
	};

	fwrite(&hdr, sizeof(hdr), 1, p->fp);

	uint32 destaddr, srcaddr;
	uint16 destport;//, srcport;
	//uint32 seqnum, acknum; 

	if(flags & PCAP_SENDING)
	{
		destaddr = dest->sin_addr.S_un.S_addr;
		destport = 
		srcaddr  = source->sin_addr.S_un.S_addr;
		
	}

	// write IP header
	ip_hdr ip = 
	{
		0x45,				// version 4, 20 bytes
		0x00, 
		htons(total_len),	// total length
		htons(id),			// identification
		0x40,				// flags
		0x00,
		0x80,				// ttl
		IP_PROTO_TCP,		// protocol = tcp
		0x0000,				// no checksum
		flags & PCAP_SENDING ? source->sin_addr.S_un.S_addr : dest->sin_addr.S_un.S_addr,
		flags & PCAP_SENDING ? dest->sin_addr.S_un.S_addr   : source->sin_addr.S_un.S_addr,
	};

	fwrite(&ip, sizeof(ip), 1, p->fp);

	uint32 seq = flags & PCAP_SENDING ? p->seq : p->ack;
	uint32 ack = flags & PCAP_SENDING ? p->ack : p->seq;

	// tcp header
	tcp_hdr tcp = 
	{
		flags & PCAP_SENDING ? source->sin_port : htons(80),
		flags & PCAP_SENDING ? htons(80)        : source->sin_port,
		htonl(seq),		// seq
		htonl(ack),		// ack
		0x50,			// length (20 bytes)
		0x18,			// PSH,ACK
		htons(16425),	// window size
		0x0000,			// checksum
		0x0000			// padding
	};

	fwrite(&tcp, sizeof(tcp), 1, p->fp);

	// update the TCP sequence numbers AFTER writing the TCP header
	if(flags & PCAP_SENDING)	p->seq += len;
	else						p->ack += len;

	// finally write the IP payload
	fwrite(buf, 1, len, p->fp);
}

void pcap_data_send(PCAP *p, void *buf, size_t len, SOCKADDR_IN *local, SOCKADDR_IN *peer)
{
	pcap_write(p, PCAP_SENDING, buf, len, local, peer);
}

void pcap_data_recv(PCAP *p, void *buf, size_t len, SOCKADDR_IN *local, SOCKADDR_IN *peer)
{
	pcap_write(p, PCAP_RECEIVING, buf, len, local, peer);
}

void pcap_free(PCAP *p)
{
	free(p);
}
