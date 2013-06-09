//
//  pcap.h
//
//	Simple routines for writing socket data into PCAP format
//
//  www.catch22.net
//
//  Copyright (C) 2013 James Brown
//  Please refer to the file LICENCE.TXT for copying permission
//

#ifndef APP_PCAP_INCLUDED
#define APP_PCAP_INCLUDED

typedef struct
{
	FILE * fp;
	size_t seq;
	size_t ack;
} PCAP;

PCAP * pcap_init(FILE *fp);
void   pcap_free(PCAP *pcap);

void   pcap_data_send(PCAP *p, void *buf, size_t len, SOCKADDR_IN *local, SOCKADDR_IN *peer);
void   pcap_data_recv(PCAP *p, void *buf, size_t len, SOCKADDR_IN *local, SOCKADDR_IN *peer);

#endif