//
//  openssl.cpp
//
//	OpenSSL static hooking
//
//  www.catch22.net
//
//  Copyright (C) 2013 James Brown
//  Please refer to the file LICENCE.TXT for copying permission
//

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <map>
#include "detours.h"
#include "Trace.h"

using std::map;
#pragma comment(lib, "ws2_32")

#define PCAP_FORMAT
#ifdef PCAP_FORMAT
#include "pcap.h"
#endif

WCHAR logDir[MAX_PATH];
extern HMODULE g_hModule;
void dump_ptr(char *prefix, PVOID p);

typedef struct 
{
	int type;
} BIO_METHOD;

typedef struct bio_st
{
	BIO_METHOD *method;
	void *callback;
	char *cb_arg;
	int init;
	int shutdown;
	int flags;
	int retry_reason;
	int num;
	void *ptr;
	struct bio_st *next_bio;
	struct bio_st *prev_bio;
	int refs;
	unsigned long num_read;
	unsigned long num_write;
} BIO;


typedef struct
{
	int version;
	int type;
	void * method;		//SSL3

	BIO *rbio;
	BIO *wbio;
	BIO *bbio;

	int rwstate;
	int in_handshake;
	void *handshake_func;

	int server;	// server/client
	int new_session;
	int quiet_shutdown;
	int shutdown;
	int state;
	int rstate;

	void *init_buf;
	void *init_msg;
	int   init_num;
	int   init_off;

	unsigned char *packet;
	unsigned int   packet_length;

} SSL;

#define BIO_C_GET_FD 105
#define BIO_TYPE_DESCRIPTOR	0x0100

typedef int (__cdecl * SSL_PROTO)(SSL *s, void *buf, int len);

SSL_PROTO Target_SSL_read = 0;
SSL_PROTO Target_SSL_write = 0;

int BIO_get_fd(SSL *s)
{
	int sock = -1;
	if(s && s->rbio) sock = s->rbio->num;
	else if(s && s->wbio) sock = s->wbio->num;
	return sock;
}

SOCKADDR_IN sslHost(SSL *s)
{
	int sock = BIO_get_fd(s);

	SOCKADDR_IN addr = { 0 };
	int addr_len = sizeof(addr);  

	getsockname(sock, (struct sockaddr*)&addr, &addr_len);
	return addr;
}

SOCKADDR_IN sslPeer(SSL *s)
{
	int sock = BIO_get_fd(s);

	SOCKADDR_IN addr = { 0 };
	int addr_len = sizeof(addr);  
	
	getpeername(sock, (struct sockaddr*)&addr, &addr_len);
	return addr;
}

std::map<u_long, PCAP *> logSession;

PCAP * createLog(IN_ADDR peer_addr)
{
	WCHAR name[MAX_PATH];
	SYSTEMTIME st;
	GetLocalTime(&st);

#ifdef PCAP_FORMAT
	WCHAR ext[] = L"pcap";
#else
	WCHAR ext[] = L"txt";
#endif

	swprintf_s(name, MAX_PATH, L"%s\\%hs - %04d-%02d-%02d - %02d%02d%02d.%ls", 
		logDir, 
		inet_ntoa(peer_addr),
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
		ext);

	FILE *fp = _wfopen(name, L"wb");

#ifdef PCAP_FORMAT
	PCAP *p = pcap_init(fp);
#endif

	return p;
}

PCAP * getSession(SSL*s)
{
	std::map<u_long, PCAP*>::iterator it;
	
	SOCKADDR_IN peer_addr = sslPeer(s);

	it = logSession.find(peer_addr.sin_addr.S_un.S_addr);

	if(it != logSession.end())
	{
		return it->second;
	}
	else
	{
		PCAP *p = createLog(peer_addr.sin_addr);
		logSession[peer_addr.sin_addr.S_un.S_addr] = p;
		return p;
	}
}

int Detour_SSL_read(SSL *s, void *buf, int len)
{
	int ret = Target_SSL_read(s, buf, len);

	if(ret > 0)
	{
		PCAP *fp = getSession(s);

#ifdef PCAP_FORMAT
		SOCKADDR_IN h = sslHost(s);
		SOCKADDR_IN d = sslPeer(s);
		pcap_data_recv(fp, buf, ret, &h, &d);
#else
		if(memcmp(buf, "HTTP/1.1", 8) == 0)
			fwrite("\r\n\r\n", 1, 4, fp);

		fwrite(buf, 1, ret, fp);
#endif
		fflush(fp->fp);
	}

	return ret;
}

int Detour_SSL_write(SSL *s, void *buf, int len)
{
	int ret = Target_SSL_write(s, buf, len);

	if(ret > 0)
	{
		//FILE *fp = getSession(s);
		PCAP *fp = getSession(s);

#ifdef PCAP_FORMAT
		SOCKADDR_IN h = sslHost(s);
		SOCKADDR_IN d = sslPeer(s);
		pcap_data_send(fp, buf, ret, &h, &d);
#else
		if(memcmp(buf, "POST ", 5) == 0 || memcmp(buf, "GET ", 4) == 0)
			fwrite("\r\n\r\n", 1, 4, fp);

		fwrite(buf, 1, ret, fp);
#endif
		fflush(fp->fp);
	}

	return ret;
}


void Hook_OpenSSL(DWORD_PTR write_addr, DWORD_PTR read_addr)//, DWORD_PTR bio_addr)
{
	// create the log directory
	GetModuleFileName(g_hModule, logDir, MAX_PATH);
	WCHAR *sep = wcsrchr(logDir, '\\');
	if(sep) *sep = '\0';
	wcscat_s(logDir, MAX_PATH, L"\\log");
	CreateDirectory(logDir, 0);

	Target_SSL_read  = (SSL_PROTO)read_addr;
	Target_SSL_write = (SSL_PROTO)write_addr;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach(&(PVOID&)Target_SSL_read,  Detour_SSL_read);
	DetourAttach(&(PVOID&)Target_SSL_write, Detour_SSL_write);

	DetourTransactionCommit();
}

void UnHook_OpenSSL()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourDetach(&(PVOID&)Target_SSL_read,  Detour_SSL_read);
	DetourDetach(&(PVOID&)Target_SSL_write, Detour_SSL_write);

	Target_SSL_write = 0;
	Target_SSL_read  = 0;

	DetourTransactionCommit();

	std::map<u_long, PCAP*>::iterator it;
	for(it = logSession.begin(); it != logSession.end(); it++)
	{
		PCAP *p = it->second;
		fclose(p->fp);
		pcap_free(p);
	}
}
