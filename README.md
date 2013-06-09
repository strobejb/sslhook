sslhook
-------

SSLHOOK is a Win32 DLL that allows hooking of the OpenSSL functions SSL_read and SSL_write. 

Version 1 is designed to work against statically-compiled versions of OpenSSL (rather than the DLL version). As such sslhook requires some preconfiguration, which requires knowledge of the relative addresses of the SSL_read and SSL_write functions in the target binary.

Installation
------------

Running SSLHOOK on Win32 requires the following registry settings:

  > HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  >   AppInit_DLLs: <full-path-to-sslhook.dll>
  >   LoadAppInit_DLLs: 0x1

On 64bit windows:
  
  > HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
  >   AppInit_DLLs: <full-path-to-sslhook.dll>
  >   LoadAppInit_DLLs: 0x1


Configuration
-------------

Configuration is by way of an INI file. SSLHOOK will read a file called sslhook.ini that must exist in the same directory as sslhook.dll. Each process to target must have its own section in the INI file, and the RVA (relative virtual address) of SSL_Read and SSL_Write provided. The DLL that the OpenSSL functions are linked into must also be specified withe the targetDLL parameter.

For example:

  >  [target.exe]
  >  targetDLL=BASENAME.DLL
  >  SSL_Read=10001234   ; the RVA of SSL_Read
  >  SSL_Read=10004567   ; the RVA of SSL_Write

Capturing output
----------------

Output can be captured through the SysInternals DebugView program. Output is also written in PCAP format which can be viewed with Wireshark. 
