#pragma once

#define APSIDLL extern "C" __declspec(dllexport)
#define APSICALL __cdecl

typedef unsigned long long u64;

APSIDLL bool APSICALL ReceiverConnect(char* address, int port);

APSIDLL void APSICALL ReceiverDisconnect();

APSIDLL bool APSICALL ReceiverIsConnected();

APSIDLL bool APSICALL ReceiverQuery(int length, u64* items, int* result, u64* labels);
