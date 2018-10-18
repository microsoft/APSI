#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the APSI library
// that can be PInvoked by .Net code.
// 
// In this way we avoid having to create a .Net assembly, with all the
// restrictions that it implies.
//
///////////////////////////////////////////////////////////////////////////

#define APSIDLL extern "C" __declspec(dllexport)
#define APSICALL __cdecl

typedef unsigned long long u64;

/**
Connect a Receiver to the given address and port.

Connecting will internally create a Receiver instance
and initialize it by performing a handshake with the Sender.
*/
APSIDLL bool APSICALL ReceiverConnect(char* address, int port);

/**
Disconnect a Receiver.
*/
APSIDLL void APSICALL ReceiverDisconnect();

/**
Returns whether the Receiver is connected
*/
APSIDLL bool APSICALL ReceiverIsConnected();

/**
Perform a Query for the given items.

The result and labels are returned in the given arrays.
*/
APSIDLL bool APSICALL ReceiverQuery(int length, u64* items, int* result, u64* labels);
