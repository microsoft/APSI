// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the APSI library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#define APSIEXPORT extern "C" __declspec(dllexport)
#define APSICALL __cdecl

typedef unsigned long long u64;

/**
Connect a Receiver to the given address and port.

Connecting will internally create a Receiver instance
and initialize it by performing a handshake with the Sender.
*/
APSIEXPORT bool APSICALL ReceiverConnect(char* address, int port);

/**
Disconnect a Receiver.
*/
APSIEXPORT void APSICALL ReceiverDisconnect();

/**
Returns whether the Receiver is connected
*/
APSIEXPORT bool APSICALL ReceiverIsConnected();

/**
Perform a Query for the given items.

The 'result' array consist of booleans encoded as integers. Any value other than 0
is considered 'true', 0 is considered as 'false'.
*/
APSIEXPORT bool APSICALL ReceiverQuery(int length, u64* items, int* result, u64* labels);
