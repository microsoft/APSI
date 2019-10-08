// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Microsoft.Research.APSI.Client
{
    /// <summary>
    /// Wrapper for APSI Client
    /// </summary>
    public static class APSIClient
    {
        private const string APSINative = "APSINative";

        [DllImport(APSINative, CharSet = CharSet.Ansi)]
        static extern bool ReceiverConnect(string address, int port);

        [DllImport(APSINative)]
        static extern void ReceiverDisconnect();

        [DllImport(APSINative)]
        static extern bool ReceiverIsConnected();

        [DllImport(APSINative)]
        static extern bool ReceiverQuery(int length,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] ulong[] items,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] int[] result,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] ulong[] labels);

        /// <summary>
        /// Connect to an APSI service at the given IP Address and port.
        /// </summary>
        /// <param name="address">IP Address to connect to</param>
        /// <param name="port">Port to connect to</param>
        public static void Connect(string address, int port)
        {
            if (!ReceiverConnect(address, port))
                throw new InvalidOperationException("Receiver could not connect!");
        }

        /// <summary>
        /// Disconnect from an APSI service.
        /// </summary>
        public static void Disconnect()
        {
            ReceiverDisconnect();
        }

        /// <summary>
        /// Get whether this client is connected to an APSI service
        /// </summary>
        public static bool IsConnected
        {
            get
            {
                return ReceiverIsConnected();
            }
        }

        /// <summary>
        /// Perform a query to an APSI service.
        /// </summary>
        /// <param name="items">Items to query</param>
        /// <returns>An enumeration of pairs. The first item indicates whether the corresponding item is present in the APSI Service,
        /// the second item contains any associated data.</returns>
        public static IEnumerable<(bool, ulong)> Query(IEnumerable<ulong> items)
        {
            if (null == items)
                throw new ArgumentNullException("items");

            // Build items
            int count = items.Count();
            ulong[] qitems = new ulong[count];
            int[] intersection = new int[count];
            ulong[] labels = new ulong[count];

            int idx = 0;
            foreach (ulong item in items)
            {
                qitems[idx++] = item;
            }

            if (!ReceiverQuery(count, qitems, intersection, labels))
                throw new InvalidOperationException("Could not query!");

            List<(bool, ulong)> result = new List<(bool, ulong)>();

            for (idx = 0; idx < count; idx++)
            {
                bool present = intersection[idx] != 0;
                ulong value = 0;
                if (present)
                {
                    value = labels[idx];
                }

                result.Add((present, value));
            }

            return result;
        }
    }
}
