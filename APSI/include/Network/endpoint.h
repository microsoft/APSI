#pragma once

#include <string> 

namespace apsi 
{
    namespace network
    {
        class Channel;

        class Endpoint
        {
        public:
            virtual ~Endpoint()
            {
            }

            virtual std::string getName() const = 0;

            /// <summary>Adds a new channel (data pipe) between this endpoint and the remote. The channel is named at each end.</summary>
            virtual Channel& addChannel(std::string localName, std::string remoteName) = 0;

            /// <summary>Stops this Endpoint. Will block until all channels have closed.</summary>
            virtual void stop() = 0;

            /// <summary>returns whether the endpoint has been stopped (or never opened).</summary>
            virtual bool stopped() const = 0;

            //
            // Helper functions.
            //

            /// <summary>Adds a new channel (data pipe) between this endpoint and the remote. The channel has the same name at each end.</summary>
            Channel& addChannel(std::string name) { return addChannel(name, name); }
        };
    }
}