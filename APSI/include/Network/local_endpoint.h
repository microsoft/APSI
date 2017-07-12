#pragma once

#include <string>
#include <mutex>
#include <vector>
#include "endpoint.h"

namespace apsi
{
    namespace network
    {
        class LocalChannel;

        class LocalEndpoint : public Endpoint
        {
            friend class LocalChannel;

        public:
            LocalEndpoint(std::string name);

            ~LocalEndpoint();

            /// <summary>Gets the name which will be matched up with the other end point. Used if there are multiple endpoint. e.g. 3 party protocol. </summary>
            std::string getName() const override { return mName; };

            /// <summary>Adds a new channel (data pipe) between this endpoint and the remote. The channel is named at each end.</summary>
            Channel& addChannel(std::string localName, std::string remoteName) override;

            /// <summary>Stops this Endpoint. Will block until all channels have closed.</summary>
            void stop() override;

            /// <summary>returns whether the endpoint has been stopped (or never opened).</summary>
            bool stopped() const override;


        private:

            std::string mName;
            LocalEndpoint* mRemote;

            std::mutex mChannelsMtx;
            std::vector<LocalChannel*> mChannels;

            static std::mutex mLocalEndpointsMtx;
            static std::vector<LocalEndpoint*> mLocalEndpoints;
        };
    }
}