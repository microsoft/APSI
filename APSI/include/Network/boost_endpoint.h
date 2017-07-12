#pragma once 

#include <list>
#include <mutex>
#include "boost_acceptor.h"
#include "endpoint.h"
#include "boost_channel.h"
#include "boost_ioservice.h"
#include "boost/lexical_cast.hpp"

namespace apsi
{
    namespace network
    {
        class BoostAcceptor;

        class BoostEndpoint : public Endpoint
        {

            BoostEndpoint(const BoostEndpoint&) = delete;

            std::string mIP;
            std::uint32_t mPort;
            bool mHost, mStopped;
            BoostIOService* mIOService;
            BoostAcceptor* mAcceptor;
            std::list<BoostChannel> mChannels;
            std::mutex mAddChannelMtx;
            std::promise<void> mDoneProm;
            std::shared_future<void> mDoneFuture;
            std::string mName;
            boost::asio::ip::tcp::endpoint mRemoteAddr;
        public:

            void start(BoostIOService& ioService, std::string remoteIp, std::uint32_t port, bool host, std::string name);
            void start(BoostIOService& ioService, std::string address, bool host, std::string name);

            BoostEndpoint(BoostIOService & ioService, std::string address, bool host, std::string name)
                : mPort(0), mHost(false), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
                mDoneFuture(mDoneProm.get_future().share())
            {
                start(ioService, address, host, name);
            }

            BoostEndpoint(BoostIOService & ioService, std::string remoteIP, std::uint32_t port, bool host, std::string name)
                : mPort(0), mHost(false), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
                mDoneFuture(mDoneProm.get_future().share())
            {
                start(ioService, remoteIP, port, host, name);
            }


            BoostEndpoint()
                : mPort(0), mHost(false), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
                mDoneFuture(mDoneProm.get_future().share())
            {
            }

            ~BoostEndpoint();

            std::string getName() const override;

            BoostIOService& getIOService() { return *mIOService; }

            /// <summary>Adds a new channel (data pipe) between this endpoint and the remote. The channel is named at each end.</summary>
            Channel& addChannel(std::string localName, std::string remoteName) override;


            /// <summary>Stops this Endpoint. Will block until all channels have closed.</summary>
            void stop() override;

            /// <summary>returns whether the endpoint has been stopped (or never opened).</summary>
            bool stopped() const override;

            /// <summary> Removes the channel with chlName. (deallocates it)</summary>
            void removeChannel(std::string  chlName);

            std::uint32_t port() const { return mPort; };

            std::string IP() const { return mIP; }

            bool isHost() const { return mHost; };
        };
    }
}