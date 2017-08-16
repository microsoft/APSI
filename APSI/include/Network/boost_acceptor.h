#pragma once

#include <list>
#include <future>
#include <unordered_map>
#include <atomic>
#include "boost_socket.h"

namespace apsi 
{
    namespace network
    {
        class BoostSocket;
        class BoostChannel;
        class BoostIOService;
        struct BoostIOOperation;

        //class SocketTag
        //{
        //public:
        //	std::string
        //		mEndpointName,
        //		mRemoteChannelName,
        //		mLocalChannelName;

        //	bool operator==(const SocketTag& other) const
        //	{
        //		return mEndpointName == other.mEndpointName &&
        //			mRemoteChannelName == other.mRemoteChannelName &&
        //			mLocalChannelName == other.mLocalChannelName;
        //	}
        //};


        class BoostAcceptor
        {

        public:
            BoostAcceptor() = delete;
            BoostAcceptor(const BoostAcceptor&) = delete;

            BoostAcceptor(BoostIOService& ioService);
            ~BoostAcceptor();

            std::promise<void> mStoppedPromise;
            std::future<void> mStoppedFuture;

            BoostIOService& mIOService;

            boost::asio::ip::tcp::acceptor mHandle;

            //SOCKET mListenSocket;
            std::atomic<bool> mStopped;
            std::mutex mMtx;
            std::unordered_map<std::string, std::promise<BoostSocket*>> mSocketPromises;
            std::deque<std::string> mQueuedConnections;

            std::promise<BoostSocket*>& getSocketPromise(
                std::string endpointName,
                std::string localChannelName,
                std::string remoteChannelName);

            BoostSocket* getSocket(BoostChannel& chl);

            std::promise<BoostSocket*>& createRandomSocketPromise(
                std::string endpointName);

            std::pair<std::string, BoostSocket*> getNextQueuedSocket();

            std::uint64_t mPort;
            boost::asio::ip::tcp::endpoint mAddress;

            //SOCKET mListenSocket, mAcceptSocket;

            void bind(std::uint32_t port, std::string ip);
            void start();
            void stop();
            bool stopped() const;
        };
    }
}