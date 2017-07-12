#pragma once

#include <thread> 
#include <mutex>
#include <list> 
#include <future>
#include <string>
#include <vector>
#include "boost/asio.hpp"

namespace apsi
{
    namespace network
    {
        class BoostAcceptor;
        struct BoostIOOperation;
        class BoostEndpoint;
        class BoostSocket;

        std::vector<std::string> split(const std::string &s, char delim);

        class BoostIOService
        {
            friend class BoostSocket;
            friend class BoostEndpoint;

        public:

            BoostIOService(const BoostIOService&) = delete;
            BoostIOService() = delete;

            /// <summary> Constructor for the IO service that services network IO operations.</summary>
            /// <param name="threadCount">The number of threads that should be used to service IO operations. 0 = use # of CPU cores.</param>
            BoostIOService(std::uint64_t threadCount);
            ~BoostIOService();

            /// /// <summary> This is a Windows specific object that is used to queue up pending network IO operations.</summary>
            boost::asio::io_service mIoService;

            std::unique_ptr<boost::asio::io_service::work> mWorker;


            /// <summary> This list hold the threads that send and recv messages. </summary>
            std::list<std::thread> mWorkerThrds;

            /// <summary> The list of acceptor objects that hold state about the ports that are being listened to. </summary>
            std::list<BoostAcceptor> mAcceptors;


            /// <summary> indicates whether stop() has been called already.</summary>
            bool mStopped;

            /// <summary> The mutex the protects sensitive objects in this class. </summary>
            std::mutex mMtx;

            /// <summary> A list containing futures for the endpoint that use this IO service. Each is fulfilled when the endpoint is finished with this class.</summary>
            std::list<std::shared_future<void>> mEndpointStopFutures;

            void receiveOne(BoostSocket* socket);

            void sendOne(BoostSocket* socket);

            /// <summary> Used to queue up asynchronous socket operations.</summary>
            /// <param name="socket">The socket that is being operated on.</param>
            /// <param name="op">The operation that should be queued up. </param>
            void dispatch(BoostSocket* socket, BoostIOOperation& op);

            /// <summary> Gives a new endpoint which is a host endpoint the acceptor which provides sockets. 
            /// Needed since multiple endpoints with different names may listen on a single port.</summary>
            /// <param name="endpoint">The new Endpoint that needs its acceptor.</param>
            BoostAcceptor* getAcceptor(BoostEndpoint& endpoint);

            /// <summary> Shut down the IO service. WARNING: blocks until all Channels and Endpoints are stopped.</summary>
            void stop();
        };
    }
}
