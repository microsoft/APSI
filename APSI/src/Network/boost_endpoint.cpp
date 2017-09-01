#include "Network/boost_endpoint.h"
#include "Network/boost_ioservice.h"
#include "Network/boost_channel.h"
#include "Network/boost_acceptor.h"
#include "Network/byte_stream.h"
#include "Network/boost_socket.h"
#include "Tools/log.h"
#include <sstream>
#include <stdexcept>
#include "Network/network_utils.h"

namespace apsi
{
    namespace network
    {
        //extern std::vector<std::string> split(const std::string &s, char delim);


        void BoostEndpoint::start(BoostIOService& ioService, std::string remoteIP, uint32_t port, bool host, std::string name)
        {
            if (mStopped == false)
                throw std::runtime_error("");


            mIP = (remoteIP);
            mPort = (port);
            mHost = (host);
            mIOService = &(ioService);
            mStopped = (false);
            mName = (name);

            if (host)
                mAcceptor = (ioService.getAcceptor(*this));
            else
            {
                boost::asio::ip::tcp::resolver resolver(mIOService->mIoService);
                boost::asio::ip::tcp::resolver::query query(remoteIP, boost::lexical_cast<std::string>(port));
                mRemoteAddr = *resolver.resolve(query);
            }

            std::lock_guard<std::mutex> lock(ioService.mMtx);
            ioService.mEndpointStopFutures.push_back(mDoneFuture);

        }

        void BoostEndpoint::start(BoostIOService& ioService, std::string address, bool host, std::string name)
        {
            auto vec = split(address, ':');

            auto ip = vec[0];
            auto port = 1212;
            if (vec.size() > 1)
            {
                std::stringstream ss(vec[1]);
                ss >> port;
            }

            start(ioService, ip, port, host, name);

        }

        BoostEndpoint::~BoostEndpoint()
        {
        }

        std::string BoostEndpoint::getName() const
        {
            return mName;
        }


        Channel & BoostEndpoint::addChannel(std::string localName, std::string remoteName)
        {

            BoostChannel* chlPtr;

            // first, add the channel to the endpoint.
            {
                std::lock_guard<std::mutex> lock(mAddChannelMtx);

                if (mStopped == true)
                {
                    throw std::runtime_error("");
                }

                mChannels.emplace_back(*this, localName, remoteName);
                chlPtr = &mChannels.back();
            }

            BoostChannel& chl = *chlPtr;


            if (mHost)
            {
                // if we are a host, then we can ask out acceptor for the socket which match the channel name.
                chl.mSocket.reset(mAcceptor->getSocket(chl));
            }
            else
            {
                chl.mSocket.reset(new BoostSocket(*mIOService));

                boost::system::error_code ec;
                auto tryCount = 10000000;

                chl.mSocket->mHandle.connect(mRemoteAddr, ec);

                while (tryCount-- && ec)
                {
                    chl.mSocket->mHandle.connect(mRemoteAddr, ec);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }

                if (ec)
                {
                    throw std::runtime_error("");
                }

                chl.mSocket->mHandle.set_option(boost::asio::ip::tcp::no_delay(true));
                chl.mSocket->mHandle.set_option(boost::asio::socket_base::receive_buffer_size(1024 * 512));

                std::stringstream ss;
                ss << mName << char('`') << localName << char('`') << remoteName;

                auto str = ss.str();
                std::unique_ptr<ByteStream> buff(new ByteStream((uint8_t*)str.data(), str.size()));


                chl.asyncSend(std::move(buff));

                /* If client lets server sets the channel name, then client should receive that channel name before moving on. */
                if (localName == "-")
                {
                    receive_string(chl.mLocalName, chl);
                    chl.mRemoteName = chl.mLocalName;
                }
            }

            return chl;
        }

        Channel* BoostEndpoint::getNextQueuedChannel()
        {
            if (!mHost)
                throw std::logic_error("Cannot get queued channel for non-host endpoints.");
            if (mStopped == true)
            {
                throw std::runtime_error("");
            }
            std::pair<std::string, BoostSocket*> socket = mAcceptor->getNextQueuedSocket();
            if (socket.second == nullptr)
                return nullptr;
            auto names = split(socket.first, char(':'));
            if (names[0] != mName)
                throw std::logic_error("Unexpected endpoint name."); // This should never happen.

            std::lock_guard<std::mutex> lock(mAddChannelMtx);
            mChannels.emplace_back(*this, names[1], names[2]);
            mChannels.back().mSocket.reset(socket.second);

            send_string(names[1], mChannels.back()); // Send back the channel name

            return &mChannels.back();
        }


        void BoostEndpoint::stop()
        {
            {
                std::lock_guard<std::mutex> lock(mAddChannelMtx);
                if (mStopped == false)
                {
                    mStopped = true;

                    if (mChannels.size() == 0)
                    {
                        mDoneProm.set_value();
                    }
                }
            }
            mDoneFuture.get();
        }

        bool BoostEndpoint::stopped() const
        {
            return mStopped;
        }

        void BoostEndpoint::removeChannel(std::string  chlName)
        {
            std::lock_guard<std::mutex> lock(mAddChannelMtx);

            auto iter = mChannels.begin();

            while (iter != mChannels.end())
            {
                auto name = iter->getName();
                if (name == chlName)
                {
                    //Log::out << Log::lock << "removing " << getName() << " "<< name << " = " << chlName << Log::unlock << Log::endl;
                    mChannels.erase(iter);
                    break;
                }
                ++iter;
            }

            // if there are no more channels and the send point has stopped, signal that the last one was just removed.
            if (mStopped && mChannels.size() == 0)
            {
                mDoneProm.set_value();
            }
        }
    }
}
