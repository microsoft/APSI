#include "Network/boost_acceptor.h"
#include "Network/boost_ioservice.h"
#include "Network/boost_channel.h"
#include "Network/endpoint.h"
#include "Network/byte_stream.h"
#include "Tools/log.h"
#include "boost/lexical_cast.hpp"
#include <random>
#include <stdexcept>

using namespace apsi::tools;

namespace apsi
{
    namespace network
    {

        BoostAcceptor::BoostAcceptor(BoostIOService& ioService)
            :
            mStoppedFuture(mStoppedPromise.get_future()),
            mIOService(ioService),
            mHandle(ioService.mIoService),
            mStopped(false),
            mPort(0)
        {
            mStopped = false;


        }



        BoostAcceptor::~BoostAcceptor()
        {
            stop();


            mStoppedFuture.get();
        }




        void BoostAcceptor::bind(std::uint32_t port, std::string ip)
        {
            auto pStr = std::to_string(port);
            mPort = port;

            boost::asio::ip::tcp::resolver resolver(mIOService.mIoService);
            boost::asio::ip::tcp::resolver::query
                query(ip, pStr);

            mAddress = *resolver.resolve(query);

            mHandle.open(mAddress.protocol());
            mHandle.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

            boost::system::error_code ec;
            mHandle.bind(mAddress, ec);

            if (mAddress.port() != port)
                throw std::runtime_error("");

            if (ec)
            {
                Log::out << ec.message() << Log::endl;

                throw std::runtime_error(ec.message());
            }


            mHandle.listen(boost::asio::socket_base::max_connections);
        }

        void BoostAcceptor::start()
        {
            if (stopped() == false)
            {

                BoostSocket* newSocket = new BoostSocket(mIOService);
                mHandle.async_accept(newSocket->mHandle, [newSocket, this](const boost::system::error_code& ec)
                {
                    start();

                    if (!ec)
                    {

                        auto buff = new ByteStream(4);
                        buff->setp(buff->capacity());

                        newSocket->mHandle.set_option(boost::asio::ip::tcp::no_delay(true));
                        newSocket->mHandle.set_option(boost::asio::socket_base::receive_buffer_size(1024 * 512));

                        newSocket->mHandle.async_receive(boost::asio::buffer(buff->data(), buff->size()),
                            [newSocket, buff, this](const boost::system::error_code& ec2, std::uint64_t bytesTransferred)
                        {
                            if (!ec2 || bytesTransferred != 4)
                            {
                                std::uint32_t size = buff->getArrayView<std::uint32_t>()[0];

                                buff->reserve(size);
                                buff->setp(size);

                                newSocket->mHandle.async_receive(boost::asio::buffer(buff->data(), buff->size()),
                                    [newSocket, buff, size, this](const boost::system::error_code& ec3, std::uint64_t bytesTransferred2)
                                {
                                    if (!ec3 || bytesTransferred2 != size)
                                    {
                                        // lets split it into pieces.
                                        auto names = split(std::string((char*)buff->data(), buff->size()), char('`'));


                                        // Now lets create or get the std::promise<WinNetSocket> that will hold this socket
                                        // for the WinNetEndpoint that will eventually receive it.
                                        auto& prom = (names[1] == "-") ?
                                            (createRandomSocketPromise(names[0]))
                                            :
                                            (getSocketPromise(names[0], names[2], names[1]));
                                        
                                        //Log::out << "accept WinNetSocket @ " << (std::uint64_t)socket << Log::endl;

                                        try
                                        {
                                            prom.set_value(newSocket);
                                        }
                                        catch (...)
                                        {
                                            Log::out << "failed to accept new socket: " << names[0] << " " << names[1] << "  " << names[2] << Log::endl;
                                            Log::out << "Socket with that name already exists." << Log::endl;

                                            delete newSocket;
                                        }
                                    }
                                    else
                                    {
                                        Log::out << "async_accept->async_receive->async_receive (body) failed with error_code:" << ec3.message() << Log::endl;

                                        delete newSocket;
                                    }

                                    delete buff;
                                });

                            }
                            else
                            {
                                Log::out << "async_accept->async_receive (header) failed with error_code:" << ec2.message() << Log::endl;
                                delete newSocket;
                                delete buff;
                            }

                        });
                    }
                    else
                    {
                        //Log::out << "async_accept failed with error_code:" << ec.message() << Log::endl;
                        delete newSocket;
                    }
                });
            }
            else
            {
                mStoppedPromise.set_value();
            }
        }

        void BoostAcceptor::stop()
        {
            mStopped = true;
            //mHandle.cancel();
            mHandle.close();

        }

        bool BoostAcceptor::stopped() const
        {
            return mStopped;
        }

        BoostSocket* BoostAcceptor::getSocket(BoostChannel & chl)
        {
            std::string tag = chl.getEndpoint().getName() + ":" + chl.getName() + ":" + chl.getRemoteName();


            std::promise<BoostSocket*>* prom = nullptr;

            {

                std::unique_lock<std::mutex> lock(mMtx);

                auto iter = mSocketPromises.find(tag);

                if (iter == mSocketPromises.end())
                {
                    iter = mSocketPromises.emplace(tag, std::promise<BoostSocket*>()).first;
                }

                prom = &iter->second;
            }
            return std::move(prom->get_future().get());
        }

        std::promise<BoostSocket*>& BoostAcceptor::getSocketPromise(
            std::string endpointName,
            std::string localChannelName,
            std::string remoteChannelName)
        {
            std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

            {
                std::unique_lock<std::mutex> lock(mMtx);
                auto iter = mSocketPromises.find(tag);

                if (iter == mSocketPromises.end())
                {
                    mSocketPromises.emplace(tag, std::promise<BoostSocket*>());
                }
            }

            return mSocketPromises[tag];
        }

        std::promise<BoostSocket*>& BoostAcceptor::createRandomSocketPromise(
            std::string endpointName)
        {
            std::random_device rd;
            std::string tag;
            std::unique_lock<std::mutex> lock(mMtx);
            while (true)
            {
                uint64_t random_channel = 0;
                random_channel |= rd();
                random_channel |= ((uint64_t)rd()) << 32;
                tag = endpointName + ":" + std::to_string(random_channel) + ":" + std::to_string(random_channel);
                auto iter = mSocketPromises.find(tag);
                if (iter == mSocketPromises.end())
                    break;
            }
            mSocketPromises.emplace(tag, std::promise<BoostSocket*>());
            mQueuedConnections.push_back(tag);

            return mSocketPromises[tag];
        }

        std::pair<std::string, BoostSocket*> BoostAcceptor::getNextQueuedSocket()
        {
            std::unique_lock<std::mutex> lock(mMtx);
            if (mQueuedConnections.empty())
                return std::make_pair("", nullptr);
            std::string tag = mQueuedConnections.front();
            mQueuedConnections.pop_front();
            auto iter = mSocketPromises.find(tag);
            if (iter == mSocketPromises.end())
                throw std::logic_error(std::string("Socket with name") + tag + " does not exist."); // This should never happen.

            std::promise<BoostSocket*>* prom = &(iter->second);
            return std::make_pair(tag, std::move(prom->get_future().get()));
        }
    }
}
