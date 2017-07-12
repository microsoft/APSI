#pragma once

#include <deque>
#include <mutex>
#include <future>
#include "boost_ioservice.h"
#include "boost/asio.hpp"

namespace apsi
{
    namespace network
    {
        class WinNetIOService;
        class ChannelBuffer;


        struct BoostIOOperation
        {
            enum class Type
            {
                RecvName,
                RecvData,
                CloseRecv,
                SendData,
                CloseSend,
                CloseThread
            };

            BoostIOOperation()
            {
                clear();
            }

            BoostIOOperation(const BoostIOOperation& copy)
            {
                mType = copy.mType;
                mSize = copy.mSize;
                mBuffs[0] = boost::asio::buffer(&mSize, sizeof(std::uint32_t));
                mBuffs[1] = copy.mBuffs[1];
                mOther = copy.mOther;
                mPromise = copy.mPromise;
            }

            void clear()
            {
                mType = (Type)0;
                mSize = 0;
                mBuffs[0] = boost::asio::buffer(&mSize, sizeof(std::uint32_t));
                mBuffs[1] = boost::asio::mutable_buffer();
                mOther = nullptr;
                mPromise = nullptr;
            }


            std::array<boost::asio::mutable_buffer, 2> mBuffs;
            Type mType;
            std::uint32_t mSize;

            ChannelBuffer* mOther;
            std::promise<void>* mPromise;
            std::exception_ptr mException;
            //std::function<void()> mCallback;
        };



        class BoostSocket
        {
        public:
            BoostSocket(BoostIOService& ios);

            boost::asio::ip::tcp::socket mHandle;
            boost::asio::strand mSendStrand, mRecvStrand;

            std::deque<BoostIOOperation> mSendQueue, mRecvQueue;
            bool mStopped;

            std::atomic<std::uint64_t> mOutstandingSendData, mMaxOutstandingSendData, mTotalSentData;
        };

        inline BoostSocket::BoostSocket(BoostIOService& ios) :
            mHandle(ios.mIoService),
            mSendStrand(ios.mIoService),
            mRecvStrand(ios.mIoService),
            mStopped(false),
            mOutstandingSendData(0),
            mMaxOutstandingSendData(0),
            mTotalSentData(0)
        {}
    }
}
