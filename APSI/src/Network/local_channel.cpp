#include "Network/local_channel.h"
#include "Network/local_endpoint.h"
#include <cstring>

namespace apsi
{
    namespace network
    {
        LocalChannel::LocalChannel() :
            mDoneFuture(mDoneProm.get_future()),
            mRemoteChannel(nullptr),
            mLocalEndpoint(nullptr)
        {
        }


        LocalChannel::~LocalChannel()
        {
        }
        Endpoint & LocalChannel::getEndpoint()
        {
            return *mLocalEndpoint;
        }

        std::string LocalChannel::getName() const
        {
            return mName;
        }

        void LocalChannel::asyncSend(std::unique_ptr<ChannelBuffer> mH)
        {
            asyncSend(mH->ChannelBufferData(), mH->ChannelBufferSize());
        }

        void LocalChannel::asyncSend(const void * bufferPtr, uint64_t length)
        {
            void* data = new uint8_t[length];
            memcpy(data, bufferPtr, length);

            mRemoteChannel->mMsgQueue.push(Buffer(data, length));
        }

        void LocalChannel::send(const void * bufferPtr, uint64_t length)
        {
            void* data = new uint8_t[length];
            //std::copy((uint8_t*)bufferPtr, (uint8_t*)bufferPtr + length, (uint8_t*)data);
            memcpy(data, bufferPtr, length);

            mRemoteChannel->mMsgQueue.push(Buffer(data, length));
            //}
        }
        void LocalChannel::recv(void * dest, uint64_t length)
        {
            auto buf(mMsgQueue.pop());

            if (length != buf.mLength)
                throw std::runtime_error("received message length does not match parameter");

            //std::copy((uint8_t*)buf.mData, (uint8_t*)buf.mData + buf.mLength, (uint8_t*)dest);
            memcpy(dest, buf.mData, buf.mLength);


            delete[](uint8_t*) buf.mData;
        }

        void LocalChannel::recv(ChannelBuffer & mH)
        {
            auto buf(mMsgQueue.pop());

            mH.ChannelBufferResize(buf.mLength);
            //std::copy((uint8_t*)buf.mData, (uint8_t*)buf.mData + buf.mLength, (uint8_t*)buffer.__data());
            memcpy(mH.ChannelBufferData(), buf.mData, buf.mLength);

            delete[](uint8_t*)buf.mData;
        }

        bool LocalChannel::opened()
        {
            return true;
        }

        void LocalChannel::waitForOpen()
        {
        }

        void LocalChannel::close()
        {
            //if (mMsgQueue.size())
                //throw std::runtime_error("channel has queued messages when closed.");

            mDoneProm.set_value();

            //std::lock_guard<std::mutex> lock(mLocalEndpoint->mChannelsMtx);

            //auto iter = std::find(mLocalEndpoint->mChannels.begin(), mLocalEndpoint->mChannels.end(), this);

            //*iter = mLocalEndpoint->mChannels.back();
            //mLocalEndpoint->mChannels.pop_back();

        }


        uint64_t LocalChannel::getTotalDataSent() const
        {
            return 0;
        }

        uint64_t LocalChannel::getMaxOutstandingSendData() const
        {
            return 0;
        }
    }
}