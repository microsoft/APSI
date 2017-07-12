#include "Network/boost_channel.h"
#include "Network/boost_socket.h"
#include "Network/boost_endpoint.h"

namespace apsi
{
    namespace network
    {
        BoostChannel::BoostChannel(
            BoostEndpoint& endpoint,
            std::string localName,
            std::string remoteName)
            :mEndpoint(endpoint),
            mLocalName(localName),
            mRemoteName(remoteName)
        {

        }

        BoostChannel::~BoostChannel()
        {
        }

        Endpoint & BoostChannel::getEndpoint()
        {
            return *(Endpoint*)&mEndpoint;
        }

        std::string BoostChannel::getName() const
        {
            return mLocalName;
        }

        void BoostChannel::asyncSend(const void * buff, uint64_t size)
        {
            if (mSocket->mStopped)
                throw std::runtime_error("");

            BoostIOOperation op;

            op.mSize = (uint32_t)size;
            op.mBuffs[1] = boost::asio::buffer((char*)buff, (uint32_t)size);

            op.mType = BoostIOOperation::Type::SendData;

            mEndpoint.getIOService().dispatch(mSocket.get(), op);
        }

        void BoostChannel::asyncSend(std::unique_ptr<ChannelBuffer> buff)
        {
            if (mSocket->mStopped)
                throw std::runtime_error("");

            BoostIOOperation op;

            op.mSize = (uint32_t)buff->ChannelBufferSize();


            op.mBuffs[1] = boost::asio::buffer((char*)buff->ChannelBufferData(), (uint32_t)buff->ChannelBufferSize());
            op.mType = BoostIOOperation::Type::SendData;

            op.mOther = buff.release();

            mEndpoint.getIOService().dispatch(mSocket.get(), op);
        }

        void BoostChannel::send(const void * buff, uint64_t size)
        {
            if (mSocket->mStopped)
                throw std::runtime_error("");

            BoostIOOperation op;
            op.clear();

            op.mSize = (uint32_t)size;
            op.mBuffs[1] = boost::asio::buffer((char*)buff, (uint32_t)size);


            op.mType = BoostIOOperation::Type::SendData;

            std::promise<void> prom;
            op.mPromise = &prom;

            mEndpoint.getIOService().dispatch(mSocket.get(), op);

            prom.get_future().get();
        }

        std::future<void> BoostChannel::asyncRecv(void * buff, uint64_t size)
        {
            if (mSocket->mStopped)
                throw std::runtime_error("");

            BoostIOOperation op;
            op.clear();

            op.mSize = (uint32_t)size;
            op.mBuffs[1] = boost::asio::buffer((char*)buff, (uint32_t)size);

            op.mType = BoostIOOperation::Type::RecvData;

            op.mOther = nullptr;

            op.mPromise = new std::promise<void>();
            auto future = op.mPromise->get_future();

            mEndpoint.getIOService().dispatch(mSocket.get(), op);

            return future;
        }

        std::future<void> BoostChannel::asyncRecv(ChannelBuffer & mH)
        {
            if (mSocket->mStopped)
                throw std::runtime_error("");

            BoostIOOperation op;
            op.clear();


            op.mType = BoostIOOperation::Type::RecvData;

            op.mOther = &mH;

            op.mPromise = new std::promise<void>();
            auto future = op.mPromise->get_future();

            mEndpoint.getIOService().dispatch(mSocket.get(), op);

            return future;
        }

        void BoostChannel::recv(void * dest, uint64_t length)
        {
            asyncRecv(dest, length).get();
        }

        void BoostChannel::recv(ChannelBuffer & mH)
        {
            asyncRecv(mH).get();
        }

        bool BoostChannel::opened()
        {
            return true;
        }
        void BoostChannel::waitForOpen()
        {
            // async connect hasn't been implemented.
        }

        void BoostChannel::close()
        {
            // indicate that no more messages should be queued and to fulfill
            // the mSocket->mDone* promised.
            mSocket->mStopped = true;


            BoostIOOperation closeRecv;
            closeRecv.mType = BoostIOOperation::Type::CloseRecv;
            std::promise<void> recvPromise;
            closeRecv.mPromise = &recvPromise;

            mEndpoint.getIOService().dispatch(mSocket.get(), closeRecv);

            BoostIOOperation closeSend;
            closeSend.mType = BoostIOOperation::Type::CloseSend;
            std::promise<void> sendPromise;
            closeSend.mPromise = &sendPromise;
            mEndpoint.getIOService().dispatch(mSocket.get(), closeSend);

            recvPromise.get_future().get();
            sendPromise.get_future().get();

            // ok, the send and recv queues are empty. Lets close the socket
            mSocket->mHandle.close();

            // lets de allocate ourselves in the endpoint.
            mEndpoint.removeChannel(getName());

            // WARNING: we are deallocated now. Do not touch any member variables.
        }


        std::string BoostChannel::getRemoteName() const
        {
            return mRemoteName;
        }

        uint64_t BoostChannel::getTotalDataSent() const
        {
            return (mSocket) ? (uint64_t)mSocket->mTotalSentData : 0;
        }

        uint64_t BoostChannel::getMaxOutstandingSendData() const
        {
            return (mSocket) ? (uint64_t)mSocket->mMaxOutstandingSendData : 0;
        }
    }
}
