#include "Network/local_endpoint.h"
#include "Network/local_channel.h"
#include <algorithm>

namespace apsi
{
    namespace network
    {
        std::mutex LocalEndpoint::mLocalEndpointsMtx;
        std::vector<LocalEndpoint*> LocalEndpoint::mLocalEndpoints;

        LocalEndpoint::LocalEndpoint(std::string name)
            :mName(name),
            mRemote(nullptr)
        {
            std::lock_guard<std::mutex> lock(mLocalEndpointsMtx);

            auto count = std::count_if(mLocalEndpoints.begin(), mLocalEndpoints.end(), [&](const LocalEndpoint* ep)
            {
                return ep->getName() == name;
            });

            if (count > 1)
                throw std::runtime_error("");

            mLocalEndpoints.push_back(this);
        }

        LocalEndpoint::~LocalEndpoint()
        {

            // grab the lock to synchronize
            std::lock_guard<std::mutex> lock(mLocalEndpointsMtx);


            auto thisIter = std::find_if(mLocalEndpoints.begin(), mLocalEndpoints.end(),
                [&](const LocalEndpoint* ep) -> bool
            {
                return ep == this;
            });


            mLocalEndpoints.erase(thisIter);
        }

        Channel & LocalEndpoint::addChannel(std::string localName, std::string remoteName)
        {
            // make sure that the name has been set. Used if there are more than two local endpoints. e.g. 3 party protocol...
            if (mName == "")
            {
                throw std::runtime_error("Please set Destination before adding channels. Both LocalEndpoints should use the same destincationName.");
            }

            // if the remote endpoint is not set, wait for it to come online and set it...
            while (mRemote == nullptr)
            {
                std::vector<LocalEndpoint*>::iterator remoteIter;

                {
                    // grab the lock to synchronize
                    std::lock_guard<std::mutex> lock(mLocalEndpointsMtx);

                    // see if there is another endpoint with mName that is not us.
                    remoteIter = std::find_if(mLocalEndpoints.begin(), mLocalEndpoints.end(),
                        [&](const LocalEndpoint* ep) -> bool
                    {
                        return ep->getName() == mName &&
                            ep != this;
                    });
                }

                // did we find our other endpoint?
                if (remoteIter != mLocalEndpoints.end())
                {
                    mRemote = *remoteIter;
                }
                else
                {
                    // TODO: maybe do something smarter than a spin lock...
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }

            // We have a remote endpoint.

            LocalChannel* chl;
            {
                // grab the lock to synchronize
                std::lock_guard<std::mutex> lock(mChannelsMtx);

                // make sure we haven't already added a channel with this name.
                if (std::find_if(mChannels.begin(), mChannels.end(), [&](const LocalChannel* chlParam) {
                    return chlParam->getName() == localName;
                }) != mChannels.end())
                {
                    throw std::runtime_error("Channel Name already exists.");
                }

                mChannels.emplace_back(new LocalChannel());
                chl = mChannels.back();
                chl->mName = localName;
                chl->mLocalEndpoint = this;
            }

            while (chl->mRemoteChannel == nullptr)
            {
                std::vector<LocalChannel*>::iterator remoteIter;

                {
                    // grab the lock to synchronize
                    std::lock_guard<std::mutex> lock(mRemote->mChannelsMtx);
                    if (mRemote->mName == "") throw std::runtime_error("Remote Endpoint Closed");

                    // see if remote has a channel with this name.
                    remoteIter = std::find_if(mRemote->mChannels.begin(), mRemote->mChannels.end(),
                        [&](const LocalChannel *remoteChl) ->bool
                    {
                        return remoteChl->getName() == remoteName;
                    });

                    // did we find our other channel?
                    if (remoteIter != mRemote->mChannels.end())
                    {
                        chl->mRemoteChannel = *remoteIter;
                    }

                }


                if (chl->mRemoteChannel == nullptr)
                {
                    // TODO: maybe do something smarter than a spin lock...
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }

            return *chl;
        }

        void LocalEndpoint::stop()
        {
            {
                std::lock_guard<std::mutex> lock(mChannelsMtx);
                mName = "";
            }


            for (auto& chl : mChannels)
                chl->mDoneFuture.get();

        }
        bool LocalEndpoint::stopped() const
        {
            return mName == "";
        }
    }
}