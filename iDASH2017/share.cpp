#include "share.h"
#include "plaintextarith.h"
#include "Network/network_utils.h"

using namespace apsi::network;
using namespace seal;
using namespace std;

namespace idash
{
    Share::Share(Plaintext &&plain_share, shared_ptr<Channel> channel)
        : plain_share_(move(plain_share)), channel_(move(channel))
    {

    }

    Share Share::add(const Share &operand2) const
    {
        Share result(Plaintext(), channel_);
        idash::add(plain_share_, operand2.plain_share_, poly_mod_, coeff_mod_, result.plain_share_);
        return result;
    }

    Share Share::sub(const Share &operand2) const
    {
        Share result(Plaintext(), channel_);
        idash::sub(plain_share_, operand2.plain_share_, poly_mod_, coeff_mod_, result.plain_share_);
        return result;
    }

    Share Share::multiply(const Share &operand2, const Triplet &triplet, int share_of_one) const
    {
        Share result(Plaintext(), channel_);

        Share e_share = sub(triplet.a),
            f_share = operand2.sub(triplet.b);
        Plaintext e = e_share.reconstruct(),
            f = f_share.reconstruct();

        idash::multiply(f, triplet.a.plain_share_, poly_mod_, coeff_mod_, result.plain_share_);
        idash::add(result.plain_share_,
            idash::multiply(e, triplet.b.plain_share_, poly_mod_, coeff_mod_),
            poly_mod_, coeff_mod_, result.plain_share_);
        idash::add(result.plain_share_, triplet.c.plain_share_, poly_mod_, coeff_mod_, result.plain_share_);

        /* The following can be changed to handle more than 2 parties. But for the moment, I just use two parties. */
        if (share_of_one == 1)
        {
            idash::add(result.plain_share_,
                idash::multiply(e, f, poly_mod_, coeff_mod_),
                poly_mod_, coeff_mod_, result.plain_share_);
        }
        return result;
    }

    Plaintext Share::reconstruct()
    {
        Plaintext result;

        send_plaintext(plain_share_, *channel_);
        Plaintext other_share;
        receive_plaintext(other_share, *channel_);
        idash::add(plain_share_, other_share, poly_mod_, coeff_mod_, result);

        return result;
    }
}