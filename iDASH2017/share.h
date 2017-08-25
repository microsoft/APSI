#pragma once

#include "plaintext.h"
#include "Network/channel.h"
#include "tripletgenerator.h"

namespace idash
{
    class Share
    {
    public:

        Share(seal::Plaintext &&plain_share, std::shared_ptr<apsi::network::Channel> channel);

        Share(Share &&other) = default;

        Share add(const Share &operand2) const;

        Share sub(const Share &operand2) const;

        Share multiply(const Share &operand2, const Triplet &triplet, int share_of_one) const;

        seal::Plaintext reconstruct();

        static void set_poly_mod(const seal::util::PolyModulus &poly_mod)
        {
            poly_mod_ = poly_mod;
        }

        static void set_coeff_mod(const seal::SmallModulus &coeff_mod)
        {
            coeff_mod_ = coeff_mod;
        }


    private:
        seal::Plaintext plain_share_;

        std::shared_ptr<apsi::network::Channel> channel_;

        /* We assume anyone using this sharing system would just use same poly modulus and coeff modulus all the time,
        which makes sense in most scenarios. We make these two static so that we don't need to copy them in so many shares. */

        static seal::util::PolyModulus poly_mod_;

        static seal::SmallModulus coeff_mod_;

        friend class TripletGenerator;
    };
}