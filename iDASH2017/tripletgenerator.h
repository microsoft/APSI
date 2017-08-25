#pragma once

#include "secretkey.h"
#include "publickey.h"
#include "evaluationkeys.h"
#include "Network/channel.h"
#include "context.h"
#include "encryptor.h"
#include "decryptor.h"
#include "evaluator.h"
#include "util/exfieldpolycrt.h"
#include "share.h"

namespace idash
{
    class Triplet;

    class TripletGenerator
    {
    public:
        TripletGenerator(const seal::SEALContext &context,
            std::shared_ptr<seal::util::ExField> ex_field,
            std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> ex_builder,
            std::shared_ptr<apsi::network::Channel> channel,
            bool secret_holder);

        void generate(Triplet &triplet);

        void encrypt(const Share &a0, const Share &b0);

        void evaluate(const Share &a1, const Share &b1, const seal::Plaintext &r);

        void decrypt(seal::Plaintext &d);

    private:
        seal::SecretKey secret_key_;

        std::unique_ptr<seal::Decryptor> decryptor_;
        
        seal::PublicKey public_key_;

        std::unique_ptr<seal::Encryptor> encryptor_;

        std::unique_ptr<seal::Evaluator> evaluator_;

        std::shared_ptr<seal::util::ExFieldPolyCRTBuilder> ex_builder_;

        std::shared_ptr<seal::util::ExField> ex_field_;

        std::shared_ptr<apsi::network::Channel> channel_;

        seal::util::PolyModulus poly_mod_;

        seal::SmallModulus small_mod_;

        bool secret_holder_;

        /* Pointers to temporary memory. */
        std::vector<seal::util::Pointer> memory_backing_;
    };

    /**
    Multiplication triplet. Sharing semantics: c = a * b;
    */
    class Triplet
    {
    public:
        Share a;
        Share b;
        Share c;
    };
}