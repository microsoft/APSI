#include "tripletgenerator.h"
#include "Network/network_utils.h"
#include "keygenerator.h"
#include "plaintextarith.h"

using namespace apsi::network;
using namespace std;
using namespace seal;
using namespace seal::util;

namespace idash
{
    TripletGenerator::TripletGenerator(const SEALContext &context,
        shared_ptr<ExField> ex_field,
        shared_ptr<ExFieldPolyCRTBuilder> ex_builder,
        shared_ptr<Channel> channel,
        bool secret_holder)
        : ex_field_(move(ex_field)), ex_builder_(move(ex_builder)), channel_(move(channel)), secret_holder_(secret_holder)
    {
        if (secret_holder_)
        {
            KeyGenerator generator(context);
            generator.generate();

            public_key_ = generator.public_key();
            secret_key_ = generator.secret_key();

            send_pubkey(public_key_, *channel);

            encryptor_.reset(new Encryptor(context, public_key_));
            decryptor_.reset(new Decryptor(context, secret_key_));
        }
        else
        {
            receive_pubkey(public_key_, *channel);

            encryptor_.reset(new Encryptor(context, public_key_));
        }

        const BigPoly& poly = context.poly_modulus();
        poly_mod_ = PolyModulus(poly.pointer(), poly.significant_coeff_count(), 1);
        small_mod_ = context.plain_modulus();
    }

    void TripletGenerator::generate(Triplet &triplet)
    {
        int slot_count = ex_builder_->slot_count();

        Pointer backing_a;
        vector<ExFieldElement> ex_a = ex_field_->allocate_elements(slot_count, backing_a);
        Pointer backing_b;
        vector<ExFieldElement> ex_b = ex_field_->allocate_elements(slot_count, backing_b);
        Pointer backing_c;
        vector<ExFieldElement> ex_c = ex_field_->allocate_elements(slot_count, backing_c);

        for (int i = 0; i < slot_count; i++)
        {
            ex_field_->random_element(ex_a[i]);
            ex_field_->random_element(ex_b[i]);
        }

        ex_builder_->compose(ex_a, triplet.a.plain_share_);
        ex_builder_->compose(ex_b, triplet.b.plain_share_);
        multiply(triplet.a.plain_share_, triplet.b.plain_share_, poly_mod_, small_mod_, triplet.c.plain_share_, ex_field_->pool());
        if (secret_holder_)
        {
            encrypt(triplet.a, triplet.b);
            Plaintext d;
            decrypt(d);

            add(triplet.c.plain_share_, d, poly_mod_, small_mod_, triplet.c.plain_share_, ex_field_->pool());
        }
        else
        {
            Pointer backing_r;
            vector<ExFieldElement> ex_r = ex_field_->allocate_elements(slot_count, backing_r);
            Plaintext r = ex_builder_->compose(ex_r);

            sub(triplet.c.plain_share_, r, poly_mod_, small_mod_, triplet.c.plain_share_, ex_field_->pool());
            evaluate(triplet.a, triplet.b, r);
        }
    }

    void TripletGenerator::encrypt(const Share &a0, const Share &b0)
    {
        if (!secret_holder_)
            throw logic_error("Cannot call encrypt.");

        send_ciphertext(encryptor_->encrypt(a0.plain_share_), *channel_);
        send_ciphertext(encryptor_->encrypt(b0.plain_share_), *channel_);
    }

    void TripletGenerator::evaluate(const Share &a1, const Share &b1, const Plaintext &r)
    {
        if (secret_holder_)
            throw logic_error("Cannot call evaluate.");
        
        Ciphertext enc_a0, enc_b0;
        receive_ciphertext(enc_a0, *channel_);
        receive_ciphertext(enc_b0, *channel_);

        vector<Ciphertext> tmps;
        tmps.emplace_back(evaluator_->multiply_plain(enc_a0, b1.plain_share_));
        tmps.emplace_back(evaluator_->multiply_plain(enc_b0, a1.plain_share_));
        tmps.emplace_back(encryptor_->encrypt(r));
        Ciphertext d = evaluator_->add_many(tmps);
        send_ciphertext(d, *channel_);
    }

    void TripletGenerator::decrypt(Plaintext &d)
    {
        if (!secret_holder_)
            throw logic_error("Cannot call decrypt.");

        Ciphertext enc_d;
        receive_ciphertext(enc_d, *channel_);

        d = decryptor_->decrypt(enc_d);
    }
}