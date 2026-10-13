// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <utility>
#include <vector>

// APSI
#include "apsi/seal_object.h"

// SEAL
#include "seal/batchencoder.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include "seal/relinkeys.h"
#include "seal/serializable.h"
#include "seal/serialization.h"

// GSL
#include "gsl/span"

// Google Test
#include "gtest/gtest.h"

using namespace std;
using namespace seal;
using namespace apsi;

namespace APSITests {
    namespace {
        shared_ptr<SEALContext> make_context(size_t poly_modulus_degree = 4096)
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(poly_modulus_degree);
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
            parms.set_plain_modulus(65537);
            return make_shared<SEALContext>(parms);
        }

        vector<compr_mode_type> supported_compr_modes()
        {
            vector<compr_mode_type> compr_modes;
            for (unsigned value = 0; value <= 0xFF; value++) {
                if (Serialization::IsSupportedComprMode(static_cast<uint8_t>(value))) {
                    compr_modes.push_back(static_cast<compr_mode_type>(value));
                }
            }
            return compr_modes;
        }

        /**
        Returns the bytes Microsoft SEAL saves the object as, for a local object or a
        seal::Serializable alike.
        */
        template <typename T>
        vector<unsigned char> seal_save(const T &obj, compr_mode_type compr_mode)
        {
            vector<unsigned char> bytes(static_cast<size_t>(obj.save_size(compr_mode)));
            auto size =
                obj.save(reinterpret_cast<seal_byte *>(bytes.data()), bytes.size(), compr_mode);
            bytes.resize(static_cast<size_t>(size));
            return bytes;
        }

        /**
        Returns the bytes a SEALObject saves its object as.
        */
        template <typename T>
        vector<unsigned char> apsi_save(const SEALObject<T> &obj, compr_mode_type compr_mode)
        {
            vector<unsigned char> bytes(obj.save_size(compr_mode));
            bytes.resize(obj.save(bytes, compr_mode));
            return bytes;
        }

        /**
        Returns the type and message of the exception the function throws, or an empty string if
        it throws none.
        */
        template <typename Function>
        string thrown(Function function)
        {
            try {
                function();
            } catch (const exception &ex) {
                return string(typeid(ex).name()) + ": " + ex.what();
            }
            return {};
        }

        /**
        A secret key with the means to encrypt and decrypt known values under it.
        */
        class Encryption {
        public:
            explicit Encryption(shared_ptr<SEALContext> context)
                : context_(std::move(context)), keygen_(*context_),
                  encryptor_(*context_, keygen_.secret_key()),
                  decryptor_(*context_, keygen_.secret_key()), encoder_(*context_),
                  values_(encoder_.slot_count())
            {
                iota(values_.begin(), values_.end(), static_cast<uint64_t>(1));
                encoder_.encode(values_, plain_);
            }

            [[nodiscard]] Ciphertext encrypt() const
            {
                Ciphertext ct;
                encryptor_.encrypt_symmetric(plain_, ct);
                return ct;
            }

            [[nodiscard]] Serializable<Ciphertext> encrypt_seeded() const
            {
                return encryptor_.encrypt_symmetric(plain_);
            }

            [[nodiscard]] bool decrypts_to_values(const Ciphertext &ct)
            {
                Plaintext plain;
                decryptor_.decrypt(ct, plain);
                vector<uint64_t> values;
                encoder_.decode(plain, values);
                return values == values_;
            }

            [[nodiscard]] KeyGenerator &keygen() noexcept
            {
                return keygen_;
            }

        private:
            shared_ptr<SEALContext> context_;

            KeyGenerator keygen_;

            Encryptor encryptor_;

            Decryptor decryptor_;

            BatchEncoder encoder_;

            vector<uint64_t> values_;

            Plaintext plain_;
        };
    } // namespace

    TEST(SEALObjectTests, SerializedObjectIsLoadedWhenExtracted)
    {
        auto context = make_context();
        Encryption encryption(context);

        Ciphertext ct = encryption.encrypt();
        vector<unsigned char> expected = seal_save(ct, compr_mode_type::none);

        // A ciphertext saved in any mode, as a receiver may send it
        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(static_cast<int>(compr_mode));

            SEALObject<Ciphertext> obj;
            obj.set_serialized(seal_save(ct, compr_mode));
            ASSERT_TRUE(obj.is_serialized());
            ASSERT_FALSE(obj.is_local());
            ASSERT_FALSE(obj.is_serializable());
            ASSERT_TRUE(obj);

            Ciphertext extracted = obj.extract(context);
            ASSERT_EQ(expected, seal_save(extracted, compr_mode_type::none));
            ASSERT_TRUE(encryption.decrypts_to_values(extracted));

            // Extracting empties the object, as it does an object in any other form
            ASSERT_FALSE(obj.is_serialized());
            ASSERT_FALSE(obj);
            ASSERT_THROW((void)obj.extract(context), logic_error);
        }

        // A seeded ciphertext, which is what a receiver sends, expands as it is loaded
        SEALObject<Ciphertext> seeded;
        seeded.set_serialized(seal_save(encryption.encrypt_seeded(), compr_mode_type::none));
        ASSERT_TRUE(encryption.decrypts_to_values(seeded.extract(context)));

        // Any kind of object
        RelinKeys relin_keys;
        encryption.keygen().create_relin_keys(relin_keys);
        SEALObject<RelinKeys> relin_keys_obj;
        relin_keys_obj.set_serialized(seal_save(relin_keys, Serialization::compr_mode_default));
        ASSERT_EQ(
            seal_save(relin_keys, compr_mode_type::none),
            seal_save(relin_keys_obj.extract(context), compr_mode_type::none));
    }

    TEST(SEALObjectTests, SerializedObjectThatIsNotValidThrowsWhenExtracted)
    {
        auto context = make_context();
        Encryption encryption(context);
        vector<unsigned char> valid = seal_save(encryption.encrypt(), compr_mode_type::none);

        // A ciphertext for other encryption parameters is a valid object, but not for this
        // context
        Encryption other_encryption(make_context(8192));
        vector<unsigned char> for_other_context =
            seal_save(other_encryption.encrypt(), compr_mode_type::none);

        // A ciphertext with a coefficient that is not reduced modulo its prime has the right
        // shape, and only a full validation finds it out
        Ciphertext unreduced = encryption.encrypt();
        unreduced.data()[0] = ~static_cast<uint64_t>(0);
        vector<unsigned char> unreduced_bytes = seal_save(unreduced, compr_mode_type::none);

        vector<vector<unsigned char>> invalid{
            {},
            vector<unsigned char>(100, 0x5A),
            vector<unsigned char>(valid.begin(), valid.begin() + 16),
            vector<unsigned char>(valid.begin(), valid.end() - 1),
            for_other_context,
            unreduced_bytes,
        };
        for (const auto &bytes : invalid) {
            SCOPED_TRACE(bytes.size());

            SEALObject<Ciphertext> obj;
            obj.set_serialized(bytes);
            ASSERT_TRUE(obj.is_serialized());

            // Extracting throws exactly what Microsoft SEAL throws for the bytes
            string seal_throws = thrown([&] {
                Ciphertext ct;
                ct.load(*context, reinterpret_cast<const seal_byte *>(bytes.data()), bytes.size());
            });
            ASSERT_FALSE(seal_throws.empty());
            ASSERT_EQ(seal_throws, thrown([&] { (void)obj.extract(context); }));
            ASSERT_THROW((void)obj.extract(context), logic_error);

            // The object is left as it was
            ASSERT_TRUE(obj.is_serialized());
            ASSERT_EQ(bytes, apsi_save(obj, compr_mode_type::none));
        }

        // Extracting needs a context, and without one the object is left as it was too
        SEALObject<Ciphertext> obj;
        obj.set_serialized(valid);
        ASSERT_THROW((void)obj.extract(nullptr), invalid_argument);
        ASSERT_TRUE(obj.is_serialized());
        ASSERT_TRUE(encryption.decrypts_to_values(obj.extract(context)));
    }

    TEST(SEALObjectTests, SerializedObjectIsSavedAsItIsHeld)
    {
        auto context = make_context();
        Encryption encryption(context);

        // Saved in one mode, held, and then saved in every mode
        vector<unsigned char> bytes =
            seal_save(encryption.encrypt_seeded(), Serialization::compr_mode_default);
        SEALObject<Ciphertext> obj;
        obj.set_serialized(bytes);
        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(static_cast<int>(compr_mode));
            ASSERT_EQ(bytes.size(), obj.save_size(compr_mode));
            ASSERT_EQ(bytes, apsi_save(obj, compr_mode));
        }

        // Nothing is loaded to save it, so bytes that are not an object at all are saved as well
        vector<unsigned char> garbage(100, 0x5A);
        obj.set_serialized(garbage);
        ASSERT_EQ(garbage, apsi_save(obj, Serialization::compr_mode_default));

        // A buffer that is too small is refused rather than overrun
        vector<unsigned char> too_small(garbage.size() - 1);
        ASSERT_THROW((void)obj.save(too_small, compr_mode_type::none), invalid_argument);

        // Saving leaves the object as it was
        ASSERT_TRUE(obj.is_serialized());
        ASSERT_EQ(garbage, apsi_save(obj, compr_mode_type::none));
    }

    TEST(SEALObjectTests, LocalAndSerializableObjectsAreSavedAsMicrosoftSEALSavesThem)
    {
        // A receiver's query is saved through SEALObject::save, so this is what keeps its bytes as
        // APSI 1.x saves them: those Microsoft SEAL writes for the same objects
        auto context = make_context();
        Encryption encryption(context);
        Ciphertext ct = encryption.encrypt();
        Serializable<Ciphertext> seeded = encryption.encrypt_seeded();

        for (compr_mode_type compr_mode : supported_compr_modes()) {
            SCOPED_TRACE(static_cast<int>(compr_mode));
            ASSERT_EQ(seal_save(ct, compr_mode), apsi_save(SEALObject<Ciphertext>(ct), compr_mode));
            ASSERT_EQ(
                seal_save(seeded, compr_mode),
                apsi_save(SEALObject<Ciphertext>(seeded), compr_mode));
        }
    }

    TEST(SEALObjectTests, SerializedObjectIsCopiedMovedAndReplaced)
    {
        auto context = make_context();
        Encryption encryption(context);
        Ciphertext ct = encryption.encrypt();
        vector<unsigned char> bytes = seal_save(ct, Serialization::compr_mode_default);

        // An empty object
        SEALObject<Ciphertext> obj;
        ASSERT_FALSE(obj.is_serialized());
        ASSERT_FALSE(obj);
        ASSERT_EQ(size_t(0), obj.save_size(compr_mode_type::none));

        // Even no bytes at all are held as an object, which fails only once it is extracted
        obj.set_serialized({});
        ASSERT_TRUE(obj.is_serialized());
        ASSERT_TRUE(obj);
        ASSERT_EQ(size_t(0), obj.save_size(compr_mode_type::none));

        obj.set_serialized(bytes);

        // Copies hold the same bytes
        SEALObject<Ciphertext> copy(obj);
        ASSERT_TRUE(copy.is_serialized());
        ASSERT_EQ(bytes, apsi_save(copy, compr_mode_type::none));
        SEALObject<Ciphertext> assigned;
        assigned = obj;
        ASSERT_TRUE(assigned.is_serialized());
        ASSERT_EQ(bytes, apsi_save(assigned, compr_mode_type::none));
        ASSERT_TRUE(obj.is_serialized());

        // Moving leaves the source empty
        SEALObject<Ciphertext> moved(std::move(copy));
        ASSERT_TRUE(moved.is_serialized());
        ASSERT_EQ(bytes, apsi_save(moved, compr_mode_type::none));
        ASSERT_FALSE(copy); // NOLINT(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
        SEALObject<Ciphertext> move_assigned;
        move_assigned = std::move(moved);
        ASSERT_TRUE(move_assigned.is_serialized());
        ASSERT_FALSE(moved); // NOLINT(bugprone-use-after-move,clang-analyzer-cplusplus.Move)

        // Each way of setting the object replaces the bytes, and holding bytes replaces each
        assigned.set(ct);
        ASSERT_TRUE(assigned.is_local());
        ASSERT_FALSE(assigned.is_serialized());
        assigned.set_serialized(bytes);
        ASSERT_TRUE(assigned.is_serialized());
        ASSERT_FALSE(assigned.is_local());

        assigned.set(encryption.encrypt_seeded());
        ASSERT_TRUE(assigned.is_serializable());
        ASSERT_FALSE(assigned.is_serialized());
        assigned.set_serialized(bytes);
        ASSERT_TRUE(assigned.is_serialized());
        ASSERT_FALSE(assigned.is_serializable());

        assigned.load(context, bytes);
        ASSERT_TRUE(assigned.is_local());
        ASSERT_FALSE(assigned.is_serialized());

        // Assigning an object in another form replaces the bytes as well
        move_assigned = assigned;
        ASSERT_TRUE(move_assigned.is_local());
        ASSERT_FALSE(move_assigned.is_serialized());
        move_assigned = obj;
        ASSERT_TRUE(move_assigned.is_serialized());
        ASSERT_FALSE(move_assigned.is_local());

        obj.clear();
        ASSERT_FALSE(obj.is_serialized());
        ASSERT_FALSE(obj);
    }
} // namespace APSITests
