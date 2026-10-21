// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <algorithm>
#include <cstddef>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

// SEAL
#include "seal/context.h"
#include "seal/serializable.h"
#include "seal/util/common.h"

// GSL
#include "gsl/span"

namespace apsi {
    /**
    This object stores SEAL objects that can optionally be wrapped in a seal::Serializable instance,
    such as seal::RelinKeys and seal::Ciphertext. The class defines serialization methods and a
    getter for extracting the wrapped object.

    A SEALObject can also hold an object in serialized form: the bytes of one object as SEAL saves
    it (see set_serialized). Such an object is loaded, and validated against a SEALContext, only
    when it is extracted. SEAL compresses what it saves, so a few bytes can load as a large object.
    network::SenderOperationQuery::load holds the query ciphertexts this way, so that sender::Query
    can check that there are as many as the parameters call for before loading any of them.
    */
    template <typename T>
    class SEALObject {
    public:
        using SerializableType = typename seal::Serializable<T>;

        using LocalType = T;

        SEALObject() = default;

        SEALObject(SEALObject &&source) = default;

        SEALObject &operator=(SEALObject &&assign) = default;

        SEALObject &operator=(const SEALObject &assign)
        {
            if (this == &assign) {
                return *this;
            }
            local_.reset();
            serializable_.reset();
            serialized_.reset();
            if (assign.is_local() && !assign.is_serializable() && !assign.is_serialized()) {
                local_ = std::make_unique<LocalType>(*assign.local_);
            } else if (!assign.is_local() && assign.is_serializable() && !assign.is_serialized()) {
                serializable_ = std::make_unique<SerializableType>(*assign.serializable_);
            } else if (!assign.is_local() && !assign.is_serializable() && assign.is_serialized()) {
                serialized_ = std::make_unique<std::vector<unsigned char>>(*assign.serialized_);
            } else if (assign) {
                throw std::invalid_argument("source is in an invalid state");
            }
            return *this;
        }

        SEALObject(const SEALObject &source)
        {
            operator=(source);
        }

        SEALObject(SerializableType obj)
        {
            operator=(std::move(obj));
        }

        SEALObject(LocalType obj)
        {
            operator=(std::move(obj));
        }

        SEALObject &operator=(const LocalType &obj)
        {
            set(obj);
            return *this;
        }

        SEALObject &operator=(const SerializableType &obj)
        {
            set(obj);
            return *this;
        }

        SEALObject &operator=(LocalType &&obj)
        {
            set(std::move(obj));
            return *this;
        }

        SEALObject &operator=(SerializableType &&obj)
        {
            set(std::move(obj));
            return *this;
        }

        void clear()
        {
            serializable_.reset();
            local_.reset();
            serialized_.reset();
        }

        [[nodiscard]] bool is_local() const
        {
            return !!local_;
        }

        [[nodiscard]] bool is_serializable() const
        {
            return !!serializable_;
        }

        /**
        Returns true if the object is held in serialized form (see set_serialized).
        */
        [[nodiscard]] bool is_serialized() const
        {
            return !!serialized_;
        }

        explicit operator bool() const
        {
            return is_local() || is_serializable() || is_serialized();
        }

        void set(LocalType &&value)
        {
            serializable_.reset();
            serialized_.reset();
            local_ = std::make_unique<LocalType>(std::move(value));
        }

        void set(const LocalType &value)
        {
            serializable_.reset();
            serialized_.reset();
            local_ = std::make_unique<LocalType>(value);
        }

        void set(SerializableType &&value)
        {
            local_.reset();
            serialized_.reset();
            serializable_ = std::make_unique<SerializableType>(std::move(value));
        }

        void set(const SerializableType &value)
        {
            local_.reset();
            serialized_.reset();
            serializable_ = std::make_unique<SerializableType>(value);
        }

        /**
        Holds the object in serialized form, as a copy of the given bytes, which should be one
        object as SEAL saves it. Nothing is loaded or validated here, so this accepts any bytes;
        extract loads and validates them, and throws if they are not a valid object.
        */
        void set_serialized(gsl::span<const unsigned char> in)
        {
            local_.reset();
            serializable_.reset();
            serialized_ = std::make_unique<std::vector<unsigned char>>(in.begin(), in.end());
        }

        SerializableType extract_if_serializable()
        {
            if (!is_serializable()) {
                throw std::logic_error("no serializable object to extract");
            }
            SerializableType result = std::move(*serializable_);
            serializable_.reset();
            return result;
        }

        LocalType extract_if_local()
        {
            if (!is_local()) {
                throw std::logic_error("no local object to extract");
            }
            LocalType result = std::move(*local_);
            local_.reset();
            return result;
        }

        /**
        Returns the object and leaves this SEALObject empty. An object held in serialized form is
        loaded with T::load, which validates it against the given SEALContext; if that throws,
        this throws the same exception and this SEALObject is left unchanged.

        Throws std::invalid_argument if the object is not local and context is null, and
        std::logic_error if this SEALObject is empty.
        */
        LocalType extract(const std::shared_ptr<seal::SEALContext> &context)
        {
            LocalType ret;
            if (is_local()) {
                ret = extract_if_local();
            } else if (is_serializable()) {
                if (!context) {
                    throw std::invalid_argument("context cannot be null");
                }

                SerializableType ser = extract_if_serializable();
                std::stringstream ss;
                ser.save(ss, seal::compr_mode_type::none);
                ret.unsafe_load(*context, ss);
            } else if (is_serialized()) {
                if (!context) {
                    throw std::invalid_argument("context cannot be null");
                }

                // Unlike a seal::Serializable, which this process created, these bytes may come
                // from anywhere, so they are loaded with full validation.
                ret.load(
                    *context,
                    reinterpret_cast<const seal::seal_byte *>(serialized_->data()),
                    serialized_->size());
                serialized_.reset();
            } else {
                throw std::logic_error("no object to extract");
            }

            return ret;
        }

        /**
        Writes the object to the given buffer in the given compression mode and returns the number
        of bytes written. An object held in serialized form is written as the bytes it is held as,
        so for it the compression mode has no effect.

        Throws std::invalid_argument if the object is held in serialized form and out is smaller
        than save_size returns.
        */
        // save() writes through the output span, so its byte-count return may be ignored.
        // NOLINTNEXTLINE(modernize-use-nodiscard)
        std::size_t save(gsl::span<unsigned char> out, seal::compr_mode_type compr_mode) const
        {
            std::size_t size = out.size();
            seal::seal_byte *out_ptr = reinterpret_cast<seal::seal_byte *>(out.data());

            if (is_local() && !is_serializable() && !is_serialized()) {
                return seal::util::safe_cast<std::size_t>(local_->save(out_ptr, size, compr_mode));
            }
            if (!is_local() && is_serializable() && !is_serialized()) {
                return seal::util::safe_cast<std::size_t>(
                    serializable_->save(out_ptr, size, compr_mode));
            }
            if (!is_local() && !is_serializable() && is_serialized()) {
                if (size < serialized_->size()) {
                    throw std::invalid_argument("insufficient size");
                }
                std::copy(serialized_->cbegin(), serialized_->cend(), out.begin());
                return serialized_->size();
            }
            return 0;
        }

        /**
        Returns an upper bound on the number of bytes save writes in the given compression mode.
        For an object held in serialized form this is the number of bytes it is held as, whatever
        the compression mode.
        */
        [[nodiscard]] std::size_t save_size(seal::compr_mode_type compr_mode) const
        {
            if (is_local() && !is_serializable() && !is_serialized()) {
                return seal::util::safe_cast<std::size_t>(local_->save_size(compr_mode));
            }
            if (!is_local() && is_serializable() && !is_serialized()) {
                return seal::util::safe_cast<std::size_t>(serializable_->save_size(compr_mode));
            }
            if (!is_local() && !is_serializable() && is_serialized()) {
                return serialized_->size();
            }
            return 0;
        }

        std::size_t load(
            const std::shared_ptr<seal::SEALContext> &context, gsl::span<const unsigned char> in)
        {
            if (!context) {
                throw std::invalid_argument("context cannot be null");
            }

            std::size_t size = in.size();
            const seal::seal_byte *in_ptr = reinterpret_cast<const seal::seal_byte *>(in.data());

            set(LocalType());
            return seal::util::safe_cast<std::size_t>(
                local_->load(std::move(*context), in_ptr, size));
        }

    private:
        std::unique_ptr<SerializableType> serializable_ = nullptr;

        std::unique_ptr<LocalType> local_ = nullptr;

        std::unique_ptr<std::vector<unsigned char>> serialized_ = nullptr;
    };
} // namespace apsi
