// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>

// SEAL
#include "seal/context.h"
#include "seal/serializable.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"

// GSL
#include "gsl/span"

namespace apsi {
    /**
    This object stores SEAL objects that can optionally be wrapper in a seal::Serializable instance,
    such as seal::RelinKeys and seal::Ciphertext. The class defines serialization methods and a
    getter for extracting the wrapped object.
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
            local_.reset();
            serializable_.reset();
            if (assign.is_local() && !assign.is_serializable()) {
                local_ = std::make_unique<LocalType>(*assign.local_);
            } else if (!assign.is_local() && assign.is_serializable()) {
                serializable_ = std::make_unique<SerializableType>(*assign.serializable_);
            } else if (assign.is_local() && assign.is_serializable()) {
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
        }

        bool is_local() const
        {
            return !!local_;
        }

        bool is_serializable() const
        {
            return !!serializable_;
        }

        explicit operator bool() const
        {
            return is_local() || is_serializable();
        }

        void set(LocalType &&value)
        {
            serializable_.reset();
            local_ = std::make_unique<LocalType>(std::move(value));
        }

        void set(const LocalType &value)
        {
            serializable_.reset();
            local_ = std::make_unique<LocalType>(value);
        }

        void set(SerializableType &&value)
        {
            local_.reset();
            serializable_ = std::make_unique<SerializableType>(std::move(value));
        }

        void set(const SerializableType &value)
        {
            local_.reset();
            serializable_ = std::make_unique<SerializableType>(value);
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

        LocalType extract(std::shared_ptr<seal::SEALContext> context)
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
            } else {
                throw std::logic_error("no object to extract");
            }

            return ret;
        }

        std::size_t save(gsl::span<unsigned char> out, seal::compr_mode_type compr_mode) const
        {
            std::size_t size = out.size();
            seal::seal_byte *out_ptr = reinterpret_cast<seal::seal_byte *>(out.data());

            if (is_local() && !is_serializable()) {
                return seal::util::safe_cast<std::size_t>(local_->save(out_ptr, size, compr_mode));
            } else if (!is_local() && is_serializable()) {
                return seal::util::safe_cast<std::size_t>(
                    serializable_->save(out_ptr, size, compr_mode));
            }
            return 0;
        }

        std::size_t save_size(seal::compr_mode_type compr_mode) const
        {
            if (is_local() && !is_serializable()) {
                return seal::util::safe_cast<std::size_t>(local_->save_size(compr_mode));
            } else if (!is_local() && is_serializable()) {
                return seal::util::safe_cast<std::size_t>(serializable_->save_size(compr_mode));
            }
            return 0;
        }

        std::size_t load(
            std::shared_ptr<seal::SEALContext> context, gsl::span<const unsigned char> in)
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
    };
} // namespace apsi
