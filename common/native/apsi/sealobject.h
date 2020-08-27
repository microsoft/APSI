// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <iostream>
#include <utility>
#include <memory>

// SEAL
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/context.h"
#include "seal/serializable.h"

namespace apsi
{
    /**
    This object stores SEAL objects that can optionally be wrapper in a seal::Serializable instance, such as
    seal::RelinKeys and seal::Ciphertext. The class defines serialization methods and a getter for extracting
    the wrapped object.
    */
    template<typename T>
    class SEALObject
    {
    public:
        using SerializableType = typename seal::Serializable<T>;

        using LocalType = T;

        SEALObject() = default;

        SEALObject(SEALObject &&source) = default;

        SEALObject &operator =(SEALObject &&assign) = default;

        SEALObject &operator =(const SEALObject &assign)
        {
            local_.reset();
            serializable_.reset();
            if (assign.is_local() && !assign.is_serializable())
            {
                local_ = std::make_unique<LocalType>(*assign.local_);
            }
            else if (!assign.is_local() && assign.is_serializable())
            {
                serializable_ = std::make_unique<SerializableType>(*assign.serializable_);
            }
            else if (assign.is_local() && assign.is_serializable())
            {
                throw std::invalid_argument("source is in an invalid state");
            }
            return *this;
        }

        SEALObject(const SEALObject &source)
        {
            operator =(source);
        }

        SEALObject(SerializableType obj)
        {
            operator =(std::move(obj));
        }

        SEALObject(LocalType obj)
        {
            operator =(std::move(obj));
        }

        SEALObject &operator =(const LocalType &obj)
        {
            set(obj);
            return *this;
        }

        SEALObject &operator =(const SerializableType &obj)
        {
            set(obj);
            return *this;
        }

        SEALObject &operator =(LocalType &&obj)
        {
            set(std::move(obj));
            return *this;
        }

        SEALObject &operator =(SerializableType &&obj)
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

        SerializableType extract_serializable()
        {
            if (!is_serializable())
            {
                throw std::logic_error("no serializable object to extract");
            }
            SerializableType result = std::move(*serializable_);
            serializable_.reset();
            return std::move(result);
        }

        LocalType extract_local()
        {
            if (!is_local())
            {
                throw std::logic_error("no local object to extract");
            }
            LocalType result = std::move(*local_);
            local_.reset();
            return std::move(result);
        }

        std::size_t save(seal::seal_byte *out, std::size_t size, seal::compr_mode_type compr_mode) const
        {
            if (is_local() && !is_serializable())
            {
                return seal::util::safe_cast<std::size_t>(local_->save(out, size, compr_mode));
            }
            else if (!is_local() && is_serializable())
            {
                return seal::util::safe_cast<std::size_t>(serializable_->save(out, size, compr_mode));
            }
            throw std::invalid_argument("object is in an invalid state");
        }

        std::size_t save_size(seal::compr_mode_type compr_mode) const
        {
            if (is_local() && !is_serializable())
            {
                return seal::util::safe_cast<std::size_t>(local_->save_size(compr_mode));
            }
            else if (!is_local() && is_serializable())
            {
                return seal::util::safe_cast<std::size_t>(serializable_->save_size(compr_mode));
            }
            throw std::invalid_argument("object is in an invalid state");
        }

        std::size_t load(std::shared_ptr<seal::SEALContext> context, const seal::seal_byte *in, std::size_t size)
        {
            set(LocalType());
            return seal::util::safe_cast<std::size_t>(local_->load(std::move(*context), in, size));
        }

    private:
        std::unique_ptr<SerializableType> serializable_ = nullptr;

        std::unique_ptr<LocalType> local_ = nullptr;
    };
}
