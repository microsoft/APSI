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
        SEALObject() = default;

        SEALObject(SEALObject &&source) = default;

        SEALObject &operator =(SEALObject &&assign) = default;

        SEALObject &operator =(const SEALObject &assign)
        {
            local_.reset();
            serializable_.reset();
            if (assign.is_local() && !assign.is_serializable())
            {
                local_ = std::make_unique<T>(*assign.local_);
            }
            else if (!assign.is_local() && assign.is_serializable())
            {
                serializable_ = std::make_unique<seal::Serializable<T>>(*assign.serializable_);
            }
            else if (assign.is_local() && assign.is_serializable())
            {
                throw std::invalid_argument("source is in an invalid state");
            }
        }

        SEALObject(const SEALObject &source)
        {
            operator =(source);
        }

        SEALObject(typename seal::Serializable<T> obj)
        {
            set(std::move(obj));
        }

        SEALObject(T obj)
        {
            set(std::move(obj));
        }

        bool is_local() const
        {
            return !!local_;
        }

        bool is_serializable() const
        {
            return !!serializable_;
        }

        void set(T &&value)
        {
            serializable_.reset();
            local_ = std::make_unique<T>(std::move(value));
        }

        void set(const T &value)
        {
            serializable_.reset();
            local_ = std::make_unique<T>(value);
        }

        void set(seal::Serializable<T> &&value)
        {
            local_.reset();
            serializable_ = std::make_unique<T>(std::move(value));
        }

        void set(const seal::Serializable<T> &value)
        {
            local_.reset();
            serializable_ = std::make_unique<T>(value);
        }

        seal::Serializable<T> extract_serializable()
        {
            if (!is_serializable())
            {
                throw std::logic_error("no serializable object to extract");
            }
            auto ptr = std::make_unique<seal::Serializable<T>>();
            std::swap(ptr, local_);
            return std::move(*ptr);
        }

        T extract_local()
        {
            if (!is_local())
            {
                throw std::logic_error("no local object to extract");
            }
            auto ptr = std::make_unique<T>();
            std::swap(ptr, local_);
            return std::move(*ptr);
        }

        std::size_t save(seal::SEAL_BYTE *out, std::size_t size, seal::compr_mode_type compr_mode) const
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

        std::size_t load(std::shared_ptr<seal::SEALContext> context, const seal::SEAL_BYTE *in, std::size_t size)
        {
            set(T());
            return seal::util::safe_cast<std::size_t>(local_->load(std::move(context), in, size));
        }

    private:
        std::unique_ptr<typename seal::Serializable<T>> serializable_ = nullptr;

        std::unique_ptr<T> local_ = nullptr;
    };
}
