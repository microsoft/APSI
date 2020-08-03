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
    namespace detail
    {
        template<typename T>
        union SEALObjectUnion
        {
        public:
            typename seal::Serializable<T> serializable;

            T local;

            SEALObjectUnion()
            {
                // Trivial default-constructor; we need to set a value separately
            }

            SEALObjectUnion(const SEALObjectUnion &source)
            {
                // Trivial copy-constructor; we need to copy the value separately
            }

            ~SEALObjectUnion()
            {
            }
        };
    }

    /**
    This object stores SEAL objects that can optionally be wrapper in a seal::Serializable instance, such as
    seal::RelinKeys and seal::Ciphertext. The class defines serialization methods and a getter for extracting
    the wrapped objet.
    */
    template<typename T>
    class SEALObject
    {
    private:
        detail::SEALObjectUnion<T> obj;

        enum class object_type 
        {
            local = 0,

            serializable = 1
        } type;

    public:
        SEALObject()
        {
            obj.local = T{};
            type = object_type::local;
        };

        SEALObject &operator =(SEALObject &&source)
        {
            type = source.type;
            switch (type)
            {
            case object_type::local:
                obj.local = std::move(source.obj.local); 
                break;
            case object_type::serializable:
                obj.serializable = std::move(source.obj.serializable); 
                break;
            }

            return *this;
        }

        SEALObject &operator =(const SEALObject &source)
        {
            type = source.type;
            switch (type)
            {
            case object_type::local:
                obj.local = source.obj.local; 
                break;
            case object_type::serializable:
                obj.serializable = source.obj.serializable; 
                break;
            }

            return *this;
        }

        SEALObject(const SEALObject &source)
        {
            operator =(source);
        }

        SEALObject(SEALObject &&source)
        {
            operator =(std::move(source));
        }

        SEALObject(typename seal::Serializable<T> obj)
        {
            set(std::move(obj));
        }

        SEALObject(T obj)
        {
            set(std::move(obj));
        }

        void set(typename seal::Serializable<T> obj)
        {
            obj.serializable = std::move(obj);
            type = object_type::serializable;
        }

        void set(T obj)
        {
            obj.local = std::move(obj);
            type = object_type::local;
        }

        T extract_local()
        {
            if (type != object_type::local)
            {
                throw std::logic_error("invalid object type");
            }
            return std::move(obj.local);
        }

        typename seal::Serializable<T> extract_serializable()
        {
            if (type != object_type::serializable)
            {
                throw std::logic_error("invalid object type");
            }
            return std::move(obj.serializable);
        }

        std::size_t save(seal::SEAL_BYTE *out, std::size_t size, seal::compr_mode_type compr_mode) const
        {
            switch (type)
            {
                case object_type::local:
                    return seal::util::safe_cast<std::size_t>(obj.local.save(out, size, compr_mode));
                case object_type::serializable:
                    return seal::util::safe_cast<std::size_t>(obj.serializable.save(out, size, compr_mode));
            }
            throw std::logic_error("invalid object type");
        }

        std::size_t save_size(seal::compr_mode_type compr_mode) const
        {
            switch (type)
            {
                case object_type::local:
                    return seal::util::safe_cast<std::size_t>(obj.local.save_size(compr_mode));
                case object_type::serializable:
                    return seal::util::safe_cast<std::size_t>(obj.serializable.save_size(compr_mode));
            }
            throw std::logic_error("invalid object type");
        }

        std::size_t load(std::shared_ptr<seal::SEALContext> context, const seal::SEAL_BYTE *in, std::size_t size)
        {
            type = object_type::local;
            return seal::util::safe_cast<std::size_t>(obj.local.load(std::move(context), in, size));
        }
    };
}
