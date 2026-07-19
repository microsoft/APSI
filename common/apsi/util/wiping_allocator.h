// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <memory>

namespace apsi::util {
    // Forward declaration of apsi::util::secure_zero. The full declaration plus
    // definition live in apsi/util/utils.{h,cpp}. We avoid #include'ing utils.h here
    // because utils.h pulls in apsi/item.h, and item.h needs to include this header
    // to expose LabelKeyVector (including utils.h here would create a cycle.
    void secure_zero(void *ptr, std::size_t count) noexcept;

    /**
    Stateless allocator that calls apsi::util::secure_zero on the underlying buffer
    before forwarding to std::allocator<T>::deallocate.
    */
    template <typename T>
    class wiping_allocator {
    public:
        using value_type = T;

        wiping_allocator() noexcept = default;

        template <typename U>
        wiping_allocator(const wiping_allocator<U> &) noexcept
        {}

        T *allocate(std::size_t n)
        {
            return std::allocator<T>{}.allocate(n);
        }

        void deallocate(T *p, std::size_t n) noexcept
        {
            if (p && n) {
                secure_zero(p, n * sizeof(T));
            }
            std::allocator<T>{}.deallocate(p, n);
        }
    };

    // All instances of wiping_allocator are stateless and interchangeable, so they
    // compare equal regardless of T. This matters for std::vector's allocator-traits
    // propagation (copy/move-assignment between vectors built with the same T but
    // different instantiations would otherwise need careful handling).
    template <typename T, typename U>
    bool operator==(const wiping_allocator<T> &, const wiping_allocator<U> &) noexcept
    {
        return true;
    }

    template <typename T, typename U>
    bool operator!=(const wiping_allocator<T> &, const wiping_allocator<U> &) noexcept
    {
        return false;
    }
} // namespace apsi::util
