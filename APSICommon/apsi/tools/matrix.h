// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
#include "matrixview.h"

namespace apsi
{
    /**
     * Simple bi-dimensional Matrix.
     * 
     * - Deletes its data when destroyed.
     * - Allows resizing.
     */
    template<class T>
    class Matrix : public MatrixView<T>
    {
    public:
        Matrix() = default;

        Matrix(std::size_t rows, std::size_t cols, std::size_t elt_size = 1)
        {
            resize(rows, cols, elt_size);
        }

        /**
         * Resize the matrix.
         * If the needed capacity exceeds the current capacity, will allocate more
         * memory and preserve existing data.
         * When the needed capacity is less than the current capacity, the memory
         * use will remain the same and the matrix will be reduced only logically.
         */
        void resize(std::size_t newRows, std::size_t newCols, std::size_t elt_size = 1)
        {
            std::size_t newCapacity = newRows * newCols * elt_size;

            if (newCapacity > data_.size())
            {
                data_.resize(newCapacity);
            }

            if (newRows != this->rows() || newCols != this->columns())
            {
                MatrixView<T>::resize(data_.data(), newRows, newCols, elt_size);
            }
        }

    protected:
        /**
         * Get the actual size of the backing vector. This might be different
         * from the logical size, specially if the matrix has been resized.
         */
        std::size_t capacity() const { return data_.size(); }

    private:
        std::vector<T> data_;
    }; // class Matrix
} // namespace apsi
