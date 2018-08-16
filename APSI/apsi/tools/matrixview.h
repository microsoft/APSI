#pragma once

#include "apsi/apsidefines.h"
#include <gsl/span>

namespace apsi
{
    // For now this is necessary to distinguish the standard span class from the one
    // included in cryptoTools. Once cryptoTools is removed this can go away.
    template<typename T> using msspan = gsl::span<T>;

    /**
     * Simple bi-dimensional Matrix implementation using gsl::span.
     **/
    template<class T>
    class MatrixView
    {
    public:
        MatrixView() = default;

        MatrixView(T* elems, u64 rows, u64 cols) :
            data_(msspan<T>(elems, rows * cols)),
            rows_(rows),
            cols_(cols)
        {
        }

        /**
         * Return a subspan with a row in the matrix. Useful for accesing
         * elements like so: matrix[row][col]
         */
        constexpr msspan<T> operator[] (u64 row)
        {
            return data_.subspan(/* offset */ row * stride(), /* count */ stride());
        }

        /**
         * Initialize this matrix from another matrix.
         */
        constexpr MatrixView& operator=(const MatrixView& other)
        {
            rows_ = other.rows_;
            cols_ = other.cols_;
            data_ = other.data_;

            return *this;
        }

        /**
         * Allows accesing elements like so: matrix(row, col)
         */
        T& operator()(u64 row, u64 col) const
        {
            u64 index = row * stride() + col;
            return data_[index];
        }

        /**
         * Get the stride
         */
        u64 stride() const { return cols_; }

        /**
         * Get the rows
         */
        u64 rows() const { return rows_; }

        /**
         * Get the columns
         */
        u64 columns() const { return cols_; }

        /**
         * Get a pointer to the actual data
         */
        T* data() { return data_.data(); }

    private:
        msspan<T> data_;
        u64 rows_;
        u64 cols_;
    };
}