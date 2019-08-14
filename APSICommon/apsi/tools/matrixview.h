#pragma once

#include "apsi/apsidefines.h"
#include <gsl/span>
#include <gsl/gsl_assert>

namespace apsi
{
    /**
     * Simple bi-dimensional Matrix implementation using gsl::span.
     **/
    template<class T>
    class MatrixView
    {
        // For iterating through the elements in the view
        using iterator = gsl::details::span_iterator<gsl::span<T>, false>;

    public:
        MatrixView() = default;

        MatrixView(T* elems, u64 rows, u64 cols, std::size_t elt_size = 1) :
            data_(gsl::span<T>(elems, rows * cols * elt_size)),
            rows_(rows),
            cols_(cols),
            elt_size_(elt_size)
        {
        }

        /**
         * Return a subspan with a row in the matrix. Useful for accesing
         * elements like so: matrix[row][col]
         */
        constexpr gsl::span<T> operator[] (u64 row)
        {
            Expects(row < rows_);
            return data_.subspan(
                /* offset */ row * stride(),
                /* count */ stride());
        }

        /**
         * Initialize this matrix from another matrix.
         */
        constexpr MatrixView& operator=(const MatrixView& other)
        {
            rows_ = other.rows_;
            cols_ = other.cols_;
            data_ = other.data_;
            elt_size_ = other.elt_size_;

            return *this;
        }

        /**
         * Allows accessing elements through a single index
         */
        T *operator()(u64 index)
        {
            Expects(index < (rows_ * cols_));
            return data_.data() + index * elt_size_;
        }

        /**
         * Allows accesing elements like so: matrix(row, col)
         */
        T *operator()(u64 row, u64 col) const
        {
            Expects(row < rows_);
            Expects(col < cols_);
            u64 raw_index = row * stride() + col * elt_size_;
            return data_.data() + raw_index;
        }

        /**
         * Get the stride
         */
        u64 stride() const { return cols_ * elt_size_; }

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
        T* data() const { return data_.data(); }

        /**
         * Get the number of elements
         */
        u64 size() const { return data_.size(); }

        /**
         * Get initial iterator
         */
        iterator begin() const { return data_.begin(); }

        /**
         * Get ending iterator
         */
        iterator end() const { return data_.end(); }

    protected:
        /**
         * Re-initialize the view.
         */
        void resize(T* data, u64 rows, u64 cols, std::size_t elt_size)
        {
            rows_ = rows;
            cols_ = cols;
            elt_size_ = elt_size;
            data_ = gsl::span<T>(data, rows * cols * elt_size_);
        }

    private:
        gsl::span<T> data_;
        u64 rows_ = 0;
        u64 cols_ = 0;
        std::size_t elt_size_;
    };
}
