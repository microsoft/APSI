#pragma once

#include <gsl/gsl_assert>
#include <gsl/span>
#include "apsi/apsidefines.h"

namespace apsi
{
    /**
     * Simple bi-dimensional Matrix implementation using gsl::span.
     **/
    template <class T>
    class MatrixView
    {
        // For iterating through the elements in the view
        using iterator = gsl::details::span_iterator<gsl::span<T>, false>;

    public:
        MatrixView() = default;

        MatrixView(T *elems, std::size_t rows, std::size_t cols, std::size_t elt_size = 1)
            : data_(gsl::span<T>(elems, rows * cols * elt_size)), rows_(rows), cols_(cols), elt_size_(elt_size)
        {}

        /**
         * Return a subspan with a row in the matrix. Useful for accesing
         * elements like so: matrix[row][col]
         */
        constexpr gsl::span<T> operator[](std::size_t row)
        {
            Expects(row < rows_);
            return data_.subspan(
                /* offset */ row * stride(),
                /* count */ stride());
        }

        /**
         * Initialize this matrix from another matrix.
         */
        constexpr MatrixView &operator=(const MatrixView &other)
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
        T *operator()(std::size_t index)
        {
            Expects(index < (rows_ * cols_));
            return data_.data() + index * elt_size_;
        }

        /**
         * Allows accesing elements like so: matrix(row, col)
         */
        T *operator()(std::size_t row, std::size_t col) const
        {
            Expects(row < rows_);
            Expects(col < cols_);
            std::size_t raw_index = row * stride() + col * elt_size_;
            return data_.data() + raw_index;
        }

        /**
         * Get the stride
         */
        std::size_t stride() const
        {
            return cols_ * elt_size_;
        }

        /**
         * Get the rows
         */
        std::size_t rows() const
        {
            return rows_;
        }

        /**
         * Get the columns
         */
        std::size_t columns() const
        {
            return cols_;
        }

        /**
         * Get a pointer to the actual data
         */
        T *data() const
        {
            return data_.data();
        }

        /**
         * Get the number of elements
         */
        std::size_t size() const
        {
            return data_.size();
        }

        /**
         * Get initial iterator
         */
        iterator begin() const
        {
            return data_.begin();
        }

        /**
         * Get ending iterator
         */
        iterator end() const
        {
            return data_.end();
        }

    protected:
        /**
         * Re-initialize the view.
         */
        void resize(T *data, std::size_t rows, std::size_t cols, std::size_t elt_size)
        {
            rows_ = rows;
            cols_ = cols;
            elt_size_ = elt_size;
            data_ = gsl::span<T>(data, rows * cols * elt_size_);
        }

    private:
        gsl::span<T> data_;
        std::size_t rows_ = 0;
        std::size_t cols_ = 0;
        std::size_t elt_size_;
    }; // class MatrixView
} // namespace apsi
