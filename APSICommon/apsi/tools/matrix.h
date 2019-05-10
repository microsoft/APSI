#pragma once

#include "matrixview.h"
#include <vector>

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

    Matrix(u64 rows, u64 cols)
    {
        resize(rows, cols);
    }

    /**
     * Resize the matrix.
     * If the needed capacity exceeds the current capacity, will allocate more
     * memory and preserve existing data.
     * When the needed capacity is less than the current capacity, the memory
     * use will remain the same and the matrix will be reduced only logically.
     */
    void resize(u64 newRows, u64 newCols)
    {
        u64 newCapacity = newRows * newCols;

        if (newCapacity > data_.size())
        {
            data_.resize(newCapacity);
        }

        if (newRows != this->rows() || newCols != this->columns())
        {
            MatrixView<T>::resize(data_.data(), newRows, newCols);
        }
    }

protected:
    /**
     * Get the actual size of the backing vector. This might be different
     * from the logical size, specially if the matrix has been resized.
     */
    u64 capacity() const { return data_.size(); }

private:
    std::vector<T> data_;
};

}
