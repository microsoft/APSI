#pragma once

#include "matrixview.h"
#include <vector>

namespace apsi
{
using namespace std;

/**
 * Simple bi-dimensional Matrix.
 * 
 * - Deletes its data when destroyed.
 * - Allows resizing
 */
template<class T>
class Matrix : public MatrixView<T>
{
public:
    Matrix() = default;

    Matrix(u64 rows, u64 cols) :
        capacity_(0)
    {
        resize(rows, cols);
    }

    void resize(u64 newRows, u64 newCols)
    {
        u64 newCapacity = newRows * newCols;

        if (newCapacity > capacity_)
        {
            data_.resize(newCapacity);
            capacity_ = newCapacity;
        }

        if (newRows != this->rows() || newCols != this->columns())
        {
            MatrixView<T>::resize(data_.data(), newRows, newCols);
        }

        capacity_ = newCapacity;
    }

private:
    u64 capacity_;
    vector<T> data_;
};

}
