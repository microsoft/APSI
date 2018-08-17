#include "matrix_tests.h"
#include "apsi/tools/matrixview.h"
#include "apsi/tools/matrix.h"

#include <string>

/**
 * This class only exists to expose the resize method.
 */
template<class T>
class MatrixViewTester : public apsi::MatrixView<T>
{
public:
    MatrixViewTester(T* data, apsi::u64 rows, apsi::u64 cols) :
        apsi::MatrixView<T>(data, rows, cols)
    {}

    void resize_test(T* data, apsi::u64 rows, apsi::u64 cols)
    {
        this->resize(data, rows, cols);
    }
};


void MatrixViewTests::ConstructorTest()
{
    int array[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    apsi::MatrixView mv(array, 2, 5);
    
    CPPUNIT_ASSERT_EQUAL(6, mv(1, 0));
    CPPUNIT_ASSERT_EQUAL(8, mv(1, 2));

    apsi::MatrixView mv2(array, 5, 2);

    CPPUNIT_ASSERT_EQUAL(5, mv2(2, 0));
    CPPUNIT_ASSERT_EQUAL(10, mv2(4, 1));
}

void MatrixViewTests::OperatorAssignTest()
{
    int array[9] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    apsi::MatrixView mv(array, 3, 3);

    apsi::MatrixView<int> mv2;
    CPPUNIT_ASSERT_EQUAL((apsi::u64)0, mv2.rows());
    CPPUNIT_ASSERT_EQUAL((apsi::u64)0, mv2.columns());

    mv2 = mv;
    CPPUNIT_ASSERT_EQUAL((apsi::u64)3, mv2.rows());
    CPPUNIT_ASSERT_EQUAL((apsi::u64)3, mv2.columns());
    CPPUNIT_ASSERT_EQUAL(3, mv2(2, 0));
}

void MatrixViewTests::OperatorBracketTest()
{
    int array[6] = { 1, 2, 3, 4, 5, 6 };
    apsi::MatrixView mv(array, 2, 3);

    CPPUNIT_ASSERT_EQUAL(1, mv[0][0]);
    CPPUNIT_ASSERT_EQUAL(6, mv[1][2]);
    CPPUNIT_ASSERT_EQUAL(3, mv[0][2]);
    CPPUNIT_ASSERT_EQUAL(4, mv[1][0]);

    mv[1][2] = 7;
    CPPUNIT_ASSERT_EQUAL(7, mv[1][2]);
}

void MatrixViewTests::OperatorParenTest()
{
    std::string str = "Hello world!";
    apsi::MatrixView<char> mv(str.data(), 6, 2);

    CPPUNIT_ASSERT_EQUAL('H', mv(0, 0));
    CPPUNIT_ASSERT_EQUAL('!', mv(5, 1));
    CPPUNIT_ASSERT_EQUAL('l', mv(1, 0));

    // We can also use a single index to iterate
    CPPUNIT_ASSERT_EQUAL('H', mv(0));
    CPPUNIT_ASSERT_EQUAL('!', mv(11));
    CPPUNIT_ASSERT_EQUAL('l', mv(2));
    CPPUNIT_ASSERT_EQUAL('l', mv(3));
}

void MatrixViewTests::SizeTest()
{
    int array[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    apsi::MatrixView mv(array, 2, 2);

    // The view _can_ have a smaller size than the actual data.
    CPPUNIT_ASSERT_EQUAL(4, mv[1][1]);
    CPPUNIT_ASSERT_EQUAL((apsi::u64)4, mv.size());
}

void MatrixViewTests::ResizeTest()
{
    int array[20] = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                      11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    MatrixViewTester<int> mv(array, 5, 4);

    CPPUNIT_ASSERT_EQUAL(1, mv(0, 0));
    CPPUNIT_ASSERT_EQUAL(5, mv(1, 0));
    CPPUNIT_ASSERT_EQUAL(9, mv(2, 0));
    CPPUNIT_ASSERT_EQUAL(13, mv(3, 0));
    CPPUNIT_ASSERT_EQUAL(20, mv(4, 3));

    mv.resize_test(array, 4, 5);

    CPPUNIT_ASSERT_EQUAL(1, mv(0, 0));
    CPPUNIT_ASSERT_EQUAL(5, mv(0, 4));
    CPPUNIT_ASSERT_EQUAL(9, mv(1, 3));
    CPPUNIT_ASSERT_EQUAL(13, mv(2, 2));
    CPPUNIT_ASSERT_EQUAL(20, mv(3, 4));
}

void MatrixViewTests::IteratorTest()
{
    int array[10] = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10 };
    apsi::MatrixView mv(array, 5, 2);
    apsi::MatrixView mv2(array, 5, 1);

    apsi::u64 sum = 0;
    apsi::u64 sum2 = 0;

    for(auto& elem : mv)
    {
        sum += elem;
    }

    for (auto& elem : mv2)
    {
        sum2 += elem;
    }

    CPPUNIT_ASSERT_EQUAL((apsi::u64)55, sum);
    CPPUNIT_ASSERT_EQUAL((apsi::u64)15, sum2);
}

void MatrixTests::ResizeTest()
{
    apsi::Matrix<int> m(5, 5);
    for (apsi::u64 i = 0; i < m.rows(); i++)
    {
        for(apsi::u64 j = 0; j < m.columns(); j++)
        {
            m[i][j] = i * m.columns() + j + 1;
        }
    }

    m.resize(10, 10);

    CPPUNIT_ASSERT_EQUAL((apsi::u64)10, m.rows());
    CPPUNIT_ASSERT_EQUAL((apsi::u64)10, m.columns());
    CPPUNIT_ASSERT_EQUAL((apsi::u64)100, m.size());

    // Data should still be there
    CPPUNIT_ASSERT_EQUAL(25, m(2, 4));
    CPPUNIT_ASSERT_EQUAL(10, m(0, 9));
    CPPUNIT_ASSERT_EQUAL(20, m(1, 9));
}

