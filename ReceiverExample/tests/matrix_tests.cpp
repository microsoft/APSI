#include "matrix_tests.h"
#include <string>

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
}
