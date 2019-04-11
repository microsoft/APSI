#pragma once

#include <cppunit/extensions/HelperMacros.h>

namespace APSITests {

class MatrixViewTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(MatrixViewTests);

    CPPUNIT_TEST(ConstructorTest);
    CPPUNIT_TEST(OperatorAssignTest);
    CPPUNIT_TEST(OperatorBracketTest);
    CPPUNIT_TEST(OperatorParenTest);
    CPPUNIT_TEST(SizeTest);
    CPPUNIT_TEST(ResizeTest);
    CPPUNIT_TEST(IteratorTest);

    CPPUNIT_TEST_SUITE_END();

public:
    void ConstructorTest();
    void OperatorAssignTest();
    void OperatorBracketTest();
    void OperatorParenTest();
    void SizeTest();
    void ResizeTest();
    void IteratorTest();
};

class MatrixTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(MatrixTests);
    CPPUNIT_TEST(ResizeTest);
    CPPUNIT_TEST_SUITE_END();

public:
    void ResizeTest();
};

}
