#pragma once

#include <cppunit/extensions/HelperMacros.h>

class MatrixViewTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(MatrixViewTests);

    CPPUNIT_TEST(ConstructorTest);
    CPPUNIT_TEST(OperatorAssignTest);
    CPPUNIT_TEST(OperatorBracketTest);
    CPPUNIT_TEST(OperatorParenTest);
    CPPUNIT_TEST(SizeTest);
    CPPUNIT_TEST(ResizeTest);

    CPPUNIT_TEST_SUITE_END();

public:
    void ConstructorTest();
    void OperatorAssignTest();
    void OperatorBracketTest();
    void OperatorParenTest();
    void SizeTest();
    void ResizeTest();
};

class MatrixTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(MatrixTests);
    CPPUNIT_TEST(ResizeTest);
    CPPUNIT_TEST_SUITE_END();

public:
    void ResizeTest();
};
