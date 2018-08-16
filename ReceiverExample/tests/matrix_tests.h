#pragma once

#include <cppunit/extensions/HelperMacros.h>
#include "apsi/tools/matrixview.h"

class MatrixViewTests : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(MatrixViewTests);
    CPPUNIT_TEST(ConstructorTest);
    CPPUNIT_TEST(OperatorAssignTest);
    CPPUNIT_TEST(OperatorBracketTest);
    CPPUNIT_TEST(OperatorParenTest);
    CPPUNIT_TEST_SUITE_END();

public:
    void ConstructorTest();
    void OperatorAssignTest();
    void OperatorBracketTest();
    void OperatorParenTest();
};
