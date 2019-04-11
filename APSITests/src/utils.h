#pragma once

#define ASSERT_THROWS(expr) \
    { \
        bool exception_thrown = false; \
        try \
        { \
            CPPUNIT_ASSERT(!exception_thrown); \
            expr; \
        } \
        catch(...) \
        { \
            exception_thrown = true; \
        } \
        CPPUNIT_ASSERT_MESSAGE("Exception should have been thrown.", exception_thrown); \
    }
