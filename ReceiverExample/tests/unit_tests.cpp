#include "unit_tests.h"
#include <test.h>

#include "bit_copy_test.h"
#include "interpolate_tests.h"

/**
 * Run unit tests
 */
void run_unit_tests()
{
    try
    {
        TEST_WAIT(false);

        TEST(bit_copy_test());
        TEST(u64_interpolate_test());

        TEST_SUMMARY;
    }
    catch(...)
    {
        TEST_EXCEPTION;
    }
}
