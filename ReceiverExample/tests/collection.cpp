#include "collection.h"
#include "interpolate_tests.h"
void bit_copy_test();

oc::TestCollection apsi_tests([](oc::TestCollection& tc)
{
    tc.add("u64_interpolate_test  ", u64_interpolate_test);
    tc.add("bit_copy_test         ", bit_copy_test);
});