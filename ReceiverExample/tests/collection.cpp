#include "collection.h"
#include "interpolate_tests.h"

oc::TestCollection apsi_tests([](oc::TestCollection& tc)
{
    tc.add("u64_interpolate_test", u64_interpolate_test);
});