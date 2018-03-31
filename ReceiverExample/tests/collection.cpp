#include "collection.h"
#include "interpolate_tests.h"

oc::TestCollection apsi_tests([](oc::TestCollection& tc)
{
    tc.add("plaintext_interpolate_test", plaintext_interpolate_test);
});