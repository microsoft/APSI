#pragma once 

#include <vector>
#include <utility>
#include "apsi/apsidefines.h"
#include <apsi/item.h>
#include "apsi/tools/matrix.h"
#include "apsi/psiparams.h"
#include "cppunit/extensions/HelperMacros.h"

namespace APSITests
{
    class SenderReceiverTests : public CppUnit::TestFixture
    {
        CPPUNIT_TEST_SUITE(SenderReceiverTests);

        CPPUNIT_TEST(OPRFandLabelsTest);
        CPPUNIT_TEST(OPRFTest);
        CPPUNIT_TEST(LabelsTest);
        CPPUNIT_TEST(NoOPRFNoLabelsTest);

        CPPUNIT_TEST_SUITE_END();

    public:
        void OPRFandLabelsTest();
        void OPRFTest();
        void LabelsTest();
        void NoOPRFNoLabelsTest();

    private:
        apsi::PSIParams create_params(size_t sender_set_size, bool use_oprf, bool use_labels);
        void initialize_db(std::vector<apsi::Item>& items, apsi::Matrix<apsi::u8>& labels, size_t item_count, unsigned label_byte_count = 0);
        void initialize_query(std::vector<apsi::Item>& items, size_t item_count);
        void verify_intersection_results(std::vector<apsi::Item>& client_items, int intersection_size, std::pair<std::vector<bool>, apsi::Matrix<apsi::u8>>& intersection, bool compare_labels, std::vector<int>& label_idx, apsi::Matrix<apsi::u8>& labels);

        void RunTest(size_t senderActualSize, apsi::PSIParams& params);
    };
}
