#include "unit_tests.h"
#include <cppunit/TextTestRunner.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestFailure.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TextOutputter.h>

#include "bit_copy_test.h"
#include "interpolate_tests.h"
#include "matrix_tests.h"

namespace apsi {
namespace test {

/**
 * Simple Test Listener class to output each unit test run
 */
class ProgressListener : public CppUnit::TestListener
{
public:
    ProgressListener() = default;
    ~ProgressListener() = default;

    void startTest(CppUnit::Test* test)
    {
        CppUnit::stdCOut() << test->getName();
        CppUnit::stdCOut() << "\n";
        CppUnit::stdCOut().flush();
        lastTestFailed_ = false;
    }

    void addFailure(const CppUnit::TestFailure& failure)
    {
        CppUnit::stdCOut() << " : " << (failure.isError() ? "error" : "assertion");
        lastTestFailed_ = true;
    }

    void endTest(CppUnit::Test* test)
    {
        if (!lastTestFailed_)
        {
            CppUnit::stdCOut() << " : OK";
        }
        CppUnit::stdCOut() << "\n";
    }

private:
    bool lastTestFailed_;
};

}
}
/**
 * Run unit tests
 */
void run_unit_tests()
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    apsi::test::ProgressListener progress;
    CppUnit::TextTestRunner runner;

    controller.addListener(&result);
    controller.addListener(&progress);

    runner.addTest(MatrixViewTests::suite());
    runner.addTest(BitCopyTests::suite());
    runner.addTest(InterpolateTests::suite());

    runner.run(controller);

    CppUnit::TextOutputter outputter(&result, CppUnit::stdCOut());
    outputter.write();
}
