#include "unit_tests_runner.h"
#include <cppunit/TextTestRunner.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestFailure.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TextOutputter.h>
#include <iomanip>
#include <string>

#include "bit_copy_test.h"
#include "interpolate_tests.h"
#include "matrix_tests.h"
#include "plaintextarith.h"

namespace APSITests {

namespace {
    struct Colors {
        static const std::string Red;
        static const std::string Green;
        static const std::string RedBold;
        static const std::string GreenBold;
        static const std::string Reset;
    };

    const std::string Colors::Red       = "\033[31m";
    const std::string Colors::Green     = "\033[32m";
    const std::string Colors::RedBold   = "\033[1;31m";
    const std::string Colors::GreenBold = "\033[1;32m";
    const std::string Colors::Reset     = "\033[0m";
}

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
        testResult_ = Colors::GreenBold + "OK       " + Colors::Reset;
    }

    void addFailure(const CppUnit::TestFailure& failure)
    {
        testResult_ = Colors::RedBold + (failure.isError() ? "ERROR    " : "ASSERTION") + Colors::Reset;
    }

    void endTest(CppUnit::Test* test)
    {
        CppUnit::stdCOut() << testResult_ << ": " << test->getName() << std::endl;
    }

private:
    std::string testResult_;
};

}

using namespace APSITests;

/**
 * Run unit tests
 */
int run_unit_tests()
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    ProgressListener progress;
    CppUnit::TextTestRunner runner;

    controller.addListener(&result);
    controller.addListener(&progress);

    runner.addTest(MatrixViewTests::suite());
    runner.addTest(MatrixTests::suite());
    runner.addTest(BitCopyTests::suite());
    runner.addTest(InterpolateTests::suite());
    runner.addTest(TestPlainArith::suite());

    runner.run(controller);

    CppUnit::TextOutputter outputter(&result, CppUnit::stdCOut());
    outputter.write();

    return result.wasSuccessful() ? 0 : 1;
}

int main (int argc, char** argv)
{
    return run_unit_tests();
}
