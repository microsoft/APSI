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
#include "aes_tests.h"
#include "prng_tests.h"

#ifdef _MSC_VER
#include "Windows.h"
#endif

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
 * Prepare console for running unit tests.
 * This only turns on showing colors for Windows.
 */
void prepare_console()
{
#ifndef _MSC_VER
    return; // Nothing to do on Linux.
#else

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE)
        return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hConsole, &dwMode))
        return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hConsole, dwMode);

#endif
}

/**
 * Run unit tests
 */
int run_unit_tests()
{
    prepare_console();

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
    runner.addTest(AESTests::suite());
    runner.addTest(PRNGTests::suite());

    runner.run(controller);

    CppUnit::TextOutputter outputter(&result, CppUnit::stdCOut());
    outputter.write();

    return result.wasSuccessful() ? 0 : 1;
}

int main (int argc, char** argv)
{
    return run_unit_tests();
}
