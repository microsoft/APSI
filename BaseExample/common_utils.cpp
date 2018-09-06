#include "common_utils.h"

// STD
#include <iostream>

#ifdef _MSC_VER
#include "windows.h"
#endif


using namespace std;

void apsi::tools::print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}

/**
 * This only turns on showing colors for Windows.
 */
void apsi::tools::prepare_console()
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
