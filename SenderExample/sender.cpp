#include "sender.h"
#include "apsi.h"
#include <iostream>
#include <string>
#include "Sender/sender.h"
#include "util/exfield.h"
#include "apsidefines.h"
#include "Network/network_utils.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace seal::util;
using namespace seal;

void print_example_banner(string title);
void example_remote();

int main(int argc, char *argv[])
{
    // Example: Remote
    example_remote();

    // Wait for ENTER before closing screen.
    cout << endl << "Press ENTER to exit" << endl;
    char ignore;
    cin.get(ignore);
    return 0;
}

void example_remote()
{
    throw std::runtime_error("NOT IMPL");
}

void print_example_banner(string title)
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