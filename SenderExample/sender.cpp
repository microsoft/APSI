#include "sender.h"

// STD
#include <iostream>
#include <string>

// APSI
#include "clp.h"
#include "apsi/sender/sender.h"
#include "common_utils.h"

using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::sender;


void example_remote(const CLP& cmd);


int main(int argc, char *argv[])
{
    prepare_console();

    CLP cmd("Example of a Sender implementation");
    if (!cmd.parse_args(argc, argv))
        return -1;

    // Example: Remote
    example_remote(cmd);

    // Wait for ENTER before closing screen.
    cout << endl << "Press ENTER to exit" << endl;
    char ignore;
    cin.get(ignore);
    return 0;
}

void example_remote(const CLP& cmd)
{
    print_example_banner("Remote Sender");
}

