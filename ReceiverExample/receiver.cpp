#include "receiver.h"
#include "hipsi.h"
#include <iostream>
#include <string>

using namespace std;
using namespace hipsi;

int main(int argc, char *argv[])
{
	tools::Stopwatch watch;
	tools::CLP clp(argc, argv);
	watch.set_time_point("Processed parms");
	cout << "Moi kaikille!" << endl;
	watch.set_time_point("Printed message");

	cout << watch;

	return 0;
}