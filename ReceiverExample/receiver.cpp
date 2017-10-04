#include "receiver.h"
#include "apsi.h"
#include <iostream>
#include <string>
#include "Sender/sender.h"
#include "util/exfield.h"
#include "util/uintcore.h"
#include "apsidefines.h"
#include <fstream>

using namespace std;
using namespace apsi;
using namespace apsi::tools;
using namespace apsi::receiver;
using namespace apsi::sender;
using namespace seal::util;
using namespace seal;

void print_example_banner(string title);
void example_basics();
void example_update();
void example_save_db();
void example_load_db();
void example_fast_batching();
void example_slow_batching();
void example_slow_vs_fast();
void example_remote();
void example_remote_multiple();


int main(int argc, char *argv[])
{
    // Example: Basics
    //example_basics();

    //// Example: Update
    //example_update();

    //// Example: Save and Load
    //example_save_db();
    //example_load_db();

    //// Example: Fast batching
    example_fast_batching();

    //// Example: Slow batching
    //example_slow_batching();

    // Example: Slow batching vs. Fast batching
    //example_slow_vs_fast();

    // Example: Remote connection
    //example_remote();

    // Example: Remote connection from multiple receivers
    //example_remote_multiple();

    // Wait for ENTER before closing screen.
    cout << endl << "Press ENTER to exit" << endl;
    char ignore;
    cin.get(ignore);
    return 0;
}

void example_basics()
{
    print_example_banner("Example: Basics");
    stop_watch.time_points.clear();

    /* sender total threads (8), sender session threads (8), receiver threads (1),
    table size (2^8=256), sender bin size (32), window size (2), splits (4). */
    PSIParams params(8, 8, 1, 8, 32, 2, 4);

    /* 
    Item's bit length. In this example, we will only consider 32 bits of input items. 
    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
    */
    params.set_item_bit_length(32);  

    params.set_decomposition_bit_count(2);

    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
    params.set_log_poly_degree(11);

    /* The prime p in ExField. It is also the plain modulus in SEAL. */
    params.set_exfield_characteristic(0x101);

    /* f(x) in ExField. It determines the generalized batching slots. */
    params.set_exfield_polymod(string("1x^16 + 3"));

    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
    params.set_coeff_mod_bit_count(60);

    params.validate();

    Receiver receiver(params, MemoryPoolHandle::New(true));

    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.
    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
    stop_watch.set_time_point("Precomputation done");

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
    stop_watch.set_time_point("Query done");
    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    /* We can also use integers to construct the items.
    In this example, because params set item bit length to be 32, it will only use the first 32 bits of the input integers. */
    sender.load_db(vector<Item>{10, 12, 89, 33, 123, 352, 4, 236});
    stop_watch.set_time_point("Precomputation done");

    intersection = receiver.query({78, 12, 84, 784, 3, 352}, sender);
    stop_watch.set_time_point("Query done");
    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    cout << stop_watch << endl;
}

void example_update()
{
    print_example_banner("Example: Update");
    stop_watch.time_points.clear();

    PSIParams params(8, 8, 1, 8, 32, 2, 4);
    params.set_item_bit_length(32);
    params.set_decomposition_bit_count(2);
    params.set_log_poly_degree(11);
    params.set_exfield_characteristic(0x101);
    params.set_exfield_polymod(string("1x^16 + 3"));
    params.set_coeff_mod_bit_count(60);  // SEAL param: when n = 2048, q has 60 bits.
    params.validate();
    Receiver receiver(params, MemoryPoolHandle::New(true));

    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.set_secret_key(receiver.secret_key());
    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
    stop_watch.set_time_point("Precomputation done");

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
    stop_watch.set_time_point("Query done");
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    /* Now we update the database, and precompute again. It should be faster because we only update a few stale blocks. */
    sender.add_data(string("i"));
    sender.add_data(string("h")); // duplicated item
    sender.add_data(string("x"));
    //sender.offline_compute();
    stop_watch.set_time_point("Update done");

    intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
    stop_watch.set_time_point("Query done");
    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    /* We can also delete items in the database. */
    sender.delete_data(string("1")); // Item will be ignored if it doesn't exist in the database.
    sender.delete_data(string("f"));
    //sender.offline_compute();
    stop_watch.set_time_point("Delete done");

    intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
    stop_watch.set_time_point("Query done");
    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    cout << stop_watch << endl;
}

void example_save_db()
{
    print_example_banner("Example: Save DB");
    stop_watch.time_points.clear();

    PSIParams params(4, 4, 1, 14, 3584, 1, 256);
    params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
    params.set_exfield_polymod(string("1x^1")); // f(x) = x
    params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
    params.set_log_poly_degree(14); /* n = 2^14 = 16384, in SEAL's poly modulus "x^n + 1". */
    params.set_coeff_mod_bit_count(226);  // SEAL param: when n = 16384, q has 189 or 226 bits.
    params.set_decomposition_bit_count(46);
    params.validate();

    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;

    if (params.reduced_item_bit_length() >= get_significant_bit_count(params.exfield_characteristic()))
    {
        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params.exfield_characteristic()) - 1 << " bits." << endl;
    }
    else
    {
        cout << "All bits of reduced items are used." << endl;
    }

    Receiver receiver(params, MemoryPoolHandle::New(true));
    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.

    stop_watch.set_time_point("Application preparation");
    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
    stop_watch.set_time_point("Sender pre-processing");

    ofstream ofs("apsi.sender.db", ofstream::out | ofstream::binary); // Must use binary mode
    sender.save_db(ofs);
    ofs.close();
    stop_watch.set_time_point("Sender DB saved");

    cout << stop_watch << endl;
}

void example_load_db()
{
    print_example_banner("Example: Load DB");
    stop_watch.time_points.clear();

    PSIParams params(4, 4, 1, 14, 3584, 1, 256);
    params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
    params.set_exfield_polymod(string("1x^1")); // f(x) = x
    params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
    params.set_log_poly_degree(14); /* n = 2^14 = 16384, in SEAL's poly modulus "x^n + 1". */
    params.set_coeff_mod_bit_count(226);  // SEAL param: when n = 16384, q has 189 or 226 bits.
    params.set_decomposition_bit_count(46);
    params.validate();

    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;

    if (params.reduced_item_bit_length() >= get_significant_bit_count(params.exfield_characteristic()))
    {
        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params.exfield_characteristic()) - 1 << " bits." << endl;
    }
    else
    {
        cout << "All bits of reduced items are used." << endl;
    }

    Receiver receiver(params, MemoryPoolHandle::New(true));
    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.

    stop_watch.set_time_point("Application preparation");

    ifstream ifs("apsi.sender.db", ifstream::in | ifstream::binary); // Must use binary mode
    sender.load_db(ifs);
    ifs.close();
    stop_watch.set_time_point("Sender DB loaded");

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);

    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    /* Try update database. */
    sender.delete_data(string("1")); // Item will be ignored if it doesn't exist in the database.
    sender.delete_data(string("f"));
    stop_watch.set_time_point("Delete done");

    intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);
    stop_watch.set_time_point("Query done");
    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    cout << stop_watch << endl;
}

void example_fast_batching()
{
    print_example_banner("Example: Fast batching");
    stop_watch.time_points.clear();

    /* Use generalized batching in integer mode. This requires using an ExField with f(x) = x and r = 1, which makes ExField becomes an integer field.
    Then the generalized batching is essentially equivalent to SEAL's PolyCRTBuilder, which is slightly faster due to David Harvey's optimization of
    NTT butterfly operation on integers.
    
    However, in this case, we can only use short PSI items such that the reduced item length is smaller than bit length of 'p' in ExField (also the 
    plain modulus in SEAL). "Reduced item" refers to the permutation-based cuckoo hashing items.
    */

    //PSIParams params(4, 4, 1, 13, 112, 3, 8);
    //params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
    //params.set_exfield_polymod(string("1x^1")); // f(x) = x
    //params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
    //params.set_log_poly_degree(13); /* n = 2^13 = 8192, in SEAL's poly modulus "x^n + 1". */
    //params.set_coeff_mod_bit_count(189);  // SEAL param: when n = 8192, q has 189 or 226 bits.
    //params.set_decomposition_bit_count(48);

    PSIParams params(8, 8, 1, 14, 3584, 1, 256);
    params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
    params.set_exfield_polymod(string("1x^1")); // f(x) = x
    params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
    params.set_log_poly_degree(14); /* n = 2^14 = 16384, in SEAL's poly modulus "x^n + 1". */
    params.set_coeff_mod_bit_count(226);  // SEAL param: when n = 16384, q has 189 or 226 bits.
    params.set_decomposition_bit_count(60);
    params.validate();
    
    //PSIParams params(1, 1, 1, 13, 80, 1, 16);
    //params.set_item_bit_length(32); // The effective item bit length will be limited by ExField's p.
    //params.set_exfield_polymod(string("1x^1")); // f(x) = x
    //params.set_exfield_characteristic(0x820001); // p = 8519681. NOTE: p=1 (mod 2n)
    //params.set_log_poly_degree(13); /* n = 2^14 = 16384, in SEAL's poly modulus "x^n + 1". */
    //params.set_coeff_mod_bit_count(189);  // SEAL param: when n = 16384, q has 189 or 226 bits.
    //params.set_decomposition_bit_count(60);
    //params.validate();

    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;

    if (params.reduced_item_bit_length() >= get_significant_bit_count(params.exfield_characteristic()))
    {
        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params.exfield_characteristic()) - 1 << " bits." << endl;
    }
    else
    {
        cout << "All bits of reduced items are used." << endl;
    }

    Receiver receiver(params, MemoryPoolHandle::New(true));
    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.

    stop_watch.set_time_point("Application preparation");
    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
    stop_watch.set_time_point("Sender pre-processing");

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);

    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;


    /* Test different update performance. */
    /*vector<int> updates{1, 10, 30, 50, 70, 100};
    random_device rd;
    for (int i = 0; i < updates.size(); i++)
    {
        vector<Item> items;
        for (int j = 0; j < updates[i]; j++)
            items.emplace_back(to_string(rd()));
        sender.add_data(items);
        sender.offline_compute();

        stop_watch.set_time_point(string("Add ") + to_string(updates[i]) + " records done");
    }*/

    cout << stop_watch << endl;
}

void example_slow_batching()
{
    print_example_banner("Example: Slow batching");
    stop_watch.time_points.clear();

    /* Use generalized batching. */

    //PSIParams params(1, 1, 1, 10, 448, 1, 32);
    //params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    //params.set_exfield_polymod(string("1x^8 + 3"));
    //params.set_exfield_characteristic(0xE801);
    //params.set_log_poly_degree(13);
    //params.set_coeff_mod_bit_count(189); 
    //params.set_decomposition_bit_count(60);
    //params.validate();

    //PSIParams params(1, 1, 1, 9, 896, 1, 64);
    //params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    //params.set_exfield_polymod(string("1x^8 + 7"));
    //params.set_exfield_characteristic(0x3401);
    //params.set_log_poly_degree(12);
    //params.set_coeff_mod_bit_count(189); 
    //params.set_decomposition_bit_count(60);
    //params.validate();

    //PSIParams params(1, 1, 1, 8, 1792, 1, 128);
    //params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    //params.set_exfield_polymod(string("1x^8 + 7"));
    //params.set_exfield_characteristic(0x3401);
    //params.set_log_poly_degree(12);
    //params.set_coeff_mod_bit_count(189); 
    //params.set_decomposition_bit_count(60);
    //params.validate();

    PSIParams params(8, 8, 1, 10, 3968, 1, 128);
    params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    params.set_exfield_polymod(string("1x^8 + 3"));
    params.set_exfield_characteristic(0xE801);
    params.set_log_poly_degree(13);
    params.set_coeff_mod_bit_count(189);
    params.set_decomposition_bit_count(60);
    params.validate();

    //PSIParams params(1, 1, 1, 9, 7936, 1, 256);
    //params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    //params.set_exfield_polymod(string("1x^8 + 7"));
    //params.set_exfield_characteristic(0x3401);
    //params.set_log_poly_degree(12);
    //params.set_coeff_mod_bit_count(189);
    //params.set_decomposition_bit_count(60);
    //params.validate();

    //PSIParams params(8, 8, 1, 10, 52736, 2, 256);
    //params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    //params.set_exfield_polymod(string("1x^8 + 3"));
    //params.set_exfield_characteristic(0xE801);
    //params.set_log_poly_degree(13);
    //params.set_coeff_mod_bit_count(189);
    //params.set_decomposition_bit_count(60);
    //params.validate();

    //PSIParams params(2, 2, 1, 10, 13056, 2, 256);
    //params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    //params.set_exfield_polymod(string("1x^8 + 3"));
    //params.set_exfield_characteristic(0xE801);
    //params.set_log_poly_degree(13);
    //params.set_coeff_mod_bit_count(189);
    //params.set_decomposition_bit_count(60);
    //params.validate();

    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;

    if (params.reduced_item_bit_length() >
        (get_significant_bit_count(params.exfield_characteristic()) - 1) * (params.exfield_polymod().coeff_count() - 1))
    {
        cout << "Reduced items too long. We will only use the first " << (get_significant_bit_count(params.exfield_characteristic()) - 1) * (params.exfield_polymod().coeff_count() - 1) << " bits." << endl;
    }
    else
    {
        cout << "All bits of reduced items are used." << endl;
    }

    Receiver receiver(params, MemoryPoolHandle::New(true));
    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.set_secret_key(receiver.secret_key());  // This should not be used in real application. Here we use it for outputing noise budget.

    stop_watch.set_time_point("Application preparation");
    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});
    stop_watch.set_time_point("Sender pre-processing");

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);

    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    cout << stop_watch << endl;
}

void example_slow_vs_fast()
{
    print_example_banner("Example: Slow batching vs. Fast batching");
    stop_watch.time_points.clear();

    /* The slow batching case. We are using an ExField with f(x) of degree higher than 1, which results in fewer batching slots and thus 
    potentially more batches to be processed. The following table size is 4096, number of batching slots is 512, hence we have 8 batches. 
    In exchange, we could handle very long items. */
    PSIParams params(8, 8, 1, 12, 128, 2, 8);
    params.set_item_bit_length(90); // We can handle very long items in the following ExField.
    params.set_exfield_polymod(string("1x^8 + 7"));  // f(x) = x^8 + 7
    params.set_exfield_characteristic(0x3401); // p = 13313
    params.set_log_poly_degree(12);
    params.set_coeff_mod_bit_count(116);  // SEAL param: when n = 4096, q has 116 bits.
    params.validate();

    cout << "Reduced item bit length: " << params.reduced_item_bit_length() << endl;
    cout << "Bit length of p: " << get_significant_bit_count(params.exfield_characteristic()) << endl;

    if (params.reduced_item_bit_length() > 
        (get_significant_bit_count(params.exfield_characteristic()) - 1) * (params.exfield_polymod().coeff_count() - 1))
    {
        cout << "Reduced items too long. We will only use the first " 
            << (get_significant_bit_count(params.exfield_characteristic()) - 1) * (params.exfield_polymod().coeff_count() - 1) << " bits." << endl;
    }
    else
    {
        cout << "All bits of reduced items are used." << endl;
    }

    Receiver receiver(params, MemoryPoolHandle::New(true));
    Sender sender(params, MemoryPoolHandle::New(true));
    sender.set_keys(receiver.public_key(), receiver.evaluation_keys());
    sender.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender);

    cout << "First Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;
    stop_watch.set_time_point("PSI with slow batching done.");
    
    /* The fast batching case. The table size is 4096, and the batching slots are also 4096, hence we only have one batch. */
    PSIParams params2(8, 8, 1, 12, 128, 2, 8);
    params2.set_item_bit_length(90); // The effective item bit length will be limited by ExField's p.
    params2.set_exfield_polymod(string("1x^1")); // f(x) = x
    params2.set_exfield_characteristic(0xA001); // p = 40961. NOTE: p=1 (mod 2n)
    params2.set_log_poly_degree(12);
    params2.set_coeff_mod_bit_count(116);  // SEAL param: when n = 4096, q has 116 bits.
    params2.validate();

    cout << "Reduced item bit length: " << params2.reduced_item_bit_length() << endl;
    cout << "Bit length of p: " << get_significant_bit_count(params2.exfield_characteristic()) << endl;

    if (params2.reduced_item_bit_length() >= get_significant_bit_count(params2.exfield_characteristic()))
    {
        cout << "Reduced items too long. We will only use the first " << get_significant_bit_count(params2.exfield_characteristic()) - 1 << " bits." << endl;
    }
    else
    {
        cout << "All bits of reduced items are used." << endl;
    }

    Receiver receiver2(params2, MemoryPoolHandle::New(true));
    Sender sender2(params2, MemoryPoolHandle::New(true));
    sender2.set_keys(receiver2.public_key(), receiver2.evaluation_keys());
    sender2.load_db(vector<Item>{string("a"), string("b"), string("c"), string("d"), string("e"), string("f"), string("g"), string("h")});

    vector<bool> intersection2 = receiver2.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, sender2);

    cout << "Second Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection2.size(); i++)
        cout << intersection2[i] << ", ";
    cout << ']' << endl;
    stop_watch.set_time_point("PSI with fast batching done.");

    cout << stop_watch << endl;
}

void example_remote()
{
    print_example_banner("Example: Remote");
    stop_watch.time_points.clear();

    /* sender total threads (8), sender session threads (4), receiver threads (1)
    table size (2^8=256), sender bin size (32), window size (2), splits (4). */
    PSIParams params(8, 4, 1, 8, 32, 2, 4);

    /*
    Item's bit length. In this example, we will only consider 32 bits of input items.
    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
    */
    params.set_item_bit_length(32);

    params.set_decomposition_bit_count(2);

    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
    params.set_log_poly_degree(11);

    /* The prime p in ExField. It is also the plain modulus in SEAL. */
    params.set_exfield_characteristic(0x101);

    /* f(x) in ExField. It determines the generalized batching slots. */
    params.set_exfield_polymod(string("1x^16 + 3"));

    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
    params.set_coeff_mod_bit_count(60);

    params.validate();

    Receiver receiver(params, MemoryPoolHandle::New(true));

    vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, "127.0.0.1", params.apsi_port());
    stop_watch.set_time_point("Query done");
    cout << "Intersection result: ";
    cout << '[';
    for (int i = 0; i < intersection.size(); i++)
        cout << intersection[i] << ", ";
    cout << ']' << endl;

    cout << stop_watch << endl;
}

void example_remote_multiple()
{
    print_example_banner("Example: Remote multiple");
    stop_watch.time_points.clear();

    /* sender total threads (8), sender session threads (4), receiver threads (1)
    table size (2^8=256), sender bin size (32), window size (2), splits (4). */
    PSIParams params(8, 4, 1, 8, 32, 2, 4);

    /*
    Item's bit length. In this example, we will only consider 32 bits of input items.
    If we use Item's string or pointer constructor, it means we only consider the first 32 bits of its hash;
    If we use Item's integer constructor, it means we only consider the first 32 bits of the integer.
    */
    params.set_item_bit_length(32);

    params.set_decomposition_bit_count(2);

    /* n = 2^11 = 2048, in SEAL's poly modulus "x^n + 1". */
    params.set_log_poly_degree(11);

    /* The prime p in ExField. It is also the plain modulus in SEAL. */
    params.set_exfield_characteristic(0x101);

    /* f(x) in ExField. It determines the generalized batching slots. */
    params.set_exfield_polymod(string("1x^16 + 3"));

    /* SEAL's coefficient modulus q: when n = 2048, q has 60 bits. */
    params.set_coeff_mod_bit_count(60);

    params.validate();

    mutex mtx;

    auto receiver_connection = [&](int id)
    {
        Receiver receiver(params, MemoryPoolHandle::New(true));
        stop_watch.set_time_point("[Receiver " + to_string(id) + "] Initialization done");

        vector<bool> intersection = receiver.query(vector<Item>{string("1"), string("f"), string("i"), string("c")}, "127.0.0.1", params.apsi_port());
        stop_watch.set_time_point("[Receiver " + to_string(id) + "] Query done");
        mtx.lock();
        cout << "[Receiver " << id << "] Intersection result: ";
        cout << '[';
        for (int i = 0; i < intersection.size(); i++)
            cout << intersection[i] << ", ";
        cout << ']' << endl;
        mtx.unlock();
    };

    int receiver_count = 3;
    vector<thread> receiver_pool;
    for (int i = 0; i < receiver_count; i++)
    {
        receiver_pool.emplace_back(receiver_connection, i);
    }

    for (int i = 0; i < receiver_count; i++)
        receiver_pool[i].join();

    cout << stop_watch << endl;
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