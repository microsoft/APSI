# APSI

The `cli/` subdirectory contains primitive server and client programs, demonstrating the use of APSI. In this document we explain the different command line arguments to these programs, and how to set them.

## Terminology

### (Unlabeled) PSI and Labeled PSI

Private Set Intersection (PSI) referes to a functionality where two parties, each holding a private set of *items*, can check which items they have in common without revealing anything else to each other.
Upper bounds on the sizes of the sets are assumed to be public information and are not protected.

The APSI (Asymmetric PSI) library provides a PSI functionality for asymmetric set sizes.
For example, in many cases one party may hold a large dataset of millions of records, and the other party wishes to find out whether a single particular record, or a small number of records, appear in the dataset.
We refer to this as the *unlabeled* APSI mode.

In many cases, however, the querier wishes to also retrieve some information per each record key that matched.
This can be viewed as a key-value store with a privacy preserving batched query capability.
We use the terminology *item* and *label* to refer to the key and the value in such a key-value store, and call this the *labeled* APSI mode.

**Note:** Unless labeled mode is actually needed, it will be much more efficient (both communication and computation) to use the unlabeled mode.

### Sender and Receiver

We use the terminology **sender** and **receiver** to denote the two parties in the APSI protocol.
A receiver *receives* the query result and a sender *sends* it.
The most common use-case is one where a server hosts a private look-up table that multiple client can query.
In this case the server acts as the sender and the clients act as (independent) receivers.

# Command-Line Interface (CLI)

APSI allows a receiver to optionally query for protocol parameters from the sender.
In many cases this is not necessary, since the parameters may already be determined ahead of time according to some known upper bounds on the data size.

In the CLI the receiver always obtains the parameters from the sender, so only the sender can specify them on the command line.
Therefore, the sender's command line arguments are much more complex than the receiver's.

## Common Arguments

The following arguments are common both to the sender and the receiver applications.

| Parameter | Explanation | 
|-----------|-------------|
| `-t` \| `--threads` | Number of threads to use |
| `-f` \| `--logFile` | Log file path (optional) |
| `-c` \| `--logToConsole` | Write log output additionally to the console (optional) |
| `-l` \| `--logLevel` | One of `all`, `debug`, `info` (default), `warning`, `error`, `off` |

## Receiver

The following arguments specify the receiver's behavior.

| Parameter | Explanation | 
|-----------|-------------|
| `-q` \| `--queryFile` | File containing the query data |
| `-o` \| `--outFile` | Output file (not implemented; currently printed in terminal) |
| `-a` \| `--ipAddr` | IP address for a sender endpoint |
| `-p` \| `--port` | TCP port to connect to (default is 1212) |

## Sender

The following arguments specify the sender's behavior and determine the parameters for the protocol.

| Parameter | Explanation | 
|-----------|-------------|
| `-d` \| `--dbFile` | CSV file describing a look-up table with possibly empty values |
| `-p` \| `--port` | TCP port to bind to (default is 1212) |
| `-F` \| `--feltsPerItem` | Number of field elements to use per item |
| `-T` \| `--tableSize` | Size of the cuckoo hash table |
| `-m` \| `--maxItemsPerBin` | Bound on the bin size for sender's hash tables |
| `-H` \| `--hashFuncCount` | Number of hash functions to use for cuckoo hashing |
| `-w` \| `--queryPowerCount` | Number of encrypted powers of the query data to be sent |
| `-P` \| `--polyModulusDegree` | Microsoft SEAL `poly_modulus_degree` parameter |
| `-C` \| `--coeffModulusBits` | Bit count for a single Microsoft SEAL `coeff_modulus` prime |
| `-a` \| `--plainModulusBits` | Bit count for a Microsoft SEAL `plain_modulus` prime (cannot be used with `-A`) |
| `-A` \| `--plainModulus` | Microsoft SEAL `plain_modulus` prime (cannot be used with `-a`) |

#### `-d` \| `--dbFile`

Each row of the database CSV file contains an arbitrarily long key and optionally a value, separated by a comma.
If every row contains only a key, APSI will run in the more efficient unlabeled mode, where the receiver learns whether the keys they queried appear in the look-up table.
Thus, no values should be specified on any of the rows unless it is truly necessary for the functionality.

#### `-p` \| `--port`

Specified the TCP/IP port the application will bind to.

#### `-F` \| `--feltsPerItem`

Specified how many Microsoft SEAL batching slots are used to encode a single item.
If the `plain_modulus` is a B-bit prime, then each slot encodes B - 1 bits of item data.
For example, if the sender is invoked with `-a 16 -F 8`, then APSI will use 120 = 8 * (16 - 1) bits per item.
We call this the *item bit count*, and it must be in the range 80 &ndash; 128.
APSI handles hashing the items to appropriate length, but the user must specify the `-a` and the `-F` values appropriately.

The value for `-F` must be a power of two. Common choices are `4`, `8`, and `16`.

#### `-A` \| `--plainModulus`

Allows the exact value for a Microsoft SEAL `plain_modulus` to be specified.
Since APSI uses batching, the prime must have a special form (congruent to 1 modulo `2 * poly_modulus_degree`).
A common and good choice for the `plain_modulus` is the 16-bit Fermat prime 65537.
In general, however, we recommend the much easier `-a` option instead, which allows specifying the bit count instead and leaves the prime sampling for Microsoft SEAL.

Smaller values for `plain_modulus` result in less noise growth in homomorphic encryption and in some cases may allow smaller encryption parameters to be used (`poly_modulus_degree` and `coeff_modulus`), resulting in significant speed-ups.
However, at the same time a smaller value for `plain_modulus` reduces the number of bits of the values that can be encoded into a single batching slot, possibly requiring a larger value for `-F`.

#### `-a` \| `--plainModulusBits`

Instead of specifying the Microsoft SEAL `plain_modulus` prime directly, the `-a` option allows its bit size to be provided and automatically samples an appropriate prime.

#### `-T` \| `--tableSize`

The size of the cuckoo hash table the receiver needs to populate.
This value must be a power of two and must be at least as large as `poly_modulus_degree` divided by the value for `-F` (the number of items encoded into a single Microsoft SEAL plaintext).
If the value for `-T` is larger than `poly_modulus_degree` divided by the value for `-F`, then APSI will use multiple Microsoft SEAL plaintexts to encode the hash table bins.

A larger value for `-T` allows the receiver to hash more items into a single query. If the query size is very small, it can be beneficial to make the value for `-T` as small as possible, i.e., equal to `poly_modulus_degree` divided by the value for `-F`.

#### `-H` \| `--hashFuncCount`

The number of hash functions (2 &ndash; 8) used for cuckoo hashing.
A larger value for `-H` implies denser packing for the receiver's hash table, i.e., they can fit more items into a single query.
On the other hand, the sender must add its database items into a large hash table using each of the hash functions, so a larger value for `-H` means that the sender's hash table may be much larger, possibly increasing both communication and computation cost.

#### `-P` \| `--polyModulusDegree`

The Microsoft SEAL `poly_modulus_degree` parameter determines how many integers modulo the `plain_modulus` can be batched into a single plaintext object.
APSI encodes items into multiple Microsoft SEAL batching slots, because the `plain_modulus` value (up to 60 bits) is never large enough to hold an entire item (80 &ndash; 128 bits).

The situation is easiest to understand on the receiver's side.
The receiver uses cuckoo hashing to hash its query items into a single hash table of size specified with the `-T` option.
Suppose the receiver wants to submit 800 items in a batched query.
Since 800 is about 78% of 1024, using `-T 1024 -H 3` should result in overwhelming success probability for cuckoo hashing.
Suppose also that `-F 8 -a 16` is used, resulting in 120-bit items.
This means that the hash table will require 8192 = 1024 * 8 batching slots; `-P 8192` is the largest valid option in this case, because the cuckoo hash table cannot be smaller than a single Microsoft SEAL plaintext.
On the other hand, `-P 4096` can be beneficial if the sender's database is small and `-P 8192` enables unnecessarily much encrypted computing capability.

#### `-C` \| `--coeffModulusBits`

The `-C` option can be specified multiple times to provide bit sizes for Microsoft SEAL `coeff_modulus` primes.
Each provided bit size can be up to 60 (as large as possible should generally be preferred) and the total bit size must not exceed the bounds specified [here](https://github.com/microsoft/SEAL/blob/f27b3b36fed0de3c57cd91f03d1d4ddf3ca75641/native/examples/1_bfv_basics.cpp#L73-L82).
A larger total `coeff_modulus` bit size provides more noise budget for encrypted computing, but has an adverse effect on both communication and computation cost.

#### -m | --maxItemsPerBin

The sender's data structure is much more complex than the receiver's.
Unlike the receiver's single cuckoo hash table, the sender's data is organized into multiple smaller units called *bin bundles*.
The idea is that the receiver's encrypted query can be matched independently against each bin bundle, and each result is returned back to the receiver.
Matching against smaller bin bundles results in smaller encrypted computations, requiring less noise budget and subsequently smaller encryption parameters, which improves performance.

Several important details remain to be clarified.
To illustrate the situation, we use a small toy example `-T 256 -F 2 -P 512`, where only a single ciphertext is needed to encrypt the receiver's query.
The receiver's view is as follows.

```
Receiver's cuckoo hash table

[ item79-part1  ]
[ item79-part2  ]
[ empty         ]
[ empty         ]
[ item14-part1  ]
[ item14-part2  ]
[ item92-part1  ]  ==>  query-ctxt
[ item92-part2  ]
[ item401-part1 ]
[ item401-part2 ]
[ empty         ]
[ empty         ]
[ ...           ]
[ item3-part1   ]
[ item3-part2   ]
```

The sender creates one big hash table, which is broken into several bin bundles (basically, smaller hash tables) as follows.
```
Sender's big hash table

[ item416-part1 | item12-part1  ][ item71-part1  | item611-part1 ]
[ item416-part2 | item12-part2  ][ item71-part2  | item611-part2 ]
[ item125-part1 | item9-part1   ][ item512-part1 | empty         ]
[ item125-part2 | item9-part2   ][ item512-part2 | empty         ]
[ item500-part1 | item277-part1 ][ item14-part1  | item320-part1 ]
[ item500-part2 | item277-part2 ][ item14-part2  | item320-part2 ]
[ item92-part1  | empty         ][ empty         | empty         ]
[ item92-part2  | empty         ][ empty         | empty         ]
[ item498-part1 | item403-part1 ][ item88-part1  | item5-part1   ]
[ item498-part2 | item403-part2 ][ item88-part2  | item5-part2   ]
[ ...           | ...           ][ ...           | ...           ]
[ item100-part1 | item37-part1  ][ item90-part1  | item3-part1   ]
[ item100-part2 | item37-part2  ][ item90-part2  | item3-part2   ]

\-------------------------------/\-------------------------------/
           Bin bundle 1                     Bin bundle 2
```
The sender's table is created by first starting with a single bin bundle.
Imagine first `item416` is inserted and it happens to land in the very first bin of the hash table.
Next suppose we add `item500`, `item125`, `item12`, `item9`, and finally `item512` into the bins as shown in the diagram.
The value for the `-m` option specifies how many items the sender can fit (horizontally) into each bin bundle.
Once more room is needed, a new bin bundle is created.
In this toy example we are using `-m 2` (in reality the value should be much larger).
The sender started with only *Bin bundle 1*, but `item512` would land in the same bin as `item125` and `item9`, which is already full according to the specified value for `-m`.
Hence, APSI creates *Bin bundle 2* and inserts `item512` into it.
Next, `item277` is inserted into *Bin bundle 1* since there is still room for it.
In the end, we may end up with dozens or hundreds of bin bundles, and some of the last bin bundles to be added may end up with many empty locations.

For the matching, the encrypted query `query-ctxt` is matched &ndash; in encrypted form &ndash; against both *Bin bundle 1* and *Bin bundle 2*, producing results `result-ctxt-1` and `result-ctxt-2`, which are sent back to the receiver.
The receiver decrypts the results and finds a result as follows (this is the unlabeled mode).
```
Receiver decrypting the result

                    [ item79-no-match  ]                            [ item79-no-match  ]
                    [ empty            ]                            [ empty            ]
                    [ item14-no-match  ]                            [ item14-match     ]
result-ctxt-1  ==>  [ item92-match     ]        result-ctxt-2  ==>  [ item92-no-match  ]
                    [ item401-no-match ]                            [ item401-no-match ]
                    [ ...              ]                            [ ...              ]
                    [ item3-no-match   ]                            [ item3-match      ]
```
APSI computes the logical OR of the match values for each result ciphertext and orders the results according to the order of the items appearing in the original query producing, for example, a result vector as follows.
The order of the items in the query is arbitrary and irrelevant.
```
Receiver's query vector      Receiver's result vector

[ item92  ]                  [ match    ]
[ item14  ]                  [ match    ]
[ item79  ]                  [ no-match ]
[ item3   ]                  [ match    ]
[ item401 ]                  [ no-match ]
```
The receiver, in this case, concludes that `item92`, `item14`, and `item3` are all present in the sender's database, whereas the other ones are not.

Two important details are omitted from the above description.

First in reality, the items are not inserted directly into the hash table on either side, but instead hashes of the items are used.
The sender needs to insert each item multiple times, once using each of the cuckoo hash functions.
For example, if `-H 3` is used, the sender in reality inserts, e.g., `Hash1(item92)`, `Hash2(item92)`, and `Hash3(item92)`.
The receiver, on the other hand, has inserted only `HashX(item92)`, where `HashX` is one of the three hash functions; in any case, the match will be discovered.
However, our diagram above is slightly misleading: we should have used names like `item92-hash1-part1`.

The second important detail is that in many cases the receiver's query consists of multiple ciphertexts &ndash; not just one like above.
For example, suppose we use `-T 1024 -F 2 -P 512`; now a single plaintext cannot encode the receiver's query anymore.
Instead, the query is broken into four ciphertexts (1024 * 2 / 512), each encoding a contiguous chunck of the cuckoo hash table.
```
Receiver's cuckoo hash table

[ item79-part1  ]
[ item79-part2  ]
[ empty         ]
[ empty         ]
[ item14-part1  ]
[ item14-part2  ]
[ item92-part1  ]  ==>  query-ctxt0
[ item92-part2  ]
[ item401-part1 ]
[ item401-part2 ]
[ empty         ]
[ empty         ]
[ ...           ]

[ ...           ]  ==>  query-ctxt1

[ ...           ]  ==>  query-ctxt2

[ ...           ]
[ item3-part1   ]  ==>  query-ctxt3
[ item3-part2   ]
```
A similar breakdown takes place on the sender's side, creating a jagged array of bin bundles.
Here is an example of what the sender's view could be.
```
                +------------++------------++------------+
                |            ||            ||            |
Bundle index 0  | Bin bundle || Bin bundle || Bin bundle |
                |            ||            ||            |
                +------------++------------++------------+
                +------------++------------+
                |            ||            |
Bundle index 1  | Bin bundle || Bin bundle |
                |            ||            |
                +------------++------------+
                +------------++------------++------------++------------+
                |            ||            ||            ||            |
Bundle index 2  | Bin bundle || Bin bundle || Bin bundle || Bin bundle |
                |            ||            ||            ||            |
                +------------++------------++------------++------------+
                +------------++------------++------------+
                |            ||            ||            |
Bundle index 3  | Bin bundle || Bin bundle || Bin bundle |
                |            ||            ||            |
                +------------++------------++------------+
```
When the sender receives `query-ctxt0`, it must compute the encrypted match for each bin bundle at bundle index 0.
Similarly, `query-ctxt1` must be matched against each bin bundle at bundle index 1, and so on.
The number of result ciphertexts obtained by the receiver will be equal to the total number of bin bundles the sender holds; the client cannot know this number in advance.

Using a smaller value for `-m`, therefore, will result in more bin bundles per each bundle index, because fewer items can be inserted into the bin bundles.
This clearly increases the communication cost, as the result size is proportional to the number of bin bundles.
A smaller value for `-m` reduces the complexity of the encrypted match computation, allowing possibly smaller encryption parameters to be used.
Since the bin bundles can also be processed independently in parallel, (more) smaller bin bundles often outperforms (fewer) larger bin bundles.

#### `-w` \| `--queryPowerCount`

Suppose we use `-m 32`. Upon receiving a query ciphertext `Q`, the sender must compute all powers of `Q`, up to `Q^32`.
Homomorphic encryption makes this possible, but the computation can easily have significantly large multiplicative depth, and may require impractically large encryption parameters.

Instead of using very large encryption parameters, the receiver will compute ahead of time certain powers of its query, encrypt those powers, and send them all to the sender, along with instructions for how to multiply the ciphertexts together to obtain all of the required powers.
Much of this is invisible to the user, and is controlled by the `-w` option, which specifies how many powers will be sent.
APSI will determine internally exactly which powers it will send.
For example, using `-w 6` will have twice larger communication cost from receiver to sender, compared to using `-w 3`, whereas the communication cost from sender to receiver is not directly impacted by this choice.

Using a larger value for `-w` results in increased communication and reduced computation.
In some cases it can allow for smaller encryption parameters to be used.