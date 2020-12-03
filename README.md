# APSI Library

## Terminology

### (Unlabeled) PSI and Labeled PSI

Private Set Intersection (PSI) refers to a functionality where two parties, each holding a private set of *items*, can check which items they have in common without revealing anything else to each other.
Upper bounds on the sizes of the sets are assumed to be public information and are not protected.

The APSI (Asymmetric PSI) library provides a PSI functionality for asymmetric set sizes.
For example, in many cases one party may hold a large dataset of millions of records, and the other party wishes to find out whether a single particular record, or a small number of records, appear in the dataset.
We refer to this as the *unlabeled* APSI mode.

In many cases, however, the querier wishes to also retrieve some information per each record key that matched.
This can be viewed as a key-value store with a privacy preserving batched query capability.
We use the terminology *item* and *label* to refer to the key and the value in such a key-value store, and call this the *labeled* APSI mode.

**Note:** Unless labeled mode is actually needed, it will be much more efficient (both communication and computation) to use the unlabeled mode.

### Sender and Receiver

We use the terminology *sender* and *receiver* to denote the two parties in the APSI protocol: a sender sends the result to the receiver.
The most common use-case is one where a server hosts a private look-up table that multiple client can query.
In this case the server acts as the sender and the clients act as (independent) receivers.

## How APSI Works

### Homomorphic Encryption

APSI uses a relatively new encryption technology called as homomorphic encryption, that allows computations to be performed directly on encrypted data.
Results of such computations remain encrypted, and can be only decrypted by the owner of the secret key.
There are many homomorphic encryption schemes with different properties; APSI uses the BFV encryption scheme implemented in the [Microsoft SEAL](https://GitHub.com/Microsoft/SEAL) library.

#### Computing on Encrypted Data

Microsoft SEAL does not enable arbitrary computation to be done on encrypted data, but only limited depth arithmetic circuits (additions and multiplications modulo a prime number).
In fact, these computations can be done in a *batched* manner, where a single Microsoft SEAL ciphertext encrypts a large vector of numbers, and computations are done simultaneously and independently on every value in the vector; batching is crucial for APSI to achieve good performance.

#### Noise Budget

The amount of encrypted computation that can be done is measured in terms of a so-called *noise budget* that each ciphertext carries.
A freshly encrypted ciphertext has a certain amount of noise budget, which is then consumed by encrypted computations &ndash; particularly multiplications.
Once the noise budget is consumed, the ciphertext cannot be decrypted correctly anymore.
To support computations of larger multiplicative depth it may be necessary to start with a larger initial noise budget, which can be done through appropriate changes to the *encryption parameters*.

#### Encryption Parameters

Homomorphic encryption schemes, such as BFV, are notoriously difficult to configure for optimal performance.
APSI requires the user to explicitly provide the Microsoft SEAL encryption parameters, so we need to describe them here briefly.
For much more details, we refer the reader to the [examples](https://github.com/microsoft/SEAL/tree/main/native/examples) in the Microsoft SEAL repository. There are three important encryption parameters that the user should be familiar with:
1. `plain_modulus`
1. `poly_modulus_degree`
1. `coeff_modulus`

We will now describe each in some detail.

The `plain_modulus` is perhaps the easiest to understand.
It must be a prime number congruent to 1 modulo `2 * poly_modulus_degree`, and defines the finite field datatype that the BFV scheme encrypts.
For example, if `plain_modulus` is 65537 &ndash; a 16-bit prime &ndash; then the scheme encrypts and operates on integers modulo 65537.
Unfortunately, `plain_modulus` cannot be increased arbitrarily much, because a larger `plain_modulus` leads to larger noise budget consumption, hence reducing the encrypted computing capability of the scheme unless other steps are taken to subsequently increase it.

The `poly_modulus_degree` is a positive power-of-two integer that determines how many integers modulo `plain_modulus` can be encoded into a single Microsoft SEAL plaintext; typical values are 2048, 4096, 8192, and 16384.
It is now easy for the reader to appreciate the value of batching: thousands of encrypted computations can be done at the cost of one.
Unfortunately things are not quite this simple, because `poly_modulus_degree` also affects the security level of the encryption scheme: bigger `poly_modulus_degree` is more secure.

Finally, `coeff_modulus` is a set of prime numbers that determine the noise budget of a freshly encrypted ciphertext.
In Microsoft SEAL the `coeff_modulus` primes are rarely given explicitly &ndash; the library can sample them &ndash; but instead one would merely specify their bit counts.
In APSI it is necessary to specify at least two `coeff_modulus` primes, but it is beneficial to have as few of them as possible; 2 &ndash; 8 primes is probably reasonable.
The individual primes can be up to 60 bits.
The noise budget depends linearly on the total bit count of the primes.
Again, things are unfortunately not quite this simple, because the `coeff_modulus` also affects the security level of the encryption scheme: bigger total bit count is less secure.
Thus, to obtain more encrypted computing capability, i.e., more noise budget, one needs to increase the total bit count of the `coeff_modulus`, but this may be necessary to combine with increasing of the `poly_modulus_degree`, which will subsequently have an impact on the batching capability, so the computation itself may now change.

Fortunately, Microsoft SEAL prevents the user from accidentally setting insecure parameters.
It checks that, for the given `poly_modulus_degree`, the total `coeff_modulus` bit count does not exceed the following bounds:

| poly_modulus_degree | max coeff_modulus bit count |
|---------------------|-----------------------------|
| 1024                | 27                          |
| 2048                | 54                          |
| 4096                | 109                         |
| 8192                | 218                         |
| 16384               | 438                         |
| 32768               | 881                         |

In APSI, the user will need to explicitly provide the `coeff_modulus` prime bit counts, so the table above will be of great help in avoiding unnecessary exceptions being thrown by Microsoft SEAL.

### Theory

#### Basic Idea

The basic idea of APSI is as follows.
Suppose the sender holds a set `{Y_i}` of items &ndash; each an integer modulo `plain_modulus` &ndash; and the receiver holds a single item `X` &ndash; also an integer modulo `plain_modulus`.
The receiver can choose a secret key, encrypt `X` to obtain a ciphertext `Q = Enc(X)`, and send it over to the sender.
The sender can now evaluate the *matching polynomial* `M(x) = (x-Y_0)*(x-Y_1)*...*(x-Y_n)` at `x=Q`.
Here the values `Y_i` are unencrypted data held by the sender.
Due to the capabilities of homomorphic encryption, `M(Q)` will hold an encryption of `(X-Y_0)*(X-Y_1)*...*(X-Y_n)`, which is zero if `X` exactly matches one of the sender's items, and non-zero otherwise.
The sender, performing the encrypted computation, will not be able to know this result due to the secret key being held only by the receiver.

One problem with the above is that the computation has an enormously high multiplicative depth.
It is not uncommon for the sender to have millions, or even hundreds of millions, of items.
This would require a very high initial noise budget and subsequently very large encryption parameters with an impossibly large computational overhead.

#### Lowering the Depth

The first step towards making this naive idea more practical is to figure out ways of lowering the multiplicative depth of the computation.
First, notice that the sender can simply split up its set into `S` equal size parts, and evaluate the matching polynomial totally independently on each of the parts, producing `S` results `{M_i}`.
All of these results must be sent back to the receiver, so the sender-to-receiver communication has increased by a factor of `S`. Nevertheless, this turns out to be a really valuable trick in helping reduce the size of the encryption parameters.

The second step is to use batching in Microsoft SEAL.
Per each of the `S` parts described above, the sender can further split its set into `poly_modulus_degree` many equal size parts, and the receiver can batch-encrypt its item into a single batched query ciphertext `Q`.
Now, the sender can evaluate vectorized versions of the matching polynomials on `Q`, improving the computational complexity by a factor of `poly_modulus_degree` and significantly reducing the multiplicative depth.

The third step to lowering the depth is to have the receiver compute higher powers of its query, encrypt those separately, and send them all to the sender.
Suppose the matching polynomials the sender hopes to evaluate have degree `d`.
Then, the sender will need ciphertexts encrypting all powers of the receiver's query, up to power `d`.
This is certainly always possible because, given `Q`, homomorphic encryption allows the sender to compute `Q^2`, ..., `Q^d`, but the computation can have high multiplicative depth even with the improvements described above.
Instead, suppose the receiver precomputes certain powers of its query, encrypts them, and sends them to the sender in addition to `Q`.
If the powers are chosen appropriately, the sender can compute all necessary powers of `Q` with a much lower depth circuit.
The receiver-to-sender communication cost increases by a factor of how many powers were sent, but it is almost always beneficial to use this trick to reduce the multiplicative depth of the matching polynomials, and subsequently the size of the encryption parameters.

#### Cuckoo Hashing

The above techniques scale poorly when the receiver has more items.
Indeed, it would seem that the query needs to be repeated once per receiver's item, so if the receiver holds 10,000 items, the communication and computation cost would massively increase.

Fortunately, there is a well-known technique for fixing this issue.
We use a hashing technique called cuckoo hashing, as implemented in the [Kuku](https://GitHub.com/Microsoft/Kuku) library. Cuckoo hashing uses multiple hash functions (usually 2 &ndash; 4), to achieve very high packing rates for a hash table with a bin size of 1.
Instead of batch-encrypting its single item `X` into a query `Q` by repeating it into each batching slot, the receiver uses cuckoo hashing to insert multiple items `{X_i}` into a hash table of size `poly_modulus_degree` (the batch size) and bin size 1.
The cuckoo hash table is then encrypted to form a query `Q`, and is sent to the sender.

The sender uses all the different cuckoo hash functions to hash its items into a regular large hash table with arbitrary size bins; notably, it does not use cuckoo hashing.
In fact, it inserts each item multiple times &ndash; once per each cuckoo hash function.
This is necessary, because the sender cannot know which of the hash functions the receiver's cuckoo hashing process ended up using for each item.
If the number of cuckoo hash functions is `H`, then clearly this effectively increases the sender's set size by a factor of `H`.
After hashing its items the sender breaks down its hash table into parts as described above in [Lowering the Depth](#lowering-the-depth), and upon receiving `Q` proceeds as before.

The benefit is enormous.
Cuckoo hashing allows dense packing of the receiver's items into a single query `Q`.
For example, the receiver may be able to fit thousands of query items `{X_i}` into a single query `Q`, and the sender can perform the matching for all of these queries simultaneously at the cost of an increase in the sender's dataset size by a small factor `H`.

#### Large Items

Recall how each item had to be represented as an integer modulo `plain_modulus`.
Unfortunately, `plain_modulus` is usually around 16 &ndash; 30 bits, and in Microsoft SEAL cannot in any case be larger than 60 bits.
Larger `plain_modulus` also causes larger noise budget consumption, lowering the encrypted computing capability.
On the other hand, we may need to be able to support arbitrary length items.
For example, an item may be an entire document, an email address, a street address, or a driver's license number.
Two tricks make this possible.

First, we first apply a hash function to all of items on both the sender's and receiver's side, so that they have a capped standard length.
We hash to 128 bits and truncate the hash to a shorter length as necessary, still ensuring that the length remains large enough to make collisions unlikely.
The shortest item length we support (after truncation) is 80 bits, which is still far above the practical sizes of `plain_modulus`.

The second trick is to break up each item into multiple parts and encode them separately into consecutive batching slots.
Namely, if `plain_modulus` is a `B`-bit prime, then we write only `B-1` bits of an item into a batching slot, and the next `B-1` bits into the next slot. One downside of this approach is that now a batched plaintext/ciphertext cannot hold anymore `poly_modulus_degree` items, but rather some fraction of it.
Typically we would use either 4 or 8 slots per item.
For example, if `plain_modulus` is a 20-bit prime, then 4 slots could encode an item of length 80, and the query ciphertext `Q` (and its powers) can encrypt up to `poly_modulus_degree / 4` of the receiver's items.
This leads to another issue, where the receiver can now query substantially fewer items than before.
The solution is to decouple the cuckoo hash table size from the `poly_modulus_degree`, and simply use two or more ciphertexts to encrypt `Q` (and its powers).

#### OPRF

Unfortunately, the above approach has two issues:
1. It allows the receiver to learn if parts of its query matched;
2. The result of the matching polynomial reveals &ndash; even when there is no match &ndash; information about the sender's data.

Both issues are significant and unacceptable.

The solution is to use an *Oblivious Pseudo-Random Function*, or *OPRF* for short.
An OPRF can be thought of as a keyed hash function `Hash-OPRF(s, -)` that only the sender knows; here `s` denotes the sender's key.
However, if the receiver has an item `X`, it can obtain `Hash-OPRF(s, X)` without the sender learning `X`, and without the receiver learning the function `Hash-OPRF(s, -)`.

The way to do this is simple.
The receiver hashes its item `X` to an elliptic curve point `A` in some cryptographically secure elliptic curve.
Next, the receiver chooses a secret number `r`, computes the point `B = rA`, and sends it to the sender.
The sender uses its secret `s` to compute `C = sB`, and sends it to back to the receiver.
Upon receiving `C`, the receiver computes the inverse `r^(-1)` modulo the order of the elliptic curve, and further computes `r^(-1) C = r^(-1) srA = sA`.
The receiver then extracts the final hash value `Hash-OPRF(s, X)` from this point, for example by hashing its x-coordinate to an appropriate domain.

The sender knows `s`, so it can simply replace its items `{Y_i}` with `{Hash-OPRF(s, Y_i)}`.
The receiver needs to communicate with the sender to obtain `{Hash-OPRF(s, X_i)}`, and once it has received these values, the protocol can proceed as described above.
With OPRF, the problem of the receiver learning whether parts of its query matched goes away.
Since all the items are hashed with a hash function known only by the sender, the receiver will benefit nothing from learning parts of the sender's hashed items.
In fact, the sender's dataset is no longer private information, and could in principle be sent in full to the receiver.
Homomorphic encryption only protects the receiver's data.

### Practice

We now begin to illustrate how the [Theory](#theory) is implemented in APSI.
Our discussion only considers the unlabeled mode; the labeled mode is not very different, and we will discuss it later.
For simplicity, we assume that the [OPRF](#oprf) step has already been performed, and consider the simplified case where the receiver needs only a single ciphertext (and its powers) to encrypt the query.
This could happen, for example, if `poly_modulus_degree` is 16, each item uses 2 batching slots, and the cuckoo hash table size is 8; these numbers are too small to work in reality, but are helpful to illustrate the concepts.
Suppose the receiver wants to perform a query for a vector of items as follows.
```
Receiver's query vector

[ item92  ]
[ item14  |
[ item79  ]
[ item3   ]
[ item401 ]
```
After cuckoo hashing, the receiver's view is as follows.
The entire vector of size 16 becomes a single Microsoft SEAL ciphertext.

```
Receiver's cuckoo hash table

[ item79-part1  ]
[ item79-part2  ]
[ empty         ]
[ empty         ]
[ item14-part1  ]
[ item14-part2  ]
[ item92-part1  ]
[ item92-part2  ]  ==>  query-ctxt
[ item401-part1 ]
[ item401-part2 ]
[ empty         ]
[ empty         ]
[ empty         ]
[ empty         ]
[ item3-part1   ]
[ item3-part2   ]
```

The sender creates one big hash table, which it then breaks into several independent *bin bundles*.
The matching polynomials for each bin bundle are evaluated independently on `query-ctxt`; this is the first idea presented in [Lowering the Depth](#lowering-the-depth).
For simplicity, we ignore the fact that the sender must use all of the cuckoo hash functions to insert each item.
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
[ item216-part1 | empty         ][ empty         | empty         ]
[ item216-part2 | empty         ][ empty         | empty         ]
[ item315-part1 | item491-part1 ][ item262-part1 | empty         ]
[ item315-part2 | item491-part2 ][ item262-part1 | empty         ]
[ item100-part1 | item37-part1  ][ item90-part1  | item3-part1   ]
[ item100-part2 | item37-part2  ][ item90-part2  | item3-part2   ]

\-------------------------------/\-------------------------------/
           Bin bundle 1                     Bin bundle 2
```
The sender's table is created by first starting with a single bin bundle.
Imagine first `item416` is inserted and it happens to land in the very first bin of the hash table.
Next suppose we add `item500`, `item125`, `item12`, `item9`, and finally `item512` into the bins as shown in the diagram.

APSI allows to specify how many items the sender can fit (horizontally) into each bin bundle.
For the sake of this example, we shall assume that this value is 2, but in reality it would be larger.

Once more room is needed, a new bin bundle is created.
The sender started with only *Bin bundle 1*, but `item512` would land in the same bin as `item125` and `item9`, which is already full according to our bound of 2.
Hence, APSI creates *Bin bundle 2* and inserts `item512` into it.
Next, `item277` is inserted into *Bin bundle 1* since there is still room for it.
In the end, we may end up with dozens or hundreds of bin bundles, and some of the last bin bundles to be added may be left with many empty locations.

For the matching, the encrypted query `query-ctxt` is matched &ndash; in encrypted form &ndash; against both *Bin bundle 1* and *Bin bundle 2*, producing results `result-ctxt-1` and `result-ctxt-2`, which are sent back to the receiver.
The receiver decrypts the results and finds a result as follows.
```
Receiver decrypting the result

                    [ item79-no-match  ]                            [ item79-no-match  ]
                    [ empty            ]                            [ empty            ]
                    [ item14-no-match  ]                            [ item14-match     ]
result-ctxt-1  ==>  [ item92-match     ]        result-ctxt-2  ==>  [ item92-no-match  ]
                    [ item401-no-match ]                            [ item401-no-match ]
                    [ empty            ]                            [ empty            ]
                    [ empty            ]                            [ empty            ]
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

A few important details are omitted from the above description. First, the original items on either side are never inserted directly into the APSI protocol, but instead their OPRF hashes are used.

Second, the sender needs to insert each item multiple times, once using each of the cuckoo hash functions.
For example, if three cuckoo hash functions are used, the sender would insert, e.g., `Hash1(item92)`, `Hash2(item92)`, and `Hash3(item92)`.
The receiver, on the other hand, has inserted only `Hash?(item92)`, where `Hash?` is one of the three hash functions; in any case, the match will be discovered.
Thus, our diagram above is misleading: we should have used names like `item92-hash1-part1`.

Third, as explained in [Large Items](#large-items), in many cases the receiver's query consists of multiple ciphertexts &ndash; not just one like above.
For example, suppose we use a cuckoo hash table of size 32, instead of size 8.
Now a single plaintext cannot encode the receiver's query anymore.
Instead, the query is broken into 4 ciphertexts, each encoding a contiguous chunck of the bigger cuckoo hash table.
```
Receiver's cuckoo hash table

[ item79-part1  ]
[ item79-part2  ]
[ empty         ]
[ empty         ]
[ item14-part1  ]
[ item14-part2  ]
[ item92-part1  ]
[ item92-part2  ]  ==>  query-ctxt0
[ item401-part1 ]
[ item401-part2 ]
[ empty         ]
[ empty         ]
[ empty         ]
[ empty         ]
[ item3-part1   ]
[ item3-part2   ]

[ ...           ]  ==>  query-ctxt1

[ ...           ]  ==>  query-ctxt2

[ ...           ]  ==>  query-ctxt3
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

### Labeled Mode

#### Basic Idea

The labeled mode is not too different, but requires some additional explanation.
The receiver, addition to learning whether its items are in the sender's set, will learn additional data the sender has associated associated to the item.
One can think of this as a key-value store with privacy-preserving queries.

To understand how the labeled mode works, recall from [Basic Idea](#basic-idea) how the matching polynomial `M(x)`, when evaluated for the receiver's encrypted item `Q`, outputs either an encryption of zero, or an encryption of a non-zero value.
In the labeled mode, the sender creates another polynomial `L(x)`, the *label interpolation polynomial*, that has the following property: if `{(Y_i, V_i)}` denotes the sender's item-label pairs, then `L(Y_i) = V_i`.
Upon receiving `Q`, the sender computes the pair `(M(Q), L(Q))` and returns the pair of ciphertexts to the receiver.
The receiver decrypts the pair, and checks whether the first value decrypts to zero.
If it does, the second value decrypts to the corresponding label.

#### Large Labels

One immediate issue is that all encrypted computations happen modulo the `plain_modulus`, but the sender's labels might be much longer than that.
This was a problem also for the items, and was resolved in [Large Items](#large-items) by hashing the items first to a bounded size (80 &ndash; 128 bits) and then using a sequence of batching slots to encode the items.
This works to some extent for labels as well.
Namely, the labels can be broken into parts similarly to the items, and for each part we can form a label interpolation polynomial that outputs that part of the label when evaluated on the corresponding part of the item.

This is not yet a fully satisfactory solution, because our items do not have a fixed size and are fairly short anyway (up to 128 bits).
Labels that are longer than the items can be broken into multiple parts, each of the length of the item.
For each part we can construct a separate label interpolation polynomial, evaluate them all on the encrypted query, and return each encrypted result to the receiver.
The receiver decrypts the results and concatenates them to recover the label for those items that were matched.

#### Label Encryption

There is a serious security issue with the above approach that must be resolved.
Namely, recall how we used [OPRF](#oprf) to ensure that partial (or full) leakage of the sender's items to the receiver does not create a privacy problem.
However, if the receiver can guess a part of the sender's OPRF hashed item, it can use it to query for the corresponding part of the label for that item, which is clearly unacceptable since the receiver does not actually know the item.

To solve this issue, the sender uses a symmetric encryption scheme `Enc(-,-)` to encrypt each of its labels using a key derived from the original item &ndash; not the OPRF hashed item.
In other words, instead of `{(Y_i, V_i)}` it uses `{(Y_i, Enc(HKDF(Y_i), V_i))}` and proceeds as before.
The receiver benefits nothing from learning parts (or all) of the encrypted label, unless it also knows the original item.

#### Partial Item Collisions

There is one last subtle issue that must be addressed.
Recall from [Practice](#practice) how the sender constructs a large hash table and breaks it into a jagged array of bin bundles.
In the labeled mode each bin bundle holds not only the item parts in it, but also the corresponding label parts, and the label interpolation polynomials, as described above.

Now consider what happens when, by pure chance, `item416-part1` and `item12-part1` (as in [Practice](#practice)) are the same.
If the corresponding label parts `label416-part1` and `label12-part1` are different, it will be impossible to create a label interpolation polynomial `L`.

This issue is resolved by checking, before inserting an item into a bin bundle, that its parts do not already appear in the same locations.
If any of them does, the item simply cannot be inserted into that bin bundle, and possibly a new bin bundle for the same bundle index must be created.

## Implementation Details



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

Instead of specifying the Microsoft SEAL `plain_modulus` prime directly, the `-a` option allows its bit count to be provided and automatically samples an appropriate prime.

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
Since 800 is about 78% of 1024, using `-T 1024 -H 3` should result in good success probability for cuckoo hashing.
Suppose also that `-F 8 -a 16` is used, resulting in 120-bit items.
This means that the hash table will require 8192 = 1024 * 8 batching slots; `-P 8192` is the largest valid option in this case, because the cuckoo hash table cannot be smaller than a single Microsoft SEAL plaintext.
On the other hand, `-P 4096` can be beneficial if the sender's database is small and `-P 8192` enables unnecessarily much encrypted computing capability.

#### `-C` \| `--coeffModulusBits`

The `-C` option can be specified multiple times to provide bit counts for Microsoft SEAL `coeff_modulus` primes.
Each provided bit count can be up to 60 (as large as possible should generally be preferred) and the total bit size must not exceed the bounds given in [Encryption Parameters](#encryption-parameters).
A larger total `coeff_modulus` bit count provides more noise budget for encrypted computing, but has an adverse effect on both communication and computation cost.

#### -m | --maxItemsPerBin

The value for `-m` specifies how may items can be (horizontally) inserted into each bin bundle.
Our example in [Practice](#practice) used `-m 2`, but in reality much bigger values should probably be used.

Using a smaller value for `-m` will result in more bin bundles per each bundle index, because fewer items can be inserted into the bin bundles.
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




## Requirements in order

1. [Microsoft GSL](https://github.com/Microsoft/GSL)
    - Linux: `sudo apt install libmsgsl-dev`
1. [ZLIB](https://github.com/madler/zlib)
    - Linux: `sudo apt install zlib1g-dev`
1. [Microsoft SEAL 3.6](https://github.com/microsoft/SEAL)
    - Linux: `cmake -DSEAL_USE_MSGSL=on -DSEAL_USE_ZLIB=on . && sudo make install -j`
1. [Microsoft Kuku 1.1.1](https://github.com/microsoft/Kuku)
    - Linux: `cmake . && sudo make install -j`
1. [Log4cplus](https://github.com/log4cplus/log4cplus)
    - Linux:
        ```
        git clone git@github.com:log4cplus/log4cplus.git --recurse-submodules
        cd log4cplus
        ./configure
        cmake .
        sudo make install -j
        ```
1. [ZeroMQ](http://zeromq.org)
    1. [libzmq](https://github.com/zeromq/libzmq) - ZeroMQ base
        - Linux: will be installed as a dependency of libzmqpp
    1. [libzmqpp](https://github.com/zeromq/zmqpp) - ZeroMQ C++ wrapper
        - Linux: `sudo apt install libzmqpp-dev`
1. [FourQlib](https://github.com/kiromaru/FourQlib)
    - Linux: add "SHARED_LIB=TRUE" to makefile
        ```
        git clone git@github.com:kiromaru/FourQlib.git
        cd FourQlib/FourQ_64bit_and_portable
        make -j
        sudo cp *.h /usr/local/include
        sudo cp libFourQ.so /usr/local/lib
        ```

## Questions
TODO: All CMakeFiles need to know whether we are building shared or static?

### Additional requirements
- [Google Test](https://github.com/google/googletest) - For unit tests and integration tests projects
- [TCLAP](https://sourceforge.net/projects/tclap/) - Command line parser for stand alone executables (Receiver / Sender)
    - Linux: `sudo apt install libtclap-dev `

## Directory structure

The APSI library includes 3 separate components: common library, receiver library, and sender library.
On top of C++ APIs, there is optionally a exported C wrapper layer and furthur a .NET wrapper layer.

```
APSI
|-- README.md
|-- CMakeLists.txt
|-- APSI.sln
|-- common
|   |-- native
|   |   |-- *.cpp
|   |   |-- *.h
|   |   |-- *.vscproj
|   |   `-- c
|   |       |-- *.cpp
|   |       `-- *.h
|   `-- dotnet
|       |-- *.cs
|       `-- *.vscproj
|-- sender
|   ...
|-- receiver
|   ...
|-- tests
|   |-- data
|   |-- unit
|   `-- integration
|-- pipelines
|-- tools
|-- thirdparty
`-- cli
    |-- common
    |-- sender
    `-- receiver
```

TODO: move `cli` directory to foundry99/Private AI/APSI-CLI which already  have the most up-to-date version of files.
TODO: fix CMake in subdirectories of `cli`.
TODO: fix CMake in subdirectories of `tests`.
TODO: fix CMake library/project names.
TODO: fix all `.vscproj` files including their names.