# List of Changes

## Version 0.6.0

- Added a function `SenderDB::clear_oprf_key` to clear the OPRF key from a `SenderDB`. This can be useful in some situations, where the `SenderDB` should serve query requests in an untrusted environment and should have no access to the OPRF key. Note that the `SenderDB::strip` function does **not** clear the OPRF key.
- Removed `parameters/16M-256.json`: use [parameters/16M-1024.json](parameters/16M-1024.json) instead.
- Added some error handling code in [sender/apsi/zmq/sender_dispatcher.cpp](sender/apsi/zmq/sender_dispatcher.cpp).

## Version 0.5.0

- Added flexibility to use *any* value for `felts_per_item` in `PSIParams`, not just a power of two.
- Corrected parameter files to have < 2^(-40) false-positive probability per protocol execution.
