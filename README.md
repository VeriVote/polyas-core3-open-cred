# polyas-core3-open-cred

A fragment of "Polyas Open Cred" translated from Kotlin to Java for doing formal program verification. The fragment is most likely not fully functional as simplifying assumptions are made.

## Issues found and fixed during verification

* In `Utils.bytesToHexString`, an `ArrayIndexOutOfBoundsException` could occur.

## Missing proofs

* `CredTool.processCSVRecord` information flow
* `CredTool.addInputCols` information flow
* `CrendentialGenerator.generateDataForVoter` information flow
* `Utils.bytesToHexString` information flow
* `PGP.readPublicKey` functional (leave unproven, since its behavior depends on the contents of the passed `InputStream`)