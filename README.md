# polyas-core3-open-cred

A fragment of "Polyas Open Cred" translated from Kotlin to Java for doing formal program verification. The fragment is most likely not fully functional as simplifying assumptions are made.

## Issues found and fixed during verification

* In `Utils.bytesToHexString`, an `ArrayIndexOutOfBoundsException` could occur.

## Finished proofs (see "Proofs" folders)

* TODO

## Missing proofs

* `CredTool` information flow
* `Utils.bytesToHexString` information flow
* `PGP.readPublicKey` functional (leave unproven, as its behavior depends on the contents of the passed `InputStream`)
* `CredentialGenerator.append` information flow (leave unproven, as it simply states that `strContent(s0 + s1 + s2)` depends only on `strContent(s0), strContent(s1), strContent(s2)`)
