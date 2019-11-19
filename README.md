# polyas-core3-open-cred

A fragment of "Polyas Open Cred" translated from Kotlin to Java for doing formal program verification. The fragment is most likely not fully functional as simplifying assumptions are made.

## Issues found and fixed during verification

* In `Utils.bytesToHexString`, an `ArrayIndexOutOfBoundsException` could occur.

## Finished proofs (see "Proofs" folders)

* functional proofs for `CredTool.CredTool` and all methods called by it
* functional proofs for `CredTool.processCSVRecord` and all methods called by it
* information flow proofs for all methods in `CredentialGenerator` (except for `generateDataForVoter` and `append`), `Utils` (except for `bytesToHexString`), `Crypto`, `Hashes`, `ECGroup`

## Missing proofs

* `CredTool` information flow
* `Utils.bytesToHexString` information flow
* `PGP.readPublicKey` functional (left unproven, as its behavior depends on the contents of the passed `InputStream`)
* `CredentialGenerator.append` information flow (left unproven, as it simply states that `strContent(s0 + s1 + s2)` depends only on `strContent(s0), strContent(s1), strContent(s2)`)
