# polyas-core3-open-cred

A fragment of "Polyas Open Cred" translated from Kotlin to Java for doing formal program verification. The fragment is most likely not fully functional as simplifying assumptions are made.

## Assumptions for proof

For the correctness of the proof, the following assumptions are necessary:

* The classes from the Java library are effectively final, i.e., not overridden with subclasses that require different class invariants.
* The attacker cannot make assumptions about the heap size and the number/size of created objects. By observing how many/which new objects are created during the run of the program, the attack may be able to draw some conclusions about the input data.
* The file that contains the PGP public key of printing facility is well-formed and actually contains a key (see `PGP.readPublicKey` below).

## Issues found and fixed during verification

* In `Utils.bytesToHexString`, an `ArrayIndexOutOfBoundsException` could occur.

## Finished proofs (see "Proofs" folders)

* functional proofs for `CredTool.CredTool` and all methods called by it
* functional proofs for `CredTool.processCSVRecord` and all methods called by it
* information flow proofs for all methods in `CredentialGenerator` (except for `generateDataForVoter` and `append`), `Utils` (except for `bytesToHexString`), `Crypto`, `Hashes`, `ECGroup`

## Missing proofs

* `PGP.readPublicKey` functional (left unproven, as its behavior depends on the contents of the passed `InputStream`)
* `CredentialGenerator.append` information flow (left unproven, as it simply states that `strContent(s0 + s1 + s2)` depends only on `strContent(s0), strContent(s1), strContent(s2)`)
