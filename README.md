# polyas-core3-open-cred

A fragment of "Polyas Open Cred" translated from Kotlin to Java for doing formal program verification. The fragment is most likely not fully functional as simplifying assumptions are made.

All relevant proofs can be found in the sub-directories named "proofs...". The statistics belonging to these proofs are found in the corresponding "stats..." sub-directories. These proofs were executed on a computer with an Intel Core i7-4720HQ (2x2.60GHz) processor and 16 GB of RAM. The specification and inital proof took about 80 to 90 hours.

Executing `./run.sh path/to/key.jar` will re-run all proofs, saving them and the statistics in this directory.

## Assumptions for proof

For the correctness of the proof, the following assumptions are necessary:

* The classes from the Java library are effectively final, i.e., not overridden with subclasses that require different class invariants.
* The attacker cannot observe the heap size and the number/size of created objects. By observing how many/which new objects are created during the run of the program, the attack may be able to draw some conclusions about the input data.
* The file that contains the PGP public key of printing facility is well-formed and actually contains a key (see `PGP.readPublicKey` below).
* The hash function used is one-way.

## Issues found and fixed during verification

* In `Utils.bytesToHexString`, an `ArrayIndexOutOfBoundsException` could occur.

## Finished proofs (see "Proofs" folders)

* functional proofs for `CredTool.CredTool` and most (see below) methods called by it
* functional proofs for `CredTool.processCSVRecord` and most (see below) methods called by it
* information flow proofs for `CredTool.processCSVRecord` and most (see below) methods called by it

## Missing proofs

* `PGP.readPublicKey` functional (left unproven, as its behavior depends on the contents of the passed `InputStream`)
* `CredentialGenerator.append` information flow (left unproven, as it simply states that `strContent(s0 + s1 + s2)` depends only on `strContent(s0), strContent(s1), strContent(s2)`)
