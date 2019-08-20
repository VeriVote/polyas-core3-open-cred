package de.polyas.core3.open.cred;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import de.polyas.core3.open.cred.CredentialGenerator.GeneratedDataForVoter;
import de.polyas.core3.open.crypto.basic.Hashes;
import de.polyas.core3.open.crypto.basic.Utils;


/**
 * The main class for the tool for generation credentials. It handles the input
 * and output (CSV files) and applies PGP encryption and signing.
 *
 * <p>For carrying out the core computations -- generating passwords for voters and
 * computing the derived data -- it uses ....
 */
public final class CredTool {

    //@ public instance invariant (\forall int i; 0 <= i && i < inputCols.size(); ((String)inputCols.seq[i]) != null);
    //@ public instance invariant inputCols.contains(idCol);

    //@ public instance invariant inputColsForDist.seq == \seq_singleton(idCol);
    //@ public instance invariant inputColsForPolyas.seq == \seq_singleton(idCol);

    public static List distVals;
    public static List polyasVals;

    private static String print = "";

    // some column names we will create data for
    private static final String PASSWORD_COL = "Password";
    private static final String HASHED_PASSWORD_COL = "Hashed Password";
    private static final String PUBLIC_SIGNING_KEY_COL = "Public Signing Key";
    /**
     * MIN means that Polyas gets the minimum information from the input registry (only voter id),
     * MAX means that all columns from input registry are send back to Polyas.
     */
    static final FieldsForPolyasMode polyasMode = FieldsForPolyasMode.MIN;
    /**
     * The CSV delimiter. Default is ';'.
     */
    static final char DELIMITER = ';';

    /**
     * Directory where the output files are created in; default is '.'.
     */
    final Path outPath;

    /**
     * File that contains the PGP public key of printing facility.
     */
    private String distPubKeyFilename;
    /**
     * File that contains the input registry.
     */
    private String registryFilename;
    /**
     * The name of the column header (of the input registry file) that contains
     * the voter identifier. Voter identifiers must be unique and not empty. Default id 'ID'.
     */
    private String idCol;

    /**
     * The PGP key of the distributor.
     */
    private final PGPPublicKey distPubKey;


    /**
     * The headers of the input file.
     */
    private final List inputCols;

    /**
     * Columns to be included in the distributor (printing facility) file.
     */
    private final List inputColsForDist;
    // all except for the voter identifier

    /**
     * Columns to be included in the polyas file.
     */
    private final List inputColsForPolyas;

    /**
     * CVS Parser for input registry.
     */
    private final CSVParser input;

    /**
     * CSV Writer for Polyas.
     */
    private final CSVPrinter polyas;

    /**
     * CSV Writer for the credential distributing party.
     */
    private final CSVPrinter dist;

    CredTool(String p_distPubKeyFilename, String p_registryFilename, String p_idCol) {
        distPubKeyFilename = p_distPubKeyFilename;
        registryFilename = p_registryFilename;
        idCol = p_idCol;

        outPath = Paths.get(".");
        distPubKey = readPublicKey(distPubKeyFilename);

        inputCols = parseInputCols(registryFilename);
        inputColsForDist = extractInputColsForDist(inputCols, idCol);
        inputColsForPolyas = extractInputColsForPolyas(inputCols, idCol);

        input = parseInput(registryFilename);

        polyas = printPolyas(inputColsForPolyas);
        dist = printDist(inputColsForDist);

        // a sanity check of input registry
        print = "Headers found in input file: " + inputCols;
        //assert(inputCols.contains(idCol));
    }

    /**
     * Processes the given input record `r` and adds appropriate records to
     * the CSV output [dist] and [polyas].
     * VERIFICATION TASK: prove that polyasVals does not depend on password
     */
    /*@ public behavior //TODO: divergence condition??
      @ determines polyasVals.seq \by r;
      @*/
    private void processCSVRecord(CSVRecord r, final String password) {
        if (input.getCurrentLineNumber() % 1000 == 0L) {
            print = "Processed " + input.getCurrentLineNumber() + " lines";
        }
        final String voterId = r.get(idCol);
        if (!voterIdCheck(voterId)) {
            exit("Empty or duplicate voter id");
        }

        final GeneratedDataForVoter dataForVoter =
                CredentialGenerator.generateDataForVoter(voterId, password);

        // Dist
        distVals = new ArrayList();
        for (Object it : inputColsForDist) {
            distVals.add(r.get((String) it));
        }
        distVals.add(0, dataForVoter.password);

        // Polyas
        polyasVals = new ArrayList();
        for (Object it : inputColsForPolyas) {
            polyasVals.add(r.get((String) it));
        }
        polyasVals.add(dataForVoter.hashedPassword);
        polyasVals.add(dataForVoter.publicSigningKey);
    }

    /**
     * Applied to consecutive voters ids (as read from the input file),
     * checks whether voter id's are unique and not empty.
     * It maintains a state (a mutable hash set).
     */
    /*@ public normal_behavior
      @ assignable \nothing;
      @ determines \result \by \nothing; //TODO: \result depends not on the id on voterId.trim().isEmpty()!
      @*/
    private /*@pure@*/ boolean voterIdCheck(final String voterId) {
        return !voterId.trim().isEmpty();
    }

    private List toList(List ls) {
        return new LinkedList(ls);
    }

    private List toList(List ls, String s) {
        List list = toList(ls);
        list.add(s);
        return list;
    }

    private List toList(String s, List ls) {
        List list = Arrays.asList(s);
        int len = ls.size();
        for (int i = 0; i < len; i++) {
            list.add(ls.get(i));
        }
        return list;
    }

    private String[] toArray(List list) {
        int len = list.size();
        String[] arr = new String[len];
        for (int i = 0; i < len; i++) {
            arr[i] = (String)list.get(i);
        }
        return arr;
    }

    private CSVParser parse(final CSVFormat csv, final String fName) {
        try {
            return csv.parse(new FileReader(fName));
        } catch (IOException e) {
            return null;
        }
    }

    private CSVPrinter print(final CSVFormat csv) {
        try {
            return csv.print(new StringBuffer());
        } catch (IOException e) {
            return null;
        }
    }

    /*@ public normal_behavior
      @ assignable \nothing;
      @ determines \result \by key;
      @*/
    private PGPPublicKey readPublicKey(final String key) {
        try {
            return PGP.readPublicKey(key);
        } catch (Exception e) {
            return null;
        }
    }

    /*@ public normal_behavior
      @ ensures \result.contains(idCol);
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @*/
    private LinkedList parseInputCols(final String fileName) {
        final CSVParser parser =
                parse(CSVFormat.RFC4180.withFirstRecordAsHeader().withDelimiter(DELIMITER),
                      fileName);
        final Map inputColMap;
        if (parser != null) {
            inputColMap = parser.getHeaderMap();
        } else {
            new LinkedHashMap();
            inputColMap = new LinkedHashMap();
        }
        return new LinkedList(inputColMap.keySet());
    }

    private List extractInputColsForDist(final List cols, final String id) {
        // TODO HERE: id/idCol!

        List result = new ArrayList();
        if (cols.contains(id)) {
            result.add(id);
        }
        return result;
    }

    private List extractInputColsForPolyas(final List cols, final String id) {
        // TODO HERE: id/idCol!

        List result = new ArrayList();
        if (polyasMode == FieldsForPolyasMode.MIN) {
            if (cols.contains(id)) {
                result.add(id);
            }
        } else if (polyasMode == FieldsForPolyasMode.MAX) {
            result.addAll(cols);
        }
        return result;
    }

    /*@ public normal_behavior
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @*/
    private CSVParser parseInput(final String fileName) {
        return parse(CSVFormat.RFC4180.withFirstRecordAsHeader().withDelimiter(DELIMITER),
                     fileName);
    }

    private CSVPrinter printPolyas(final List cols) {
        return print(CSVFormat.RFC4180.withDelimiter(DELIMITER)
                     .withHeader(toArray(toList(toList(cols, HASHED_PASSWORD_COL),
                                          PUBLIC_SIGNING_KEY_COL)))); // order is important!
    }


    private CSVPrinter printDist(final List cols) {
        return print(CSVFormat.RFC4180.withDelimiter(DELIMITER)
                     .withHeader(toArray(toList(PASSWORD_COL, cols)))); // order is important!
    }

    /**
     * Main entry point: reads and processes the input file line by line collecting the data
     * and then creates the output files.
     */
    FileInfo generate() {
        // Process input registry line by line.
        // as a side effect of processCSVRecord, data is added to CSV output [dist] and [polyas]
        // all data is hold only in memory

        for (CSVRecord it : input) {
            final String password = Crypto.randomCredential80(); // TODO HERE: SOURCE!
            processCSVRecord(it, password);
        }
        try {
            // TODO HERE: ONLY GOES HERE!
            dist.printRecord(distVals);
            // TODO HERE: SINK!
            polyas.printRecord(polyasVals);

            polyas.close(true);
            dist.close(true);
        } catch (IOException e1) {
            // do nothing
        }

        // Create a tag by hashing the file contents for Polyas.
        // the tag will be appended to file names
        final byte[] polyasFileContentHash = Hashes.hash512(polyas.getOut().toString(), null, null);
        final String filetag = filetag(Utils.asHexString(polyasFileContentHash));

        // Create a ephemeral key pair to sign the files
        final String pgpPassword = CredentialGenerator.newSalt();
        PGPSecretKey ourSecretKey;
        try {
            ourSecretKey = PGP.createKey(pgpPassword, "wvz-" + filetag);
        } catch (Exception e1) {
            ourSecretKey = null;
        }
        // Note that we never store the private key to any file,
        // so the choice of password actually does not matter.

        // define the file names
        final Path pubKeyFile = pubKeyFile(filetag);
        final Path polyasFile = polyasFile(filetag);
        final Path distFile = distFile(filetag);
        final Path polyasSigFile = polyasSigFile(filetag);

        // save the public key in a file
        try {
            PGP.exportKey(pubKeyFile.toString(), ourSecretKey, true);
        } catch (IOException e) {
        }

        // Write the file for the distributor (printing facility).
        // the file gets encrypted under the public key of the distributor
        // and signed by our ephemeral key using PGP
        byte[] signedAndEncryptedDistContent;
        try {
            signedAndEncryptedDistContent =
                    PGP.signAndEncrypt(dist.getOut().toString().getBytes(), ourSecretKey,
                                       pgpPassword, distPubKey, true);
        } catch (Exception e) {
            signedAndEncryptedDistContent = null;
        }
        try {
            Files.write(distFile, signedAndEncryptedDistContent);
        } catch (IOException e) {
            // do nothing
        }

        // write the file for Polyas
        try {
            Files.write(polyasFile, polyas.getOut().toString().getBytes());
        } catch (IOException e) {
            // do nothing
        }

        // create a detached signature on the Polyas file content using our ephemeral key
        try {
            PGP.createSignature(polyasFile.toString(), ourSecretKey, polyasSigFile.toString(),
                                pgpPassword.toCharArray(), true);
        } catch (Exception e) {
            // do nothing
        }

        // return the names of the files just created
        return new FileInfo(pubKeyFile, polyasFile, polyasSigFile, distFile);
    }

    private void exit(String msg) {
        print = "Error occured at input line " + input.getCurrentLineNumber() + ": " + msg;
        System.exit(-1);
    }

    Path pubKeyFile(String filetag) {
        return outPath.resolve("sigPubKey_" + filetag + ".asc");
    }
    Path polyasFile(String filetag) {
        return outPath.resolve("polyas_" + filetag + ".csv");
    }
    Path polyasSigFile(String filetag) {
        return outPath.resolve("polyasSig_" + filetag + ".csv.sig");
    }
    Path distFile(String filetag) {
        return outPath.resolve("dist_" + filetag + ".asc");
    }

    private String filetag(String hash) {
        final String now = (new SimpleDateFormat("yyyyMMdd-HHmmss")).format(new Date());
        return (now + "_" + hash).substring(0, 9);
    }

    enum FieldsForPolyasMode {
        MIN, MAX;
    }

    /**
     * Data class to hold the output files generated by the credentail tool.
     */
    public class FileInfo {
        final Path pubKeyFile;
        final Path polyasFile;
        final Path polyasSigFile;
        final Path distFile;

        public FileInfo(final Path pubKeyFile,
                        final Path polyasFile,
                        final Path polyasSigFile,
                        final Path distFile) {
            this.pubKeyFile = pubKeyFile;
            this.polyasFile = polyasFile;
            this.polyasSigFile = polyasSigFile;
            this.distFile = distFile;
        }
    }

    /**
     * Command line tool for generation credentials.
     *
     * <p>use 'gpg -d --output out.txt dist-uniqueId.asc' to decrypt
     * use 'gpg --verify polyas-uniqueId.csv.sig polyas-uniqueId.txt' to verify signature
     *
     */
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Sanity checks
        if (args.length != 3) {
            print = "Usage: java -jar CredTool.jar DISTRIBUTOR_PUBKEYFILE REGISTRYFILE " +
                    "VOTER_ID_COLUMN_HEADER";
            System.exit(0);
        }
        try {
            final CredTool customerTool = new CredTool(args[0], args[1], args[2]);
            final FileInfo fileInfo = customerTool.generate();
            print = "Success! Files created." + '\n' +
                "-----------------------" + '\n' + '\n' +

                "Please ship the following files to the PRINTING facility" + '\n' +
                "->" + fileInfo.pubKeyFile + '\n' +
                "->" + fileInfo.distFile + '\n' + '\n' +

                "Please ship the following files to the POLYAS" + '\n' +
                "->" + fileInfo.pubKeyFile + '\n' +
                "->" + fileInfo.polyasFile + '\n' +
                "->" + fileInfo.polyasSigFile + '\n' + '\n' +

                "One may" + '\n' + '\n' +

                "use 'gpg --import " + fileInfo.pubKeyFile +
                "' to import the public key" + '\n' + '\n' +

                "use 'gpg -d " + fileInfo.distFile +
                "' to decrypt (only printing facility can do this)" + '\n' +
                "use 'gpg --verify " + fileInfo.polyasFile +
                " " + fileInfo.polyasSigFile + "' to verify signature";
        } catch (Exception e) {
            print = "Error: " + e.getMessage() + '\n' +
                    "Nested technical reason: " +
                    (e.getCause() != null ? e.getCause().getMessage() : "none");
        }
    }
}
