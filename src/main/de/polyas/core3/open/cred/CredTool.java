package de.polyas.core3.open.cred;

import de.polyas.core3.open.cred.CredentialGenerator.GeneratedDataForVoter;
import de.polyas.core3.open.crypto.basic.Hashes;
import de.polyas.core3.open.crypto.basic.Utils;

import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;


/**
 * The main class for the tool for generation credentials. It handles the input
 * and output (CSV files) and applies PGP encryption and signing.
 *
 * <p>For carrying out the core computations -- generating passwords for voters and
 * computing the derived data -- it uses ....
 */
class CredTool {

    public static List<String> distVals;
    public static List<String> polyasVals;

    private static String print = "";

    // some column names we will create data for
    private static final String PASSWORD_COL = "Password";
    private static final String HASHED_PASSWORD_COL = "Hashed Password";
    private static final String PUBLIC_SIGNING_KEY_COL = "Public Signing Key";

    /**
     * Directory where the output files are created in; default is '.'.
     */
    final Path outPath = Paths.get(".");
    /**
     * MIN means that Polyas gets the minimum information from the input registry (only voter id),
     * MAX means that all columns from input registry are send back to Polyas.
     */
    static final FieldsForPolyasMode polyasMode = FieldsForPolyasMode.MAX;
    /**
     * The CSV delimiter. Default is ';'.
     */
    static final char DELIMITER = ';';

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
    private String idCol = "ID";

    /**
     * The PGP key of the distributor.
     */
    private final PGPPublicKey distPubKey = readPublicKey(distPubKeyFilename);


    /**
     * The headers of the input file.
     */
    private final List<String> inputCols = parseInputCols(registryFilename);

    /**
     * Columns to be included in the distributor (printing facility) file.
     */
    private final List<String> inputColsForDist = extractInputColsForDist(inputCols, idCol);
    // all except for the voter identifier

    /**
     * Columns to be included in the polyas file.
     */
    private final List<String> inputColsForPolyas = extractInputColsForPolyas(inputCols, idCol);

    /**
     * CVS Parser for input registry.
     */
    private final CSVParser input = parseInput(registryFilename);

    /**
     * CSV Writer for Polyas.
     */
    private final CSVPrinter polyas =
        printPolyas(inputColsForPolyas);

    /**
     * CSV Writer for the credential distributing party.
     */
    private final CSVPrinter dist = printDist(inputColsForDist);

    CredTool(String distPubKeyFilename, String registryFilename, String idCol) {
        this.distPubKeyFilename = distPubKeyFilename;
        this.registryFilename = registryFilename;
        this.idCol = idCol;
        init();
    }

    /**
     * Applied to consecutive voters ids (as read from the input file),
     * checks whether voter id's are unique and not empty.
     * It maintains a state (a mutable hash set).
     */
    private boolean voterIdCheck(final String voterId) {
        return !voterId.isBlank();
    }

    private static List<String> toList(List<String> ls) {
        return new LinkedList<String>(ls);
    }

    private static List<String> toList(List<String> ls, String s) {
        List<String> list = toList(ls);
        list.add(s);
        return list;
    }

    private static List<String> toList(String s, List<String> ls) {
        List<String> list = Arrays.asList(s);
        int len = ls.size();
        for (int i = 0; i < len; i++) {
            list.add(ls.get(i));
        }
        return list;
    }

    private static String[] toArray(List<String> list) {
        int len = list.size();
        String[] arr = new String[len];
        for (int i = 0; i < len; i++) {
            arr[i] = list.get(i);
        }
        return arr;
    }

    private static CSVParser parse(final CSVFormat csv, final String fName) {
        try {
            return csv.parse(new FileReader(fName));
        } catch (IOException e) {
            return null;
        }
    }

    private static CSVPrinter print(final CSVFormat csv) {
        try {
            return csv.print(new StringBuffer());
        } catch (IOException e) {
            return null;
        }
    }

    private static PGPPublicKey readPublicKey(final String key) {
        try {
            return PGP.readPublicKey(key);
        } catch (IOException | PGPException e) {
            return null;
        }
    }

    private static LinkedList<String> parseInputCols(final String fileName) {
        final CSVParser parser =
                parse(CSVFormat.RFC4180.withFirstRecordAsHeader().withDelimiter(DELIMITER),
                      fileName);
        final Map<String, Integer> inputColMap;
        if (parser != null) {
            inputColMap = parser.getHeaderMap();
        } else {
            new LinkedHashMap<String, Integer>();
            inputColMap = new LinkedHashMap<String, Integer>();
        }
        return new LinkedList<String> (inputColMap.keySet());
    }


    private static List<String> extractInputColsForDist(final List<String> cols, final String id) {
        // TODO HERE: id/idCol!
        final Stream<String> stream = cols.stream().filter(it -> !it.equals(id));
        return stream.collect(Collectors.toList());
    }

    private static List<String> extractInputColsForPolyas(final List<String> cols, final String id) {
        final List<String> list;
        if (polyasMode == FieldsForPolyasMode.MIN) {
            list = Arrays.asList(id);
        } else if (polyasMode == FieldsForPolyasMode.MAX) {
            list = toList(cols);
        } else {
            list = new ArrayList<String>();
        }
        return list;
    }

    private CSVParser parseInput(final String fileName) {
        return parse(CSVFormat.RFC4180.withFirstRecordAsHeader().withDelimiter(DELIMITER),
                     fileName);
    }

    private static CSVPrinter printPolyas(final List<String> cols) {
        return print(CSVFormat.RFC4180.withDelimiter(DELIMITER)
                     .withHeader(toArray(toList(toList(cols, HASHED_PASSWORD_COL),
                                          PUBLIC_SIGNING_KEY_COL)))); // order is important!
    }


    private static CSVPrinter printDist(final List<String> cols) {
        return print(CSVFormat.RFC4180.withDelimiter(DELIMITER)
                     .withHeader(toArray(toList(PASSWORD_COL, cols)))); // order is important!
    }

    void init() {
        // a sanity check of input registry
        print = "Headers found in input file: " + inputCols;
        assert(inputCols.contains(idCol));
    }

    /**
     * Main entry point: reads and processes the input file line by line collecting the data
     * and then creates the output files.
     */
    FileInfo generate() {
        // Process input registry line by line.
        // as a side effect of processCSVRecord, data is added to CSV output [dist] and [polyas]
        // all data is hold only in memory
        input.forEach(it -> {
            // generate a password with 80 bits of entropy
            final String password = Crypto.randomCredential80(); // TODO HERE: SOURCE!
            proccessCSVRecord(it, password);
        });
        try {
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
        } catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException e1) {
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
        } catch (IOException | PGPException e) {
            signedAndEncryptedDistContent = null;
        }
        try {
            Files.write(distFile, signedAndEncryptedDistContent);
        } catch (IOException e) {
            // do nothing
        }

        // write the file for Polyas
        try {
            Files.writeString(polyasFile, polyas.getOut().toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            // do nothing
        }

        // create a detached signature on the Polyas file content using our ephemeral key
        try {
            PGP.createSignature(polyasFile.toString(), ourSecretKey, polyasSigFile.toString(),
                                pgpPassword.toCharArray(), true);
        } catch (IOException | PGPException e) {
            // do nothing
        }

        // return the names of the files just created
        return new FileInfo(pubKeyFile, polyasFile, polyasSigFile, distFile);
    }

    /**
     * Processes the given input record `r` and adds appropriate records to
     * the CSV output [dist] and [polyas].
     * VERIFICATION TASK: prove that polyasVals does not depend on password
     */
    private void proccessCSVRecord(CSVRecord r, final String password) {
        // TODO HERE: xx
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
        distVals = inputColsForDist.stream().map(r::get).collect(Collectors.toList());
        distVals.add(0, dataForVoter.password); // TODO HERE: PASSWORD!
        try {
            // TODO HERE: ONLY GOES HERE!
            dist.printRecord(distVals);
        } catch (IOException e) {
        }

        // Polyas
        polyasVals = inputColsForPolyas.stream().map(r::get).collect(Collectors.toList());
        polyasVals.add(dataForVoter.hashedPassword);
        polyasVals.add(dataForVoter.publicSigningKey);
        try {
            // TODO HERE: SINK!
            polyas.printRecord(polyasVals);
        } catch (IOException e) {
        }
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
        } finally {
            System.out.println(print);
        }
    }
}
