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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
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

    public static ArrayList distVals;
    public static ArrayList polyasVals;

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
    private final LinkedList inputCols;

    /**
     * Columns to be included in the distributor (printing facility) file.
     */
    private final ArrayList inputColsForDist;
    // all except for the voter identifier

    /**
     * Columns to be included in the polyas file.
     */
    private final ArrayList inputColsForPolyas;

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

    //@ public static invariant polyasMode == FieldsForPolyasMode.MIN || polyasMode == FieldsForPolyasMode.MIN;

    //@ public instance invariant (\forall \bigint i; 0 <= i && i < inputCols.seq.length; ((String)inputCols.seq[i]) != null);
    //@ public instance invariant (\exists \bigint i; 0 <= i && i < inputCols.seq.length; ((String)inputCols.seq[i]) == idCol);

    //@ public instance invariant (\forall \bigint i; 0 <= i && i < inputColsForPolyas.seq.length; ((String)inputColsForPolyas.seq[i]) != null);
    //@ public instance invariant (\forall \bigint i; 0 <= i && i < inputColsForDist.seq.length; ((String)inputColsForDist.seq[i]) != null);

    //@ public instance invariant (\exists \bigint i; 0 <= i && i < inputColsForPolyas.seq.length; ((String)inputColsForPolyas.seq[i]) == idCol);

    /*@ public normal_behavior
      @ requires \static_invariant_for(CSVFormat);
      @ assignable \everything;
      @*/
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
    /*@ public normal_behavior
      @
      @ requires \static_invariant_for(java.math.BigInteger);
      @ requires \static_invariant_for(CredentialGenerator);
      @ requires \static_invariant_for(Crypto);
      @ requires \invariant_for(record);
      @ requires \invariant_for(this);
      @
      @ // Every element in inputColsForDist is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < inputColsForDist.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)inputColsForDist.seq[j])));
      @
      @ // Every element in inputColsForPolyas is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < inputColsForPolyas.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)inputColsForPolyas.seq[j])));
      @
      @ // The voter id is in the record:
      @ requires (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == idCol);
      @
      @ // The voter id contains at least one non-whitespace symbol:
      @ requires (\forall \bigint i; 0 <= i && i < record.key_seq.length;
      @     ((String)record.key_seq[i]) == idCol
      @         ==> (\exists \bigint j; 0 <= j && j < \dl_strContent((String)record.value_seq[i]).length;
      @             ((char)(\dl_strContent((String)record.value_seq[i])[j])) > '\u0020'));
      @
      @ determines polyasVals.seq \by record.key_seq, record.value_seq,
      @                               inputColsForPolyas.seq,
      @                               (\seq_def int i; 0; inputColsForPolyas.seq.length; \dl_strContent(((String)inputColsForPolyas.seq[i]))),
      @                               \dl_strContent(idCol);
      @*/
    private /*@helper@*/ void processCSVRecord(final CSVRecord record, final String password) {
        /*@ public normal_behavior
          @ requires true;
          @ ensures print != null;
          @ assignable print;
          @ determines polyasVals.seq \by \itself;
          @*/
        {
            if (input.getCurrentLineNumber() % 1000 == 0L) {
                print = "Processed " + input.getCurrentLineNumber() + " lines";
            }
        }

        final String voterId = record.get(idCol);

        if (!voterIdCheck(voterId)) {
            exit("Empty or duplicate voter id");
        }

        final GeneratedDataForVoter dataForVoter =
                CredentialGenerator.generateDataForVoter(voterId, password);

        initDistVals(record, dataForVoter);
        initPolyasVals(record, dataForVoter);
    }

    /*@ public normal_behavior
      @
      @ requires \invariant_for(record);
      @ requires \invariant_for(dataForVoter);
      @ requires \invariant_for(this);
      @
      @ // Every element in inputColsForDist is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < inputColsForDist.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)inputColsForDist.seq[j])));
      @
      @ ensures \invariant_for(record);
      @ ensures \invariant_for(dataForVoter);
      @ ensures \invariant_for(this);
      @
      @ assignable distVals;
      @
      @ determines polyasVals.seq \by \itself;
      @*/
    private /*@helper@*/ void initDistVals(final CSVRecord record, GeneratedDataForVoter dataForVoter) {
        distVals = new ArrayList();
        addInputCols(distVals, inputColsForDist, record);
        distVals.add(0, dataForVoter.password);
    }

    /*@ public normal_behavior
      @
      @ requires \invariant_for(record);
      @ requires \invariant_for(dataForVoter);
      @ requires \invariant_for(this);
      @
      @ // Every element in inputColsForPolyas is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < inputColsForPolyas.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)inputColsForPolyas.seq[j])));
      @
      @ assignable polyasVals;
      @
      @ determines polyasVals.seq \by record.key_seq, record.value_seq,
      @                               inputColsForPolyas.seq,
      @                               (\seq_def int i; 0; inputColsForPolyas.seq.length; \dl_strContent(((String)inputColsForPolyas.seq[i]))),
      @                               dataForVoter.hashedPassword, dataForVoter.publicSigningKey;
      @*/
    private /*@helper@*/ void initPolyasVals(final CSVRecord record, GeneratedDataForVoter dataForVoter) {
        initPolyasVals_addInputCols(record, dataForVoter);
        initPolyasVals_addDataForVoter(record, dataForVoter);
    }

    /*@ public normal_behavior
      @
      @ requires \invariant_for(record);
      @ requires \invariant_for(dataForVoter);
      @ requires \invariant_for(this);
      @
      @ // Every element in inputColsForPolyas is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < inputColsForPolyas.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)inputColsForPolyas.seq[j])));
      @
      @ ensures polyasVals != null && \invariant_for(polyasVals);
      @ ensures \invariant_for(dataForVoter);
      @ ensures \fresh(polyasVals) && \fresh(polyasVals.*);
      @
      @ assignable polyasVals;
      @ determines polyasVals \by \nothing \new_objects polyasVals;
      @ determines polyasVals.seq \by record.key_seq, record.value_seq,
      @                               inputColsForPolyas.seq,
      @                               (\seq_def int i; 0; inputColsForPolyas.seq.length; \dl_strContent(((String)inputColsForPolyas.seq[i])));
      @*/
    private /*@helper@*/ void initPolyasVals_addInputCols(final CSVRecord record, GeneratedDataForVoter dataForVoter) {
        polyasVals = new ArrayList();
        addInputCols(polyasVals, inputColsForPolyas, record);
    }

    /*@ public normal_behavior
      @ requires polyasVals != null && \invariant_for(polyasVals);
      @ requires \invariant_for(dataForVoter);
      @ assignable polyasVals.seq;
      @ determines polyasVals.seq \by polyasVals.seq, dataForVoter.hashedPassword, dataForVoter.publicSigningKey;
      @*/
    private /*@helper@*/ void initPolyasVals_addDataForVoter(final CSVRecord record, GeneratedDataForVoter dataForVoter) {
        polyasVals.add(dataForVoter.hashedPassword);
        polyasVals.add(dataForVoter.publicSigningKey);
    }

    /*@ public normal_behavior
      @
      @ // Every element in cols is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < cols.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)cols.seq[j])));
      @
      @ requires (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
      @ requires vals != cols;
      @ requires \invariant_for(record);
      @ requires \invariant_for(vals);
      @ requires \invariant_for(cols);
      @ ensures \invariant_for(record);
      @ ensures \invariant_for(vals);
      @ ensures \invariant_for(cols);
      @ assignable vals.seq;
      @ determines vals.seq \by vals.seq, cols.seq, record.key_seq, record.value_seq, (\seq_def int i; 0; cols.seq.length; \dl_strContent(((String)cols.seq[i])));
      @*/
    private /*@helper@*/ void addInputCols(ArrayList vals, ArrayList cols, CSVRecord record) {
        Iterator it = cols.iterator();
        addInputColsHelper(vals, cols, record, it);
    }
    /*@ public normal_behavior
      @
      @ // Every element in cols is in the record:
      @ requires (\forall \bigint j; 0 <= j && j < cols.seq.length;
      @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)cols.seq[j])));
      @
      @ requires (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
      @ requires vals != cols;
      @ requires \invariant_for(record);
      @ requires \invariant_for(vals);
      @ requires \invariant_for(cols);
      @ requires \invariant_for(it);
      @ requires it instanceof java.util.CollectionIterator;
      @ requires it.seq == cols.seq;
      @ ensures \invariant_for(record);
      @ ensures \invariant_for(vals);
      @ ensures \invariant_for(cols);
      @ assignable vals.seq, it.index;
      @ determines vals.seq, it.seq, it.index, record.key_seq, record.value_seq, (\seq_def int i; 0; it.seq.length; \dl_strContent(((String)it.seq[i]))) \by \itself;
      @*/
    private /*@helper@*/ void addInputColsHelper(ArrayList vals, ArrayList cols, CSVRecord record, Iterator it) {
        /*@ loop_invariant (\forall \bigint j; 0 <= j && j < cols.seq.length;
          @     (\exists \bigint i; 0 <= i && i < record.key_seq.length; ((String)record.key_seq[i]) == ((String)cols.seq[j])));
          @ loop_invariant (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
          @ loop_invariant vals != cols;
          @ loop_invariant \invariant_for(record);
          @ loop_invariant \invariant_for(vals);
          @ loop_invariant \invariant_for(cols);
          @ loop_invariant \invariant_for(it);
          @ loop_invariant it != null && record != null && vals != null && cols != null;
          @ loop_invariant it instanceof java.util.CollectionIterator;
          @ loop_invariant it.seq == cols.seq;
          @ decreases it.seq.length - it.index;
          @ assignable vals.seq, it.index;
          @ determines vals.seq, it.seq, it.index, record.key_seq, record.value_seq, (\seq_def int i; 0; it.seq.length; \dl_strContent(((String)it.seq[i]))) \by \itself;
          @*/
        while (it.hasNext()) {
            addInputCol(vals, (String) it.next(), record);
        }
    }

    /*@ public normal_behavior
      @ requires (\exists \bigint i; 0 <= i && i < r.key_seq.length; ((String)r.key_seq[i]) == key);
      @ requires \invariant_for(r);
      @ requires \invariant_for(vals);
      @ ensures \invariant_for(r);
      @ ensures \invariant_for(vals);
      @ assignable vals.seq;
      @ determines vals.seq \by vals.seq, r.key_seq, r.value_seq, \dl_strContent(key);
      @*/
    private /*@helper@*/ void addInputCol(ArrayList vals, String key, CSVRecord r) {
        vals.add(r.get(key));
    }

    /**
     * Applied to consecutive voters ids (as read from the input file),
     * checks whether voter id's are unique and not empty.
     * It maintains a state (a mutable hash set).
     */
    /*@ public normal_behavior
      @ requires (\exists \bigint i; 0 <= i && i < \dl_strContent(voterId).length; ((char)\dl_strContent(voterId)[i]) > '\u0020');
      @ ensures \result == true;
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @*/
    private /*@helper@*/ boolean voterIdCheck(final String voterId) {
        return !voterId.trim().isEmpty();
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

    /*@ public normal_behavior
      @ assignable \nothing;
      @*/
    private /*@helper@*/ PGPPublicKey readPublicKey(final String key) {
        try {
            return PGP.readPublicKey(key);
        } catch (Exception e) {
            return null;
        }
    }

    /*@ public normal_behavior
      @ requires \static_invariant_for(CredTool);
      @ requires \static_invariant_for(CSVFormat);
      @ ensures (\forall \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) != null);
      @ ensures_free (\exists \bigint i; 0 <= i && i < result.seq.length; ((String)\result.seq[i]) == idCol);
      @ assignable \nothing;
      @*/
    private /*@helper@*/ LinkedList parseInputCols(final String fileName) {
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

    /*@ public normal_behavior
      @ requires (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
      @ ensures (\forall \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) != null);
      @ ensures \invariant_for(\result);
      @ assignable \nothing;
      @*/
    private static ArrayList extractInputColsForDist(final LinkedList cols, final String id) {
        final ArrayList result = new ArrayList();

        final Iterator it = cols.iterator();

        /*@ loop_invariant \invariant_for(it);
          @ loop_invariant it.seq == cols.seq;
          @ loop_invariant (\forall \bigint i; 0 <= i && i < result.seq.length; ((String)result.seq[i]) != null);
          @ decreases cols.seq.length - it.index;
          @ assignable result.seq, it.index;
          @*/
        while (it.hasNext()) {
            String next = (String) it.next();

            if (!id.equals(next)) {
                result.add(next);
            }
        }

        return result;
    }

    /*@ public normal_behavior
      @ requires (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
      @ requires (\exists \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) == id);
      @ ensures (\forall \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) != null);
      @ ensures (\exists \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) == id);
      @ ensures \invariant_for(\result);
      @ assignable \nothing;
      @*/
    private static ArrayList extractInputColsForPolyas(final LinkedList cols, final String id) {
        ArrayList result = new ArrayList();
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
      @ requires \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static CSVParser parseInput(final String fileName) {
        return parse(CSVFormat.RFC4180.withFirstRecordAsHeader().withDelimiter(DELIMITER),
                     fileName);
    }

    /*@ public normal_behavior
      @ requires \invariant_for(cols);
      @ requires (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
      @ requires \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static CSVPrinter printPolyas(final ArrayList cols) {
        return print(CSVFormat.RFC4180.withDelimiter(DELIMITER)
                     .withHeader(toArray(toList(toList(cols, HASHED_PASSWORD_COL),
                                          PUBLIC_SIGNING_KEY_COL)))); // order is important!
    }

    /*@ public normal_behavior
      @ requires \invariant_for(cols);
      @ requires (\forall \bigint i; 0 <= i && i < cols.seq.length; ((String)cols.seq[i]) != null);
      @ requires \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static CSVPrinter printDist(final ArrayList cols) {
        return print(CSVFormat.RFC4180.withDelimiter(DELIMITER)
                     .withHeader(toArray(toList(PASSWORD_COL, cols)))); // order is important!
    }

    /*@ public normal_behavior
      @ requires \invariant_for(ls);
      @ requires (\forall \bigint i; 0 <= i && i < ls.seq.length; ((String)ls.seq[i]) != null);
      @ requires \static_invariant_for(CSVFormat);
      @ ensures \invariant_for(\result);
      @ ensures (\forall \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) != null);
      @ ensures \fresh(\result) && \fresh(\result.*);
      @ ensures \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static ArrayList toList(ArrayList ls) {
        return new ArrayList(ls);
    }

    /*@ public normal_behavior
      @ requires \invariant_for(ls);
      @ requires (\forall \bigint i; 0 <= i && i < ls.seq.length; ((String)ls.seq[i]) != null);
      @ requires \static_invariant_for(CSVFormat);
      @ ensures \invariant_for(\result);
      @ ensures (\forall \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) != null);
      @ ensures \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static ArrayList toList(ArrayList ls, String s) {
        ArrayList list = toList(ls);
        list.add(s);
        return list;
    }

    /*@ public normal_behavior
      @ requires \invariant_for(ls);
      @ requires (\forall \bigint i; 0 <= i && i < ls.seq.length; ((String)ls.seq[i]) != null);
      @ requires \static_invariant_for(CSVFormat);
      @ ensures \invariant_for(\result);
      @ ensures (\forall \bigint i; 0 <= i && i < \result.seq.length; ((String)\result.seq[i]) != null);
      @ ensures \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static ArrayList toList(String s, ArrayList ls) {
        final ArrayList list = (ArrayList) Arrays.asList(s);
        final int len = ls.size();
        /*@ loop_invariant \invariant_for(ls);
          @ loop_invariant \invariant_for(list);
          @ loop_invariant 0 <= i && i <= len;
          @ loop_invariant \invariant_for(list);
          @ loop_invariant len == ls.seq.length;
          @ loop_invariant (\forall \bigint i; 0 <= i && i < ls.seq.length; ((String)ls.seq[i]) != null);
          @ loop_invariant (\forall \bigint i; 0 <= i && i < list.seq.length; ((String)list.seq[i]) != null);
          @ loop_invariant \static_invariant_for(CSVFormat);
          @ decreases len - i;
          @ assignable list.seq;
          @*/
        for (int i = 0; i < len; i++) {
            list.add(ls.get(i));
        }
        return list;
    }

    /*@ public normal_behavior
      @ requires \invariant_for(list);
      @ requires (\forall \bigint i; 0 <= i && i < list.seq.length; ((String)list.seq[i]) != null);
      @ requires \static_invariant_for(CSVFormat);
      @ ensures \dl_nonNull(\result, 1);
      @ ensures \static_invariant_for(CSVFormat);
      @ assignable \nothing;
      @*/
    private static String[] toArray(ArrayList list) {
        final int len = list.size();
        final String[] arr = new String[len];
        /*@ loop_invariant \invariant_for(list);
          @ loop_invariant len == list.seq.length && len == arr.length;
          @ loop_invariant (\forall \bigint i; 0 <= i && i < list.seq.length; ((String)list.seq[i]) != null);
          @ loop_invariant 0 <= i && i <= len;
          @ loop_invariant arr != null && (\forall \bigint j; 0 <= j && j < i; arr[j] != null);
          @ loop_invariant \static_invariant_for(CSVFormat);
          @ decreases len - i;
          @ assignable arr[*];
          @*/
        for (int i = 0; i < len; i++) {
            arr[i] = (String)list.get(i);
        }
        return arr;
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
