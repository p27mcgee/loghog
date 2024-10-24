package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;

public class LmclShred extends Shred {
    public static final String TBL_NAME = "lmcl";
    public static final String CREATE_TBL_SQL =
            "create table lmcl(" +
                    "line integer primary key references log(line)," +
                    "class text not null," +
                    "package text not null," +
                    "result text," +
                    "location text," +
                    "adapters text)";
    public static final List<String> TBL_INDEX_SQLS = Arrays.asList(
            "create index idx_lmcl_package on lmcl(package)",
            "create index idx_lmcl_class_package on lmcl(class, package)"
    );
    public static final ShredTableCreator TBL_CREATOR = new ShredTableCreator(TBL_NAME, CREATE_TBL_SQL, TBL_INDEX_SQLS);

    public static final String ENTRY_SIGNATURE = "!LM!ClassLoad|";
    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(ENTRY_SIGNATURE);

    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier();

    public static final List<String> EXTRACTED_VAL_NAMES = Arrays.asList("fqcn", "result", "adapters", "location");
    public static final Map<String, Pattern> VALUE_EXTRACTORS = new HashMap<String, Pattern>() {{
        put(Shred.DEFAULT_TYPE, Pattern.compile(
                "!LM!ClassLoad\\|(?<fqcn>[^|]+)\\|result=(?<result>[^&]+)&adapters=(?<adapters>[^&]*)&location=(?<location>.*)$"
        ));
    }};
    public static final ShredValueExtractor VALUE_EXTRACTOR = new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    public static final List<String> INSERT_COLUMNS = Arrays.asList("line", "class", "package", "result", "location", "adapters");

    public LmclShred() {
        super(TBL_CREATOR, ENTRY_SELECTOR, ENTRY_CLASSIFIER, VALUE_EXTRACTOR, INSERT_COLUMNS);
    }

    @Override
    public Object[] transformValues(int line, String entry, String type, Map<String, String> extractedVals) {
        String[] classAndPackage = classAndPackage(extractedVals.get("fqcn"));
        String classname = classAndPackage[0];
        String packageName = classAndPackage[1];
        return new Object[] { line, classname, packageName, extractedVals.get("result"), extractedVals.get("location"), extractedVals.get("adapters") };
    }

    private String[] classAndPackage(String fqcn) {
        int lastDotIndex = fqcn.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return new String[] { fqcn, "" };
        }
        String classname = fqcn.substring(lastDotIndex + 1);
        String packageName = fqcn.substring(0, lastDotIndex);
        return new String[] { classname, packageName };
    }

    public static void main(String[] args) {
        String logname = "sb-san-petclinic";
        if (args.length > 0) {
            logname = args[0];
        }
        String debugDb = logname + ".db";
        try (Connection connection = createdb.connectdb(debugDb)) {
            LmclShred lmclShred = new LmclShred();
            lmclShred.initializeTables(connection);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}