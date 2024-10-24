package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.db.CreateDb;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;

public class AcelShred extends Shred {
    public static final String TBL_NAME = "acel";
    public static final String CREATE_TBL_SQL =
            "create table acel(" +
                    "line integer primary key references log(line)," +
                    "class text not null," +
                    "package text not null," +
                    "application text," +
                    "location text)";
    public static final List<String> TBL_INDEX_SQLS = Arrays.asList(
            "create index idx_acel_package on acel(package)",
            "create index idx_acel_class_package on acel(class, package)"
    );
    public static final ShredTableCreator TBL_CREATOR = new ShredTableCreator(TBL_NAME, CREATE_TBL_SQL, TBL_INDEX_SQLS);

    public static final String ENTRY_SIGNATURE = " ApplicationClassEventListener] ";
    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(ENTRY_SIGNATURE);

    public static final Map<String, String> TYPE_SIGNATURES = new HashMap<String, String>() {{
        put("noput", "- Not putting ");
        put("noapp", "- Couldn't find app for ");
        put("orphan", " to orphanage");
        put("uninventoried", "missed classload events");
        put("contains", "- url @detectLibraryClass");
        put("nolib", "- No library found");
        put("adopted", "from orphanage by CodeSource path");
        put("used", " to library usage for lib ");
    }};
    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier(TYPE_SIGNATURES);

    public static final List<String> EXTRACTED_VAL_NAMES = Arrays.asList("fqcn", "location", "application");
    public static final Map<String, Pattern> VALUE_EXTRACTORS = new HashMap<String, Pattern>() {{
        put("noput", Pattern.compile(
                "\\- Not putting (?<fqcn>\\S+) in orphanage as its from (?<location>~NOLOC~)?(?<application>~NOAPP~)?"
        ));
        put("noapp", Pattern.compile(
                "\\- Couldn't find app for (?<fqcn>\\S+) with CodeSource path (?<application>~NOAPP~)?(?<location>.*)$"
        ));
        put("orphan", Pattern.compile(
                "\\- Adding (?<fqcn>\\S+) to orphanage(?<location>~NOLOC~)?(?<application>~NOAPP~)?$"
        ));
        put("uninventoried", Pattern.compile(
                "\\- Adding (?<fqcn>\\S+) to list of missed classload events for uninventoried (?<location>~NOLOC~)?(?<application>.*)$"
        ));
        put("contains", Pattern.compile(
                "\\- url \\@detectLibraryClass (?<location>.+) contains (?<fqcn>\\S+) for app \".+\" \\((?<application>.*)\\)$"
        ));
        put("nolib", Pattern.compile(
                "\\- No library found for \\S+ in app \".+\" (?<location>~NOLOC~)?(?<fqcn>~NOCLASS~)?\\((?<application>.*)\\)$"
        ));
        put("adopted", Pattern.compile(
                "\\- Took (?<fqcn>\\S+) from orphanage by CodeSource path (?<location>.+) and passing to app \"(?<application>.*)\"$"
        ));
        put("used", Pattern.compile(
                "\\- Adding (?<fqcn>\\S+) to library usage for lib (?<jarname>\\S+) in app (?<location>~NOLOC~)?\".+\" \\((?<application>.*)\\)$"
        ));
        put(Shred.DEFAULT_TYPE, Pattern.compile("^~NOMATCH~$"));
    }};
    public static final ShredValueExtractor VALUE_EXTRACTOR = new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    public static final List<String> INSERT_COLUMNS = Arrays.asList("line", "type", "class", "package", "application", "location");

    public AcelShred() {
        super(TBL_CREATOR, ENTRY_SELECTOR, ENTRY_CLASSIFIER, VALUE_EXTRACTOR, INSERT_COLUMNS);
    }

    @Override
    public Object[] transformValues(int line, String entry, String type, Map<String, String> extractedVals) {
        String[] classAndPackage = classAndPackage(extractedVals.get("fqcn"));
        String classname = classAndPackage[0];
        String packageName = classAndPackage[1];
        return new Object[] { line, type, classname, packageName, extractedVals.get("application"), extractedVals.get("location") };
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            throw new IllegalArgumentException("Missing command line parameter for log name.");
        }

        String logname = args[0];
        String debugDb = Paths.get("", logname + ".db").toString();

        try (Connection connection = CreateDb.connectDb(debugDb)) {
            AcelShred acelShred = new AcelShred();
            acelShred.initializeTables(connection);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
