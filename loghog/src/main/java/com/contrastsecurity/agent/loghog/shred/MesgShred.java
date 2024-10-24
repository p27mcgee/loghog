package com.contrastsecurity.agent.loghog.shred;

import java.util.*;
import java.util.regex.Pattern;

public class MesgShred extends Shred {
    public static final String TBL_NAME = "mesg";
    public static final String MISFITS_TBL_NAME = "cont";
    public static final String CREATE_TBL_SQL =
            "create table mesg(" +
                    "line integer primary key references log(line)," +
                    "timestamp datetime not null," +
                    "thread text not null," +
                    "logger text not null," +
                    "level text not null," +
                    "message text not null)";
    public static final List<String> TBL_INDEX_SQLS = Arrays.asList(
            "create index idx_mesg_logger on mesg(logger)",
            "create index idx_mesg_level_package on mesg(level)"
    );
    public static final String CREATE_MISFITS_SQL =
            "create table cont(" +
                    "line integer primary key references log(line)," +
                    "mesg integer key references mesg(line))";
    public static final ShredTableCreator TBL_CREATOR = new ShredTableCreator(TBL_NAME, CREATE_TBL_SQL, TBL_INDEX_SQLS, MISFITS_TBL_NAME, CREATE_MISfits_SQL);

    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(2000); // selects all by default
    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier(); // just one default type

    public static final List<String> EXTRACTED_VAL_NAMES = Arrays.asList("timestamp", "thread", "logger", "level", "message");
    public static final Map<String, Pattern> VALUE_EXTRACTORS = new HashMap<String, Pattern>() {{
        put(Shred.DEFAULT_TYPE, Pattern.compile(
                "^(?<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}) \\[(?<thread>.+) (?<logger>\\S+)\\] (?<level>\\S+) -( (?<message>.*))?$"
        ));
    }};
    public static final ShredValueExtractor VALUE_EXTRACTOR = new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    public static final List<String> INSERT_COLUMNS = Arrays.asList("line", "timestamp", "thread", "logger", "level", "message");
    public static final String INSERT_MISFITS_SQL = String.format("insert into %s (line, mesg) values (?,?)", MISFITS_TBL_NAME);

    public MesgShred() {
        super(TBL_CREATOR, ENTRY_SELECTOR, ENTRY_CLASSIFIER, VALUE_EXTRACTOR, INSERT_COLUMNS, INSERT_MISFITS_SQL, false);
    }

    @Override
    public Object[] transformValues(int line, String entry, String type, Map<String, String> extractedVals) {
        return new Object[] { line, extractedVals.get("timestamp"), extractedVals.get("thread"), extractedVals.get("logger"), extractedVals.get("level"), extractedVals.get("message") };
    }

    @Override
    public Object[] transformMisfits(int line, int lastGoodLine) {
        return new Object[] { line, lastGoodLine };
    }

    public static final String SELECT_MULTILINE_ENTRIES_SQL =
            "select line, entry " +
                    "from log " +
                    "where line in (";
}
