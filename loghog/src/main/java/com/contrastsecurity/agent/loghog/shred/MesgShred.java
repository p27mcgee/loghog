/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import static com.contrastsecurity.agent.loghog.shred.PatternGroup.*;
import static com.contrastsecurity.agent.loghog.shred.ShredEntrySelector.ALL_ENTRIES_SIGNATURE;
import static com.contrastsecurity.agent.loghog.shred.ShredEntrySelector.ALL_ENTRIES_SQL;

import com.contrastsecurity.agent.loghog.sql.SqlTableBase;
import java.util.*;
import java.util.regex.Pattern;

public class MesgShred extends Shred {

    public MesgShred() {
        super(
                new SqlTableBase(
                        MESG_TBL_NAME, MESG_TBL_CREATE_SQL, MESG_TBL_INDEX_SQLS, MESG_TBL_COLUMNS),
                new SqlTableBase(
                        CONTINUATIONS_TBL_NAME,
                        CONTINUATIONS_TBL_CREATE_SQL,
                        CONTINUATIONS_TBL_INDEX_SQLS,
                        CONTINUATIONS_TBL_COLUMNS),
                ENTRY_SELECTOR,
                ENTRY_CLASSIFIER,
                VALUE_EXTRACTOR);
    }

    @Override
    public Object[] transformValues(
            int line, String entry, String type, Map<String, Object> extractedVals) {
        return new Object[] {
            line,
            extractedVals.get("timestamp"),
            extractedVals.get("thread"),
            extractedVals.get("logger"),
            extractedVals.get("level"),
            extractedVals.get("message")
        };
    }

    @Override
    public Object[] transformMisfits(int line, int lastGoodLine) {
        return new Object[] {line, lastGoodLine};
    }

    // Shred table "mesg"
    public static final String MESG_TBL_NAME = "mesg";
    public static final String MESG_TBL_CREATE_SQL =
            """
create table mesg(
    line DECIMAL primary key references log(line),
    timestamp datetime not null,
    thread text not null,
    logger text not null,
    level text not null,
    message text not null)
""";
    public static final List<String> MESG_TBL_INDEX_SQLS =
            Arrays.asList(
                    "create index idx_mesg_line on mesg(line)",
                    "create index idx_mesg_thread on mesg(thread)");
    public static final List<String> MESG_TBL_COLUMNS =
            Arrays.asList("line", "timestamp", "thread", "logger", "level", "message");

    // Selects all lines from log table
    public static final ShredEntrySelector ENTRY_SELECTOR =
            new ShredEntrySelector(ALL_ENTRIES_SIGNATURE, ALL_ENTRIES_SQL, 2000);

    // Just one pattern type. Because we just have one pattern we don't really
    // need the classifier.  Misfit entries (continuation lines) are identified by the failure
    // of an entry to match our default pattern
    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier();

    public static final List<String> EXTRACTED_VAL_NAMES =
            Arrays.asList(TIMESTAMP_VAR, THREAD_VAR, LOGGER_VAR, LEVEL_VAR, "message");
    public static final Map<String, Pattern> VALUE_EXTRACTORS =
            new HashMap<String, Pattern>() {
                {
                    put(
                            Shred.DEFAULT_TYPE,
                            Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$"));
                }
            };
    public static final ShredValueExtractor VALUE_EXTRACTOR =
            new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    // Shred misfits table "cont" identifies "continuation" lines from log file that
    // don't include the normal timestamp, thread, class, log level preamble because they
    // are continuation lines from a preceding multi-line log message
    public static final String CONTINUATIONS_TBL_NAME = "cont";
    public static final String CONTINUATIONS_TBL_CREATE_SQL =
"""
create table cont(
    foreign key (line) references log(line),
    foreign key (mesg) references mesg(line)
""";
    public static final List<String> CONTINUATIONS_TBL_INDEX_SQLS = List.of();
    public static final List<String> CONTINUATIONS_TBL_COLUMNS = Arrays.asList("line", "mesg");
}
