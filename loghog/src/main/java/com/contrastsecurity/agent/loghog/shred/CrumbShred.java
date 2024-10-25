package com.contrastsecurity.agent.loghog.shred;

import java.util.*;
import java.util.regex.Pattern;

public class CrumbShred extends Shred {
    public static final String TBL_NAME = "crumb";
    public static final String CREATE_TBL_SQL =
            "create table crumb(" +
                    "line integer primary key references log(line)," +
                    "type text," +
                    "req text," +
                    "resp text," +
                    "url text," +
                    "crumbthread text," +
                    "crumbtime datetime," +
                    "stackframe text)";
    public static final List<String> TBL_INDEX_SQLS = Arrays.asList(
            "create index idx_crumb_url on crumb(url)"
    );
    public static final ShredTableCreator TBL_CREATOR = new ShredTableCreator(TBL_NAME, CREATE_TBL_SQL, TBL_INDEX_SQLS);

    public static final String ENTRY_SIGNATURE = " CRUMB ";
    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(ENTRY_SIGNATURE);

    public static final Map<String, List<String>> TYPE_SIGNATURES = new HashMap<String, List<String>>() {{
        put("hist_req_begin", Arrays.asList("request@", "\t\t\tBEGIN "));
        put("req_begin", Arrays.asList("request@", "\t\tBEGIN "));
        put("hist_resp_begin", Arrays.asList("response@", "\t\t\tBEGIN "));
        put("resp_begin", Arrays.asList("response@", "\t\tBEGIN "));
        put("req_end", Arrays.asList("request@", "END & HISTORY:"));
        put("resp_end", Arrays.asList("response@", "END & HISTORY:"));
    }};
    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier(TYPE_SIGNATURES);

    public static final List<String> EXTRACTED_VAL_NAMES = Arrays.asList("req", "resp", "url", "crumbthread", "log_timestamp", "stackframe");
    public static final Map<String, Pattern> VALUE_EXTRACTORS = new HashMap<String, Pattern>() {{
        put("hist_req_begin", Pattern.compile(LOG_TIMESTAMP_EXTRACTOR + " " + LOG_THREAD_EXTRACTOR + " " + LOG_LEVEL_DEBUG + " -  CRUMB request@(?<req>\\S+) (?<url>\\S+)\\t\\t\\tBEGIN.+(?<resp>~NORESP~)?(?<stackframe>~NOFRAME~)?$"));
        put("req_begin", Pattern.compile("(?<crumbtime>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}) \\[(?<crumbthread>\\S+) \\S+] DEBUG - CRUMB request@(?<req>\\S+) (?<url>\\S+)\\t\\tBEGIN.+(?<resp>~NORESP~)?(?<stackframe>~NOFRAME~)?$"));
        put("hist_resp_begin", Pattern.compile("(?<crumbtime>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}) \\[(?<crumbthread>\\S+) \\S+] DEBUG - CRUMB response@(?<resp>\\S+) \\t\\t\\tBEGIN.+(?<req>~NOREQ~)?(?<url>~NOURL~)?(?<stackframe>~NOFRAME~)?$"));
        put("resp_begin", Pattern.compile("(?<crumbtime>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}) \\[(?<crumbthread>\\S+) \\S+] DEBUG - CRUMB response@(?<resp>\\S+) \\t\\tBEGIN.+(?<req>~NOREQ~)?(?<url>~NOURL~)?(?<stackframe>~NOFRAME~)?$"));
        put("req_end", Pattern.compile("(?<crumbtime>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}) \\[(?<crumbthread>\\S+) \\S+] DEBUG - CRUMB request@(?<req>\\S+) (?<url>\\S+) END & HISTORY:(?<resp>~NORESP~)?(?<stackframe>~NOFRAME~)?$"));
        put("resp_end", Pattern.compile("(?<crumbtime>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}) \\[(?<crumbthread>\\S+) \\S+] DEBUG - CRUMB response@(?<resp>\\S+)  END & HISTORY:(?<req>~NOREQ~)?(?<url>~NOURL~)?(?<stackframe>~NOFRAME~)?$"));
        put(Shred.DEFAULT_TYPE, Pattern.compile("^~NOMATCH~$"));
    }};
    public static final ShredValueExtractor VALUE_EXTRACTOR = new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    public static final List<String> INSERT_COLUMNS = Arrays.asList("line", "type", "req", "resp", "url", "crumbthread", "crumbtime", "stackframe");

    public CrumbShred() {
        super(TBL_CREATOR, ENTRY_SELECTOR, ENTRY_CLASSIFIER, VALUE_EXTRACTOR, INSERT_COLUMNS);
    }
}
