package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Shred {
    public static final String DEFAULT_TYPE = "default";

    private String tblName;
    private String createTblSql;
    private List<String> tblIndexSqls;
    private String misfitsTblName;
    private String createMisfitsSql;
    private List<String> misfitsIndexSqls;
    private String dropTblSql;
    private String dropMisfitsSql;
    private final boolean showMisfits;

    public Shred(String tblName, String createTblSql, List<String> tblIndexSqls,
                 String misfitsTblName, String createMisfitsSql, final boolean showMisfits) {
        this.tblName = tblName;
        this.createTblSql = createTblSql;
        this.tblIndexSqls = tblIndexSqls != null ? tblIndexSqls : List.of();
        this.dropTblSql = "drop table if exists " + this.tblName;
        if (misfitsTblName == null) {
            this.misfitsTblName = tblName + "_misfits";
        } else {
            this.misfitsTblName = misfitsTblName;
        }
        if (createMisfitsSql == null) {
            this.createMisfitsSql = "create table " + this.misfitsTblName + "( line integer primary key references log(line))";
        } else {
            this.createMisfitsSql = createMisfitsSql;
        }
        this.misfitsIndexSqls = misfitsIndexSqls != null ? misfitsIndexSqls : List.of();
        this.dropMisfitsSql = "drop table if exists " + this.misfitsTblName;
        this.showMisfits = showMisfits;
    }

    public void createTables(Connection connection) {
        createEmptyTable(connection);
        createEmptyMisfitsTable(connection);
        populate_tables(connection);
    }

    // TODO recreate or keep
    protected void createEmptyTable(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(dropTblSql);
            stmt.execute(createTblSql);
            for (String indexSql : tblIndexSqls) {
                stmt.execute(indexSql);
            }
        }
    }

    // TODO recreate or keep
    protected void createEmptyMisfitsTable(Connection connection) throws SQLException {
        if (misfitsTblName != null && !misfitsTblName.isEmpty()) {
            try (Statement stmt = connection.createStatement()) {
                stmt.execute(dropMisfitsSql);
                stmt.execute(createMisfitsSql);
                for (String indexSql : misfitsIndexSqls) {
                    stmt.execute(indexSql);
                }
            }
        }
    }

    public Shred(final boolean showMisfits) {
        this.showMisfits = showMisfits;
    }

    static class ShredEntryClassifier {
        private Map<String, Object> patternSignatures;
        public static final String DEFAULT_PATTERN_ID = "default";

        public ShredEntryClassifier() {
            this(null);
        }

        public ShredEntryClassifier(Map<String, Object> typeSignatures) {
            if (typeSignatures == null) {
                this.patternSignatures = new HashMap<>();
                this.patternSignatures.put(DEFAULT_PATTERN_ID, "");
            } else {
                this.patternSignatures = typeSignatures;
            }
        }

        public String findPatternId(String entry) {
            for (Map.Entry<String, Object> typeSignature : patternSignatures.entrySet()) {
                String type = typeSignature.getKey();
                Object signature = typeSignature.getValue();
                if (signature instanceof List) {
                    boolean isType = true;
                    for (String part : (List<String>) signature) {
                        if (!entry.contains(part)) {
                            isType = false;
                            break;
                        }
                    }
                    if (isType) {
                        return type;
                    }
                } else {
                    if (entry.contains((String) signature)) {
                        return type;
                    }
                }
            }
            return DEFAULT_PATTERN_ID;
        }
    }

    public static class ShredEntrySelector {
        public static final String ALL_ENTRIES_SIGNATURE = "";
        public static final String ALL_ENTRIES_SQL = "select line, entry from log";
        private String entrySignature;
        private String selectEntriesSql;
        private int batchSize;

        public ShredEntrySelector(String entrySignature, String selectEntriesSql, int batchSize) {
            if (entrySignature == null) {
                this.entrySignature = "";
            } else {
                this.entrySignature = entrySignature;
            }
            if (selectEntriesSql == null) {
                this.selectEntriesSql = "select line, entry from log where entry like '%" + this.entrySignature + "%'";
            } else {
                this.selectEntriesSql = selectEntriesSql;
            }
            this.batchSize = batchSize;
        }

        public List<List<Object[]>> selectBatches(Connection connection) throws SQLException {
            List<List<Object[]>> batches = new ArrayList<>();
            try (PreparedStatement stmt = connection.prepareStatement(this.selectEntriesSql)) {
                ResultSet rs = stmt.executeQuery();
                while (true) {
                    List<Object[]> rows = new ArrayList<>();
                    for (int i = 0; i < this.batchSize && rs.next(); i++) {
                        rows.add(new Object[]{rs.getInt("line"), rs.getString("entry")});
                    }
                    if (rows.isEmpty()) {
                        break;
                    }
                    batches.add(rows);
                }
            }
            return batches;
        }
    }

    static class ShredValueExtractor {
        private List<String> extractedValNames;
        private Map<String, Pattern> valueExtractors;
        public static final String DEFAULT_PATTERN_ID = "default";

        public ShredValueExtractor(List<String> extractedValNames, Map<String, Pattern> valueExtractors) {
            if (extractedValNames == null) {
                this.extractedValNames = new ArrayList<>();
            } else {
                this.extractedValNames = extractedValNames;
            }
            if (valueExtractors == null) {
                this.valueExtractors = new HashMap<>();
                this.valueExtractors.put(DEFAULT_PATTERN_ID, Pattern.compile(""));
            } else {
                this.valueExtractors = valueExtractors;
            }
        }

        public Map<String, String> extractValues(String patternId, String entry) {
            Map<String, String> extractedVals = new HashMap<>();
            Pattern extractor = this.valueExtractors.get(patternId);
            if (extractor != null) {
                Matcher match = extractor.matcher(entry);
                if (match.find()) {
                    for (String extractedValName : this.extractedValNames) {
                        extractedVals.put(extractedValName, match.group(extractedValName));
                    }
                }
            }
            return extractedVals;
        }
    }
}

