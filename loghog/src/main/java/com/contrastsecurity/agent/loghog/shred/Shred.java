package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Shred {
    private String selectEntriesSql;
    private int batchSize;

    public Shred(String entrySignature, String selectEntriesSql, int batchSize) {
        if (entrySignature != null) {
            this.selectEntriesSql = "select line, entry from log where entry like '%" + entrySignature + "%'";
        } else {
            this.selectEntriesSql = selectEntriesSql;
        }
        this.batchSize = batchSize;
    }

    public List<Map<String, Object>> selectBatches(Connection connection) throws SQLException {
        List<Map<String, Object>> batches = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(this.selectEntriesSql)) {
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("line", rs.getInt("line"));
                row.put("entry", rs.getString("entry"));
                batches.add(row);
                if (batches.size() >= this.batchSize) {
                    break;
                }
            }
        }
        return batches;
    }
}

class ShredEntryClassifier {
    private Map<String, Object> typeSignatures;
    public static final String DEFAULT_TYPE = "default";

    public ShredEntryClassifier(Map<String, Object> typeSignatures) {
        if (typeSignatures == null) {
            this.typeSignatures = new HashMap<>();
            this.typeSignatures.put(DEFAULT_TYPE, "");
        } else {
            this.typeSignatures = typeSignatures;
        }
    }

    public String findType(String entry) {
        for (Map.Entry<String, Object> typeSignature : typeSignatures.entrySet()) {
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
        return DEFAULT_TYPE;
    }
}

class ShredValueExtractor {
    private List<String> extractedValNames;
    private Map<String, Pattern> valueExtractors;
    public static final String DEFAULT_TYPE = "default";

    public ShredValueExtractor(List<String> extractedValNames, Map<String, Pattern> valueExtractors) {
        if (extractedValNames == null) {
            this.extractedValNames = new ArrayList<>();
        } else {
            this.extractedValNames = extractedValNames;
        }
        if (valueExtractors == null) {
            this.valueExtractors = new HashMap<>();
            this.valueExtractors.put(DEFAULT_TYPE, Pattern.compile(""));
        } else {
            this.valueExtractors = valueExtractors;
        }
    }

    public Map<String, String> extractValues(String type, String entry) {
        Map<String, String> extractedVals = new HashMap<>();
        Pattern extractor = this.valueExtractors.get(type);
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