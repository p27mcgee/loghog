package com.contrastsecurity.agent.loghog.shred;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class ShredValueExtractor {
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

    public Map<String, Object> extractValues(String patternId, String entry) {
        Map<String, Object> extractedVals = new HashMap<>();
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