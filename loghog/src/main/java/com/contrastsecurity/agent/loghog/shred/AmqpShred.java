package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.db.CreateDb;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AmqpShred extends Shred {
    public static final String TBL_NAME = "amqp";
    public static final String CREATE_TBL_SQL =
            "create table amqp(" +
                    "line integer primary key references log(line)," +
                    "type text not null," +
                    "exchangeName text not null," +
                    "queueName text not null," +
                    "properties text not null," +
                    "body text not null)";
    public static final List<String> TBL_INDEX_SQLS = Collections.emptyList();
    public static final ShredTableCreator TBL_CREATOR = new ShredTableCreator(TBL_NAME, CREATE_TBL_SQL, TBL_INDEX_SQLS);

    public static final String ENTRY_SIGNATURE = "AMQP Publisher] DEBUG - MQPublisherImpl#publish call: exchangeName:";
    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(ENTRY_SIGNATURE);

    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier(); // just one default type

    public static final List<String> EXTRACTED_VAL_NAMES = Arrays.asList("exchangeName", "queueName", "properties", "body");
    public static final Map<String, Pattern> VALUE_EXTRACTORS = new HashMap<String, Pattern>() {{
        put(Shred.DEFAULT_TYPE, Pattern.compile(
                "^.* AMQP Publisher] DEBUG - MQPublisherImpl#publish call: exchangeName: (?<exchangeName>[^,]*), queueName: (?<queueName>[^,]*), properties: (?<properties>.*), body: (?<body>.*)$"
        ));
    }};
    public static final ShredValueExtractor VALUE_EXTRACTOR = new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    public static final List<String> INSERT_COLUMNS = Arrays.asList("line", "type", "exchangeName", "queueName", "properties", "body");

    public static final Pattern TYPE_EXTRACTOR = Pattern.compile(".*, type=(?<type>[^,]+), ");

    public AmqpShred() {
        super(TBL_CREATOR, ENTRY_SELECTOR, ENTRY_CLASSIFIER, VALUE_EXTRACTOR, INSERT_COLUMNS);
    }

    @Override
    public Object[] transformValues(int line, String entry, String type, Map<String, String> extractedVals) {
        Matcher match = TYPE_EXTRACTOR.matcher(entry);
        if (match.find()) {
            return new Object[] { line, match.group("type"), extractedVals.get("exchangeName"), extractedVals.get("queueName"), extractedVals.get("properties"), extractedVals.get("body") };
        }
        return new Object[] { line, null, extractedVals.get("exchangeName"), extractedVals.get("queueName"), extractedVals.get("properties"), extractedVals.get("body") };
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            throw new IllegalArgumentException("Missing command line parameter for log name.");
        }

        String logname = args[0];
        String debugDb = Paths.get("", logname + ".db").toString();

        try (Connection connection = CreateDb.connectDb(debugDb)) {
            AmqpShred amqpShred = new AmqpShred();
            amqpShred.initializeTables(connection);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
