package com.contrastsecurity.agent.loghog;

import com.contrastsecurity.agent.loghog.db.CreateDb;
import com.contrastsecurity.agent.loghog.shred.*;

import java.io.IOException;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;

public class CreateFullDb {
    private static final String LOG_DIR = ".";

    public static void main(String[] args) {
        if (args.length < 1) {
            throw new IllegalArgumentException("Missing command line parameter for log name.");
        }

        String logname = args[0];
        String debugLog = Paths.get(LOG_DIR, logname + ".err").toString();
        String debugDb = Paths.get("", logname + ".db").toString();

        try {
            Connection connection = CreateDb.createLogDb(debugLog, debugDb);
            new MesgShred().createTables(connection);
            new LmclShred().createTables(connection);
            new AcelShred().createTables(connection);
            new AmqpShred().createTables(connection);
            new CrumbShred().createTables(connection);
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }
}