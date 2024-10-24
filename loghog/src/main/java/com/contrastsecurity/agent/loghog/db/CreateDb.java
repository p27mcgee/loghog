package com.contrastsecurity.agent.loghog.db;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class CreateDb {
    private static final boolean SHOW_PROGRESS = false;
    private static final int CHUNK_SIZE = 10000;

    public static String[] classAndPackage(String fqcn) {
        int lastDot = fqcn.lastIndexOf('.');
        String classname = fqcn.substring(lastDot + 1);
        String packageName = fqcn.substring(0, lastDot);
        return new String[]{classname, packageName};
    }

    public static String quotOrNull(String txt) {
        if (txt == null) {
            return "NULL";
        } else {
            return "'" + txt + "'";
        }
    }

    public static int addChunkOfLogEntries(List<String[]> chunk, Connection connection) throws SQLException {
        String sql = "INSERT INTO log VALUES (?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            connection.setAutoCommit(false);
            for (String[] entry : chunk) {
                pstmt.setInt(1, Integer.parseInt(entry[0]));
                pstmt.setString(2, entry[1]);
                pstmt.addBatch();
            }
            int[] result = pstmt.executeBatch();
            connection.commit();
            return result.length;
        }
    }

    public static void initializeLogTable(String infile, Connection connection) throws IOException, SQLException {
        System.out.println("Initializing log table from " + infile + " ...");
        int total = 0;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DELETE FROM log");
        }
        try (BufferedReader inlog = new BufferedReader(new FileReader(infile))) {
            List<String[]> chunk = new ArrayList<>();
            String entry;
            int idx = 0;
            while ((entry = inlog.readLine()) != null) {
                chunk.add(new String[]{String.valueOf(idx + 1), entry});
                if (idx % CHUNK_SIZE == CHUNK_SIZE - 1) {
                    total += addChunkOfLogEntries(chunk, connection);
                    if (SHOW_PROGRESS) {
                        System.out.print(".");
                    }
                    chunk.clear();
                }
                idx++;
            }
            total += addChunkOfLogEntries(chunk, connection);
        }
        if (SHOW_PROGRESS) {
            System.out.println();
        }
        System.out.println("Added " + total + " rows to table log");
    }

    public static void createLogTable(Connection connection) throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS log (line INTEGER PRIMARY KEY, entry TEXT)";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    public static Connection connectDb(String dbname) throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbname);
    }

    public static Connection createLogDb(String logPath, String dbname) throws IOException, SQLException {
        Connection connection = connectDb(dbname);
        createLogTable(connection);
        initializeLogTable(logPath, connection);
        return connection;
    }

    public static void main(String[] args) {
        String logname = "sb-san-petclinic";
        if (args.length > 0) {
            logname = args[0];
        }
        String debugLog = logname + ".err";
        String debugDb = logname + ".db";
        try {
            createLogDb(debugLog, debugDb);
        } catch (IOException | SQLException e) {
            e.printStackTrace();
        }
    }
}