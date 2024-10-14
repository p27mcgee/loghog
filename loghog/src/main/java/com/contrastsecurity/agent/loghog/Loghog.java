package com.contrastsecurity.agent.loghog;

import com.contrastsecurity.agent.loghog.db.H2Database;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Loghog {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("loghog requires a comand line argument specifying the path to a log file to load, e.g.: ");
            System.out.println("java -jar loghog-all.jar ~/logs/some-log.err");
        }
        try {
            dbstuff();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    static void dbstuff() throws SQLException {

        final String storagePath = "~.h2/testdb";
        Connection connection = H2Database.openDatabase(storagePath);

        Statement statement = null;
        ResultSet resultSet = null;
        try {
            // Create a statement
            statement = connection.createStatement();

            // Execute a query
            String sql = "CREATE TABLE IF NOT EXISTS daleks (id INT AUTO_INCREMENT, name VARCHAR(255), PRIMARY KEY (id))";
            statement.execute(sql);

            // Insert a record
            sql = "INSERT INTO daleks (name) VALUES ('John Doe')";
            statement.executeUpdate(sql);

            // Query the database
            sql = "SELECT * FROM daleks";
            resultSet = statement.executeQuery(sql);

            // Process the result set
            while (resultSet.next()) {
                int id = resultSet.getInt("id");
                String name = resultSet.getString("name");
                System.out.println("ID: " + id + ", Name: " + name);
            }
        } catch (final SQLException e) {
            e.printStackTrace();
        } finally {
            H2Database.closeDatabase(connection, statement, resultSet);
        }
    }

}