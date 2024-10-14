package com.contrastsecurity.agent.loghog.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class H2Database {

//    public static void main(String[] args) {
//        // URL of the H2 database
//        String jdbcUrl = "jdbc:h2:~/.h2/testdb";
//        String username = "sa";
//        String password = "";
//
//        Connection connection = null;
//        Statement statement = null;
//        ResultSet resultSet = null;
//
//        try {
//            // Establish the connection
//            connection = DriverManager.getConnection(jdbcUrl, username, password);
//
//            // Create a statement
//            statement = connection.createStatement();
//
//            // Execute a query
//            String sql = "CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT, name VARCHAR(255), PRIMARY KEY (id))";
//            statement.execute(sql);
//
//            // Insert a record
//            sql = "INSERT INTO users (name) VALUES ('John Doe')";
//            statement.executeUpdate(sql);
//
//            // Query the database
//            sql = "SELECT * FROM users";
//            resultSet = statement.executeQuery(sql);
//
//            // Process the result set
//            while (resultSet.next()) {
//                int id = resultSet.getInt("id");
//                String name = resultSet.getString("name");
//                System.out.println("ID: " + id + ", Name: " + name);
//            }
//        } catch (SQLException e) {
//            e.printStackTrace();
//        } finally {
//            // Close the resources
//            try {
//                if (resultSet != null) resultSet.close();
//                if (statement != null) statement.close();
//                if (connection != null) connection.close();
//            } catch (SQLException e) {
//                e.printStackTrace();
//            }
//        }
//    }

    public static Connection openDatabase(final String storagePath) throws SQLException {
        // TODO verify storagePath is a writable disk directory path
        // URL of the H2 database
        String jdbcUrl = "jdbc:h2:" + storagePath;

        // TODO Who cares?
        String username = "sa";
        String password = "";

        Connection connection = null;

        // connect
        connection = DriverManager.getConnection(jdbcUrl, username, password);

        return connection;
    }

    public static void closeDatabase(final Connection connection) {
        closeDatabase(connection, null, null);
    }

    public static void closeDatabase(final Connection connection, final Statement statement) {
        closeDatabase(connection, statement, null);
    }

    public static void closeDatabase(final Connection connection, final Statement statement, final ResultSet resultSet) {
        try {
            if (resultSet != null) resultSet.close();
            if (statement != null) statement.close();
            if (connection != null) connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }


}