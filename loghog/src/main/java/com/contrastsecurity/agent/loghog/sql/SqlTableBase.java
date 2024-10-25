package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public class SqlTableBase implements SqlTable {

    final String name;
    final String createTableSql;
    final List<String> indexTableSql;
    final String insertRowSql;
    final String dropTblSql;


    public SqlTableBase(final String name, final String createTableSql, final List<String> indexTableSql, final List<String> insertColumnNames) {
        this(name, createTableSql, indexTableSql, insertSql(name, insertColumnNames));
    }

    public SqlTableBase(final String name, final String createTableSql, final List<String> indexTableSql, final String insertRowSql) {
        this.name = name;
        this.createTableSql = createTableSql;
        this.indexTableSql = indexTableSql != null ? indexTableSql : List.of();
        this.insertRowSql = insertRowSql;
        this.dropTblSql = "drop table if exists " + name;
    }

    @Override
    public String name() {
        return "";
    }

    @Override
    public String createTableSql() {
        return "";
    }

    @Override
    public List<String> indexTableSql() {
        return List.of();
    }

    @Override
    public String insertRowSql() {
        return "";
    }

    @Override
    public String dropTblSql() {
        return "";
    }

    private static String insertSql(final String name, final List<String> insertColumnNames) {
        final StringBuilder sb = new StringBuilder("insert into ");
        sb.append(name).append(" (");
        String delimiter = "";
        for (final String insertColumnName : insertColumnNames) {
            sb.append(delimiter).append(insertColumnName);
            delimiter = ", ";
        }
        sb.append(") values (");
        delimiter = "";
        for (final String dontCare : insertColumnNames) {
            sb.append(delimiter).append("?");
            delimiter = ", ";
        }
        return sb.append(")").toString();
    }

}
