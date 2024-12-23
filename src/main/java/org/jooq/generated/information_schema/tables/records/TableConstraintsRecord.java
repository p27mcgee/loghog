/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables.records;


import org.jooq.generated.information_schema.tables.TableConstraints;
import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class TableConstraintsRecord extends TableRecordImpl<TableConstraintsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_CATALOG</code>.
     */
    public void setConstraintCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_CATALOG</code>.
     */
    public String getConstraintCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_SCHEMA</code>.
     */
    public void setConstraintSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_SCHEMA</code>.
     */
    public String getConstraintSchema() {
        return (String) get(1);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_NAME</code>.
     */
    public void setConstraintName(String value) {
        set(2, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_NAME</code>.
     */
    public String getConstraintName() {
        return (String) get(2);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_TYPE</code>.
     */
    public void setConstraintType(String value) {
        set(3, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.CONSTRAINT_TYPE</code>.
     */
    public String getConstraintType() {
        return (String) get(3);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.TABLE_CATALOG</code>.
     */
    public void setTableCatalog(String value) {
        set(4, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.TABLE_CATALOG</code>.
     */
    public String getTableCatalog() {
        return (String) get(4);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.TABLE_SCHEMA</code>.
     */
    public void setTableSchema(String value) {
        set(5, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.TABLE_SCHEMA</code>.
     */
    public String getTableSchema() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.TABLE_NAME</code>.
     */
    public void setTableName(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.TABLE_NAME</code>.
     */
    public String getTableName() {
        return (String) get(6);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.IS_DEFERRABLE</code>.
     */
    public void setIsDeferrable(String value) {
        set(7, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.IS_DEFERRABLE</code>.
     */
    public String getIsDeferrable() {
        return (String) get(7);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INITIALLY_DEFERRED</code>.
     */
    public void setInitiallyDeferred(String value) {
        set(8, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INITIALLY_DEFERRED</code>.
     */
    public String getInitiallyDeferred() {
        return (String) get(8);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.ENFORCED</code>.
     */
    public void setEnforced(String value) {
        set(9, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.ENFORCED</code>.
     */
    public String getEnforced() {
        return (String) get(9);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.NULLS_DISTINCT</code>.
     */
    public void setNullsDistinct(String value) {
        set(10, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.NULLS_DISTINCT</code>.
     */
    public String getNullsDistinct() {
        return (String) get(10);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INDEX_CATALOG</code>.
     */
    public void setIndexCatalog(String value) {
        set(11, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INDEX_CATALOG</code>.
     */
    public String getIndexCatalog() {
        return (String) get(11);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INDEX_SCHEMA</code>.
     */
    public void setIndexSchema(String value) {
        set(12, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INDEX_SCHEMA</code>.
     */
    public String getIndexSchema() {
        return (String) get(12);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INDEX_NAME</code>.
     */
    public void setIndexName(String value) {
        set(13, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.INDEX_NAME</code>.
     */
    public String getIndexName() {
        return (String) get(13);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(14, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLE_CONSTRAINTS.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(14);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached TableConstraintsRecord
     */
    public TableConstraintsRecord() {
        super(TableConstraints.TABLE_CONSTRAINTS);
    }

    /**
     * Create a detached, initialised TableConstraintsRecord
     */
    public TableConstraintsRecord(String constraintCatalog, String constraintSchema, String constraintName, String constraintType, String tableCatalog, String tableSchema, String tableName, String isDeferrable, String initiallyDeferred, String enforced, String nullsDistinct, String indexCatalog, String indexSchema, String indexName, String remarks) {
        super(TableConstraints.TABLE_CONSTRAINTS);

        setConstraintCatalog(constraintCatalog);
        setConstraintSchema(constraintSchema);
        setConstraintName(constraintName);
        setConstraintType(constraintType);
        setTableCatalog(tableCatalog);
        setTableSchema(tableSchema);
        setTableName(tableName);
        setIsDeferrable(isDeferrable);
        setInitiallyDeferred(initiallyDeferred);
        setEnforced(enforced);
        setNullsDistinct(nullsDistinct);
        setIndexCatalog(indexCatalog);
        setIndexSchema(indexSchema);
        setIndexName(indexName);
        setRemarks(remarks);
        resetChangedOnNotNull();
    }
}
