/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables.records;


import org.jooq.generated.information_schema.tables.QueryStatistics;
import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class QueryStatisticsRecord extends TableRecordImpl<QueryStatisticsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.SQL_STATEMENT</code>.
     */
    public void setSqlStatement(String value) {
        set(0, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.SQL_STATEMENT</code>.
     */
    public String getSqlStatement() {
        return (String) get(0);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.EXECUTION_COUNT</code>.
     */
    public void setExecutionCount(Integer value) {
        set(1, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.EXECUTION_COUNT</code>.
     */
    public Integer getExecutionCount() {
        return (Integer) get(1);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MIN_EXECUTION_TIME</code>.
     */
    public void setMinExecutionTime(Double value) {
        set(2, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MIN_EXECUTION_TIME</code>.
     */
    public Double getMinExecutionTime() {
        return (Double) get(2);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MAX_EXECUTION_TIME</code>.
     */
    public void setMaxExecutionTime(Double value) {
        set(3, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MAX_EXECUTION_TIME</code>.
     */
    public Double getMaxExecutionTime() {
        return (Double) get(3);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.CUMULATIVE_EXECUTION_TIME</code>.
     */
    public void setCumulativeExecutionTime(Double value) {
        set(4, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.CUMULATIVE_EXECUTION_TIME</code>.
     */
    public Double getCumulativeExecutionTime() {
        return (Double) get(4);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.AVERAGE_EXECUTION_TIME</code>.
     */
    public void setAverageExecutionTime(Double value) {
        set(5, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.AVERAGE_EXECUTION_TIME</code>.
     */
    public Double getAverageExecutionTime() {
        return (Double) get(5);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.STD_DEV_EXECUTION_TIME</code>.
     */
    public void setStdDevExecutionTime(Double value) {
        set(6, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.STD_DEV_EXECUTION_TIME</code>.
     */
    public Double getStdDevExecutionTime() {
        return (Double) get(6);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MIN_ROW_COUNT</code>.
     */
    public void setMinRowCount(Long value) {
        set(7, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MIN_ROW_COUNT</code>.
     */
    public Long getMinRowCount() {
        return (Long) get(7);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MAX_ROW_COUNT</code>.
     */
    public void setMaxRowCount(Long value) {
        set(8, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.MAX_ROW_COUNT</code>.
     */
    public Long getMaxRowCount() {
        return (Long) get(8);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.CUMULATIVE_ROW_COUNT</code>.
     */
    public void setCumulativeRowCount(Long value) {
        set(9, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.CUMULATIVE_ROW_COUNT</code>.
     */
    public Long getCumulativeRowCount() {
        return (Long) get(9);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.AVERAGE_ROW_COUNT</code>.
     */
    public void setAverageRowCount(Double value) {
        set(10, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.AVERAGE_ROW_COUNT</code>.
     */
    public Double getAverageRowCount() {
        return (Double) get(10);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.STD_DEV_ROW_COUNT</code>.
     */
    public void setStdDevRowCount(Double value) {
        set(11, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.QUERY_STATISTICS.STD_DEV_ROW_COUNT</code>.
     */
    public Double getStdDevRowCount() {
        return (Double) get(11);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached QueryStatisticsRecord
     */
    public QueryStatisticsRecord() {
        super(QueryStatistics.QUERY_STATISTICS);
    }

    /**
     * Create a detached, initialised QueryStatisticsRecord
     */
    public QueryStatisticsRecord(String sqlStatement, Integer executionCount, Double minExecutionTime, Double maxExecutionTime, Double cumulativeExecutionTime, Double averageExecutionTime, Double stdDevExecutionTime, Long minRowCount, Long maxRowCount, Long cumulativeRowCount, Double averageRowCount, Double stdDevRowCount) {
        super(QueryStatistics.QUERY_STATISTICS);

        setSqlStatement(sqlStatement);
        setExecutionCount(executionCount);
        setMinExecutionTime(minExecutionTime);
        setMaxExecutionTime(maxExecutionTime);
        setCumulativeExecutionTime(cumulativeExecutionTime);
        setAverageExecutionTime(averageExecutionTime);
        setStdDevExecutionTime(stdDevExecutionTime);
        setMinRowCount(minRowCount);
        setMaxRowCount(maxRowCount);
        setCumulativeRowCount(cumulativeRowCount);
        setAverageRowCount(averageRowCount);
        setStdDevRowCount(stdDevRowCount);
        resetChangedOnNotNull();
    }
}
