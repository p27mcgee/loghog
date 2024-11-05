/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables;


import java.util.Collection;

import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.Name;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.generated.information_schema.InformationSchema;
import org.jooq.generated.information_schema.tables.records.SequencesRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Sequences extends TableImpl<SequencesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.SEQUENCES</code>
     */
    public static final Sequences SEQUENCES = new Sequences();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<SequencesRecord> getRecordType() {
        return SequencesRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_CATALOG</code>.
     */
    public final TableField<SequencesRecord, String> SEQUENCE_CATALOG = createField(DSL.name("SEQUENCE_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_SCHEMA</code>.
     */
    public final TableField<SequencesRecord, String> SEQUENCE_SCHEMA = createField(DSL.name("SEQUENCE_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_NAME</code>.
     */
    public final TableField<SequencesRecord, String> SEQUENCE_NAME = createField(DSL.name("SEQUENCE_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.DATA_TYPE</code>.
     */
    public final TableField<SequencesRecord, String> DATA_TYPE = createField(DSL.name("DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_PRECISION</code>.
     */
    public final TableField<SequencesRecord, Integer> NUMERIC_PRECISION = createField(DSL.name("NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_PRECISION_RADIX</code>.
     */
    public final TableField<SequencesRecord, Integer> NUMERIC_PRECISION_RADIX = createField(DSL.name("NUMERIC_PRECISION_RADIX"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_SCALE</code>.
     */
    public final TableField<SequencesRecord, Integer> NUMERIC_SCALE = createField(DSL.name("NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.START_VALUE</code>.
     */
    public final TableField<SequencesRecord, Long> START_VALUE = createField(DSL.name("START_VALUE"), SQLDataType.BIGINT, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.MINIMUM_VALUE</code>.
     */
    public final TableField<SequencesRecord, Long> MINIMUM_VALUE = createField(DSL.name("MINIMUM_VALUE"), SQLDataType.BIGINT, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.MAXIMUM_VALUE</code>.
     */
    public final TableField<SequencesRecord, Long> MAXIMUM_VALUE = createField(DSL.name("MAXIMUM_VALUE"), SQLDataType.BIGINT, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.INCREMENT</code>.
     */
    public final TableField<SequencesRecord, Long> INCREMENT = createField(DSL.name("INCREMENT"), SQLDataType.BIGINT, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.CYCLE_OPTION</code>.
     */
    public final TableField<SequencesRecord, String> CYCLE_OPTION = createField(DSL.name("CYCLE_OPTION"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_DATA_TYPE</code>.
     */
    public final TableField<SequencesRecord, String> DECLARED_DATA_TYPE = createField(DSL.name("DECLARED_DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_NUMERIC_PRECISION</code>.
     */
    public final TableField<SequencesRecord, Integer> DECLARED_NUMERIC_PRECISION = createField(DSL.name("DECLARED_NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_NUMERIC_SCALE</code>.
     */
    public final TableField<SequencesRecord, Integer> DECLARED_NUMERIC_SCALE = createField(DSL.name("DECLARED_NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.BASE_VALUE</code>.
     */
    public final TableField<SequencesRecord, Long> BASE_VALUE = createField(DSL.name("BASE_VALUE"), SQLDataType.BIGINT, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.CACHE</code>.
     */
    public final TableField<SequencesRecord, Long> CACHE = createField(DSL.name("CACHE"), SQLDataType.BIGINT, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SEQUENCES.REMARKS</code>.
     */
    public final TableField<SequencesRecord, String> REMARKS = createField(DSL.name("REMARKS"), SQLDataType.VARCHAR(1000000000), this, "");

    private Sequences(Name alias, Table<SequencesRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Sequences(Name alias, Table<SequencesRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.SEQUENCES</code> table
     * reference
     */
    public Sequences(String alias) {
        this(DSL.name(alias), SEQUENCES);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.SEQUENCES</code> table
     * reference
     */
    public Sequences(Name alias) {
        this(alias, SEQUENCES);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.SEQUENCES</code> table reference
     */
    public Sequences() {
        this(DSL.name("SEQUENCES"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Sequences as(String alias) {
        return new Sequences(DSL.name(alias), this);
    }

    @Override
    public Sequences as(Name alias) {
        return new Sequences(alias, this);
    }

    @Override
    public Sequences as(Table<?> alias) {
        return new Sequences(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Sequences rename(String name) {
        return new Sequences(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Sequences rename(Name name) {
        return new Sequences(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Sequences rename(Table<?> name) {
        return new Sequences(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Sequences where(Condition condition) {
        return new Sequences(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Sequences where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Sequences where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Sequences where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Sequences where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Sequences where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Sequences where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Sequences where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Sequences whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Sequences whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}