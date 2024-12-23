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
import org.jooq.generated.information_schema.tables.records.RoutinesRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Routines extends TableImpl<RoutinesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.ROUTINES</code>
     */
    public static final Routines ROUTINES = new Routines();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<RoutinesRecord> getRecordType() {
        return RoutinesRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.SPECIFIC_CATALOG</code>.
     */
    public final TableField<RoutinesRecord, String> SPECIFIC_CATALOG = createField(DSL.name("SPECIFIC_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.SPECIFIC_SCHEMA</code>.
     */
    public final TableField<RoutinesRecord, String> SPECIFIC_SCHEMA = createField(DSL.name("SPECIFIC_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.SPECIFIC_NAME</code>.
     */
    public final TableField<RoutinesRecord, String> SPECIFIC_NAME = createField(DSL.name("SPECIFIC_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.ROUTINE_CATALOG</code>.
     */
    public final TableField<RoutinesRecord, String> ROUTINE_CATALOG = createField(DSL.name("ROUTINE_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.ROUTINE_SCHEMA</code>.
     */
    public final TableField<RoutinesRecord, String> ROUTINE_SCHEMA = createField(DSL.name("ROUTINE_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.ROUTINE_NAME</code>.
     */
    public final TableField<RoutinesRecord, String> ROUTINE_NAME = createField(DSL.name("ROUTINE_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.ROUTINE_TYPE</code>.
     */
    public final TableField<RoutinesRecord, String> ROUTINE_TYPE = createField(DSL.name("ROUTINE_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.DATA_TYPE</code>.
     */
    public final TableField<RoutinesRecord, String> DATA_TYPE = createField(DSL.name("DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ROUTINES.CHARACTER_MAXIMUM_LENGTH</code>.
     */
    public final TableField<RoutinesRecord, Long> CHARACTER_MAXIMUM_LENGTH = createField(DSL.name("CHARACTER_MAXIMUM_LENGTH"), SQLDataType.BIGINT, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ROUTINES.CHARACTER_OCTET_LENGTH</code>.
     */
    public final TableField<RoutinesRecord, Long> CHARACTER_OCTET_LENGTH = createField(DSL.name("CHARACTER_OCTET_LENGTH"), SQLDataType.BIGINT, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ROUTINES.CHARACTER_SET_CATALOG</code>.
     */
    public final TableField<RoutinesRecord, String> CHARACTER_SET_CATALOG = createField(DSL.name("CHARACTER_SET_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.CHARACTER_SET_SCHEMA</code>.
     */
    public final TableField<RoutinesRecord, String> CHARACTER_SET_SCHEMA = createField(DSL.name("CHARACTER_SET_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.CHARACTER_SET_NAME</code>.
     */
    public final TableField<RoutinesRecord, String> CHARACTER_SET_NAME = createField(DSL.name("CHARACTER_SET_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.COLLATION_CATALOG</code>.
     */
    public final TableField<RoutinesRecord, String> COLLATION_CATALOG = createField(DSL.name("COLLATION_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.COLLATION_SCHEMA</code>.
     */
    public final TableField<RoutinesRecord, String> COLLATION_SCHEMA = createField(DSL.name("COLLATION_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.COLLATION_NAME</code>.
     */
    public final TableField<RoutinesRecord, String> COLLATION_NAME = createField(DSL.name("COLLATION_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.NUMERIC_PRECISION</code>.
     */
    public final TableField<RoutinesRecord, Integer> NUMERIC_PRECISION = createField(DSL.name("NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ROUTINES.NUMERIC_PRECISION_RADIX</code>.
     */
    public final TableField<RoutinesRecord, Integer> NUMERIC_PRECISION_RADIX = createField(DSL.name("NUMERIC_PRECISION_RADIX"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.NUMERIC_SCALE</code>.
     */
    public final TableField<RoutinesRecord, Integer> NUMERIC_SCALE = createField(DSL.name("NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.DATETIME_PRECISION</code>.
     */
    public final TableField<RoutinesRecord, Integer> DATETIME_PRECISION = createField(DSL.name("DATETIME_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.INTERVAL_TYPE</code>.
     */
    public final TableField<RoutinesRecord, String> INTERVAL_TYPE = createField(DSL.name("INTERVAL_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.INTERVAL_PRECISION</code>.
     */
    public final TableField<RoutinesRecord, Integer> INTERVAL_PRECISION = createField(DSL.name("INTERVAL_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.MAXIMUM_CARDINALITY</code>.
     */
    public final TableField<RoutinesRecord, Integer> MAXIMUM_CARDINALITY = createField(DSL.name("MAXIMUM_CARDINALITY"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.DTD_IDENTIFIER</code>.
     */
    public final TableField<RoutinesRecord, String> DTD_IDENTIFIER = createField(DSL.name("DTD_IDENTIFIER"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.ROUTINE_BODY</code>.
     */
    public final TableField<RoutinesRecord, String> ROUTINE_BODY = createField(DSL.name("ROUTINE_BODY"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.ROUTINE_DEFINITION</code>.
     */
    public final TableField<RoutinesRecord, String> ROUTINE_DEFINITION = createField(DSL.name("ROUTINE_DEFINITION"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.EXTERNAL_NAME</code>.
     */
    public final TableField<RoutinesRecord, String> EXTERNAL_NAME = createField(DSL.name("EXTERNAL_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.EXTERNAL_LANGUAGE</code>.
     */
    public final TableField<RoutinesRecord, String> EXTERNAL_LANGUAGE = createField(DSL.name("EXTERNAL_LANGUAGE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.PARAMETER_STYLE</code>.
     */
    public final TableField<RoutinesRecord, String> PARAMETER_STYLE = createField(DSL.name("PARAMETER_STYLE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.IS_DETERMINISTIC</code>.
     */
    public final TableField<RoutinesRecord, String> IS_DETERMINISTIC = createField(DSL.name("IS_DETERMINISTIC"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.DECLARED_DATA_TYPE</code>.
     */
    public final TableField<RoutinesRecord, String> DECLARED_DATA_TYPE = createField(DSL.name("DECLARED_DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ROUTINES.DECLARED_NUMERIC_PRECISION</code>.
     */
    public final TableField<RoutinesRecord, Integer> DECLARED_NUMERIC_PRECISION = createField(DSL.name("DECLARED_NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ROUTINES.DECLARED_NUMERIC_SCALE</code>.
     */
    public final TableField<RoutinesRecord, Integer> DECLARED_NUMERIC_SCALE = createField(DSL.name("DECLARED_NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.GEOMETRY_TYPE</code>.
     */
    public final TableField<RoutinesRecord, String> GEOMETRY_TYPE = createField(DSL.name("GEOMETRY_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.GEOMETRY_SRID</code>.
     */
    public final TableField<RoutinesRecord, Integer> GEOMETRY_SRID = createField(DSL.name("GEOMETRY_SRID"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ROUTINES.REMARKS</code>.
     */
    public final TableField<RoutinesRecord, String> REMARKS = createField(DSL.name("REMARKS"), SQLDataType.VARCHAR(1000000000), this, "");

    private Routines(Name alias, Table<RoutinesRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Routines(Name alias, Table<RoutinesRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.ROUTINES</code> table
     * reference
     */
    public Routines(String alias) {
        this(DSL.name(alias), ROUTINES);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.ROUTINES</code> table
     * reference
     */
    public Routines(Name alias) {
        this(alias, ROUTINES);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.ROUTINES</code> table reference
     */
    public Routines() {
        this(DSL.name("ROUTINES"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Routines as(String alias) {
        return new Routines(DSL.name(alias), this);
    }

    @Override
    public Routines as(Name alias) {
        return new Routines(alias, this);
    }

    @Override
    public Routines as(Table<?> alias) {
        return new Routines(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Routines rename(String name) {
        return new Routines(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Routines rename(Name name) {
        return new Routines(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Routines rename(Table<?> name) {
        return new Routines(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Routines where(Condition condition) {
        return new Routines(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Routines where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Routines where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Routines where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Routines where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Routines where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Routines where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Routines where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Routines whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Routines whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
