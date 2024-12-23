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
import org.jooq.generated.information_schema.tables.records.ElementTypesRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class ElementTypes extends TableImpl<ElementTypesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.ELEMENT_TYPES</code>
     */
    public static final ElementTypes ELEMENT_TYPES = new ElementTypes();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<ElementTypesRecord> getRecordType() {
        return ElementTypesRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.OBJECT_CATALOG</code>.
     */
    public final TableField<ElementTypesRecord, String> OBJECT_CATALOG = createField(DSL.name("OBJECT_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.OBJECT_SCHEMA</code>.
     */
    public final TableField<ElementTypesRecord, String> OBJECT_SCHEMA = createField(DSL.name("OBJECT_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.OBJECT_NAME</code>.
     */
    public final TableField<ElementTypesRecord, String> OBJECT_NAME = createField(DSL.name("OBJECT_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.OBJECT_TYPE</code>.
     */
    public final TableField<ElementTypesRecord, String> OBJECT_TYPE = createField(DSL.name("OBJECT_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.COLLECTION_TYPE_IDENTIFIER</code>.
     */
    public final TableField<ElementTypesRecord, String> COLLECTION_TYPE_IDENTIFIER = createField(DSL.name("COLLECTION_TYPE_IDENTIFIER"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.DATA_TYPE</code>.
     */
    public final TableField<ElementTypesRecord, String> DATA_TYPE = createField(DSL.name("DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.CHARACTER_MAXIMUM_LENGTH</code>.
     */
    public final TableField<ElementTypesRecord, Long> CHARACTER_MAXIMUM_LENGTH = createField(DSL.name("CHARACTER_MAXIMUM_LENGTH"), SQLDataType.BIGINT, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.CHARACTER_OCTET_LENGTH</code>.
     */
    public final TableField<ElementTypesRecord, Long> CHARACTER_OCTET_LENGTH = createField(DSL.name("CHARACTER_OCTET_LENGTH"), SQLDataType.BIGINT, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.CHARACTER_SET_CATALOG</code>.
     */
    public final TableField<ElementTypesRecord, String> CHARACTER_SET_CATALOG = createField(DSL.name("CHARACTER_SET_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.CHARACTER_SET_SCHEMA</code>.
     */
    public final TableField<ElementTypesRecord, String> CHARACTER_SET_SCHEMA = createField(DSL.name("CHARACTER_SET_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.CHARACTER_SET_NAME</code>.
     */
    public final TableField<ElementTypesRecord, String> CHARACTER_SET_NAME = createField(DSL.name("CHARACTER_SET_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.COLLATION_CATALOG</code>.
     */
    public final TableField<ElementTypesRecord, String> COLLATION_CATALOG = createField(DSL.name("COLLATION_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.COLLATION_SCHEMA</code>.
     */
    public final TableField<ElementTypesRecord, String> COLLATION_SCHEMA = createField(DSL.name("COLLATION_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.COLLATION_NAME</code>.
     */
    public final TableField<ElementTypesRecord, String> COLLATION_NAME = createField(DSL.name("COLLATION_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.NUMERIC_PRECISION</code>.
     */
    public final TableField<ElementTypesRecord, Integer> NUMERIC_PRECISION = createField(DSL.name("NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.NUMERIC_PRECISION_RADIX</code>.
     */
    public final TableField<ElementTypesRecord, Integer> NUMERIC_PRECISION_RADIX = createField(DSL.name("NUMERIC_PRECISION_RADIX"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.NUMERIC_SCALE</code>.
     */
    public final TableField<ElementTypesRecord, Integer> NUMERIC_SCALE = createField(DSL.name("NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.DATETIME_PRECISION</code>.
     */
    public final TableField<ElementTypesRecord, Integer> DATETIME_PRECISION = createField(DSL.name("DATETIME_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.INTERVAL_TYPE</code>.
     */
    public final TableField<ElementTypesRecord, String> INTERVAL_TYPE = createField(DSL.name("INTERVAL_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.INTERVAL_PRECISION</code>.
     */
    public final TableField<ElementTypesRecord, Integer> INTERVAL_PRECISION = createField(DSL.name("INTERVAL_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.MAXIMUM_CARDINALITY</code>.
     */
    public final TableField<ElementTypesRecord, Integer> MAXIMUM_CARDINALITY = createField(DSL.name("MAXIMUM_CARDINALITY"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.DTD_IDENTIFIER</code>.
     */
    public final TableField<ElementTypesRecord, String> DTD_IDENTIFIER = createField(DSL.name("DTD_IDENTIFIER"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.DECLARED_DATA_TYPE</code>.
     */
    public final TableField<ElementTypesRecord, String> DECLARED_DATA_TYPE = createField(DSL.name("DECLARED_DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.DECLARED_NUMERIC_PRECISION</code>.
     */
    public final TableField<ElementTypesRecord, Integer> DECLARED_NUMERIC_PRECISION = createField(DSL.name("DECLARED_NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.ELEMENT_TYPES.DECLARED_NUMERIC_SCALE</code>.
     */
    public final TableField<ElementTypesRecord, Integer> DECLARED_NUMERIC_SCALE = createField(DSL.name("DECLARED_NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.GEOMETRY_TYPE</code>.
     */
    public final TableField<ElementTypesRecord, String> GEOMETRY_TYPE = createField(DSL.name("GEOMETRY_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.ELEMENT_TYPES.GEOMETRY_SRID</code>.
     */
    public final TableField<ElementTypesRecord, Integer> GEOMETRY_SRID = createField(DSL.name("GEOMETRY_SRID"), SQLDataType.INTEGER, this, "");

    private ElementTypes(Name alias, Table<ElementTypesRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private ElementTypes(Name alias, Table<ElementTypesRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.ELEMENT_TYPES</code> table
     * reference
     */
    public ElementTypes(String alias) {
        this(DSL.name(alias), ELEMENT_TYPES);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.ELEMENT_TYPES</code> table
     * reference
     */
    public ElementTypes(Name alias) {
        this(alias, ELEMENT_TYPES);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.ELEMENT_TYPES</code> table reference
     */
    public ElementTypes() {
        this(DSL.name("ELEMENT_TYPES"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public ElementTypes as(String alias) {
        return new ElementTypes(DSL.name(alias), this);
    }

    @Override
    public ElementTypes as(Name alias) {
        return new ElementTypes(alias, this);
    }

    @Override
    public ElementTypes as(Table<?> alias) {
        return new ElementTypes(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public ElementTypes rename(String name) {
        return new ElementTypes(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public ElementTypes rename(Name name) {
        return new ElementTypes(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public ElementTypes rename(Table<?> name) {
        return new ElementTypes(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ElementTypes where(Condition condition) {
        return new ElementTypes(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ElementTypes where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ElementTypes where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ElementTypes where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ElementTypes where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ElementTypes where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ElementTypes where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public ElementTypes where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ElementTypes whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public ElementTypes whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
