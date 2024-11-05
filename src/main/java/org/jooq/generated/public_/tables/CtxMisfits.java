/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.public_.tables;


import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.InverseForeignKey;
import org.jooq.Name;
import org.jooq.Path;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.Record;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.UniqueKey;
import org.jooq.generated.public_.Keys;
import org.jooq.generated.public_.Public;
import org.jooq.generated.public_.tables.Log.LogPath;
import org.jooq.generated.public_.tables.records.CtxMisfitsRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class CtxMisfits extends TableImpl<CtxMisfitsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>PUBLIC.CTX_MISFITS</code>
     */
    public static final CtxMisfits CTX_MISFITS = new CtxMisfits();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<CtxMisfitsRecord> getRecordType() {
        return CtxMisfitsRecord.class;
    }

    /**
     * The column <code>PUBLIC.CTX_MISFITS.LINE</code>.
     */
    public final TableField<CtxMisfitsRecord, Integer> LINE = createField(DSL.name("LINE"), SQLDataType.INTEGER.nullable(false), this, "");

    private CtxMisfits(Name alias, Table<CtxMisfitsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private CtxMisfits(Name alias, Table<CtxMisfitsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>PUBLIC.CTX_MISFITS</code> table reference
     */
    public CtxMisfits(String alias) {
        this(DSL.name(alias), CTX_MISFITS);
    }

    /**
     * Create an aliased <code>PUBLIC.CTX_MISFITS</code> table reference
     */
    public CtxMisfits(Name alias) {
        this(alias, CTX_MISFITS);
    }

    /**
     * Create a <code>PUBLIC.CTX_MISFITS</code> table reference
     */
    public CtxMisfits() {
        this(DSL.name("CTX_MISFITS"), null);
    }

    public <O extends Record> CtxMisfits(Table<O> path, ForeignKey<O, CtxMisfitsRecord> childPath, InverseForeignKey<O, CtxMisfitsRecord> parentPath) {
        super(path, childPath, parentPath, CTX_MISFITS);
    }

    /**
     * A subtype implementing {@link Path} for simplified path-based joins.
     */
    public static class CtxMisfitsPath extends CtxMisfits implements Path<CtxMisfitsRecord> {

        private static final long serialVersionUID = 1L;
        public <O extends Record> CtxMisfitsPath(Table<O> path, ForeignKey<O, CtxMisfitsRecord> childPath, InverseForeignKey<O, CtxMisfitsRecord> parentPath) {
            super(path, childPath, parentPath);
        }
        private CtxMisfitsPath(Name alias, Table<CtxMisfitsRecord> aliased) {
            super(alias, aliased);
        }

        @Override
        public CtxMisfitsPath as(String alias) {
            return new CtxMisfitsPath(DSL.name(alias), this);
        }

        @Override
        public CtxMisfitsPath as(Name alias) {
            return new CtxMisfitsPath(alias, this);
        }

        @Override
        public CtxMisfitsPath as(Table<?> alias) {
            return new CtxMisfitsPath(alias.getQualifiedName(), this);
        }
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : Public.PUBLIC;
    }

    @Override
    public UniqueKey<CtxMisfitsRecord> getPrimaryKey() {
        return Keys.CONSTRAINT_E;
    }

    @Override
    public List<ForeignKey<CtxMisfitsRecord, ?>> getReferences() {
        return Arrays.asList(Keys.CTX_MISFITS_FK_LINE);
    }

    private transient LogPath _log;

    /**
     * Get the implicit join path to the <code>PUBLIC.LOG</code> table.
     */
    public LogPath log() {
        if (_log == null)
            _log = new LogPath(this, Keys.CTX_MISFITS_FK_LINE, null);

        return _log;
    }

    @Override
    public CtxMisfits as(String alias) {
        return new CtxMisfits(DSL.name(alias), this);
    }

    @Override
    public CtxMisfits as(Name alias) {
        return new CtxMisfits(alias, this);
    }

    @Override
    public CtxMisfits as(Table<?> alias) {
        return new CtxMisfits(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public CtxMisfits rename(String name) {
        return new CtxMisfits(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public CtxMisfits rename(Name name) {
        return new CtxMisfits(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public CtxMisfits rename(Table<?> name) {
        return new CtxMisfits(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public CtxMisfits where(Condition condition) {
        return new CtxMisfits(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public CtxMisfits where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public CtxMisfits where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public CtxMisfits where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public CtxMisfits where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public CtxMisfits where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public CtxMisfits where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public CtxMisfits where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public CtxMisfits whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public CtxMisfits whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
