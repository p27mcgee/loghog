/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.public_.tables;


import java.time.LocalDateTime;
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
import org.jooq.generated.public_.tables.records.CtxRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Ctx extends TableImpl<CtxRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>PUBLIC.CTX</code>
     */
    public static final Ctx CTX = new Ctx();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<CtxRecord> getRecordType() {
        return CtxRecord.class;
    }

    /**
     * The column <code>PUBLIC.CTX.LINE</code>.
     */
    public final TableField<CtxRecord, Integer> LINE = createField(DSL.name("LINE"), SQLDataType.INTEGER.nullable(false), this, "");

    /**
     * The column <code>PUBLIC.CTX.TIMESTAMP</code>.
     */
    public final TableField<CtxRecord, LocalDateTime> TIMESTAMP = createField(DSL.name("TIMESTAMP"), SQLDataType.LOCALDATETIME(3), this, "");

    /**
     * The column <code>PUBLIC.CTX.THREAD</code>.
     */
    public final TableField<CtxRecord, String> THREAD = createField(DSL.name("THREAD"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.PATTERN</code>.
     */
    public final TableField<CtxRecord, String> PATTERN = createField(DSL.name("PATTERN"), SQLDataType.VARCHAR(1000000000).nullable(false), this, "");

    /**
     * The column <code>PUBLIC.CTX.CONCUR_CTX</code>.
     */
    public final TableField<CtxRecord, String> CONCUR_CTX = createField(DSL.name("CONCUR_CTX"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.ASSESS_CTX</code>.
     */
    public final TableField<CtxRecord, String> ASSESS_CTX = createField(DSL.name("ASSESS_CTX"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.APP_CTX</code>.
     */
    public final TableField<CtxRecord, String> APP_CTX = createField(DSL.name("APP_CTX"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.TASK_CLASS</code>.
     */
    public final TableField<CtxRecord, String> TASK_CLASS = createField(DSL.name("TASK_CLASS"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.TASK_OBJ</code>.
     */
    public final TableField<CtxRecord, String> TASK_OBJ = createField(DSL.name("TASK_OBJ"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.WRAP_INIT</code>.
     */
    public final TableField<CtxRecord, String> WRAP_INIT = createField(DSL.name("WRAP_INIT"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.RUNNABLE</code>.
     */
    public final TableField<CtxRecord, String> RUNNABLE = createField(DSL.name("RUNNABLE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>PUBLIC.CTX.TRACE_MAP</code>.
     */
    public final TableField<CtxRecord, String> TRACE_MAP = createField(DSL.name("TRACE_MAP"), SQLDataType.VARCHAR(1000000000), this, "");

    private Ctx(Name alias, Table<CtxRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Ctx(Name alias, Table<CtxRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>PUBLIC.CTX</code> table reference
     */
    public Ctx(String alias) {
        this(DSL.name(alias), CTX);
    }

    /**
     * Create an aliased <code>PUBLIC.CTX</code> table reference
     */
    public Ctx(Name alias) {
        this(alias, CTX);
    }

    /**
     * Create a <code>PUBLIC.CTX</code> table reference
     */
    public Ctx() {
        this(DSL.name("CTX"), null);
    }

    public <O extends Record> Ctx(Table<O> path, ForeignKey<O, CtxRecord> childPath, InverseForeignKey<O, CtxRecord> parentPath) {
        super(path, childPath, parentPath, CTX);
    }

    /**
     * A subtype implementing {@link Path} for simplified path-based joins.
     */
    public static class CtxPath extends Ctx implements Path<CtxRecord> {

        private static final long serialVersionUID = 1L;
        public <O extends Record> CtxPath(Table<O> path, ForeignKey<O, CtxRecord> childPath, InverseForeignKey<O, CtxRecord> parentPath) {
            super(path, childPath, parentPath);
        }
        private CtxPath(Name alias, Table<CtxRecord> aliased) {
            super(alias, aliased);
        }

        @Override
        public CtxPath as(String alias) {
            return new CtxPath(DSL.name(alias), this);
        }

        @Override
        public CtxPath as(Name alias) {
            return new CtxPath(alias, this);
        }

        @Override
        public CtxPath as(Table<?> alias) {
            return new CtxPath(alias.getQualifiedName(), this);
        }
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : Public.PUBLIC;
    }

    @Override
    public UniqueKey<CtxRecord> getPrimaryKey() {
        return Keys.CONSTRAINT_10;
    }

    @Override
    public List<ForeignKey<CtxRecord, ?>> getReferences() {
        return Arrays.asList(Keys.CTX_FK_LINE);
    }

    private transient LogPath _log;

    /**
     * Get the implicit join path to the <code>PUBLIC.LOG</code> table.
     */
    public LogPath log() {
        if (_log == null)
            _log = new LogPath(this, Keys.CTX_FK_LINE, null);

        return _log;
    }

    @Override
    public Ctx as(String alias) {
        return new Ctx(DSL.name(alias), this);
    }

    @Override
    public Ctx as(Name alias) {
        return new Ctx(alias, this);
    }

    @Override
    public Ctx as(Table<?> alias) {
        return new Ctx(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Ctx rename(String name) {
        return new Ctx(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Ctx rename(Name name) {
        return new Ctx(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Ctx rename(Table<?> name) {
        return new Ctx(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Ctx where(Condition condition) {
        return new Ctx(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Ctx where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Ctx where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Ctx where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Ctx where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Ctx where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Ctx where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Ctx where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Ctx whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Ctx whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
