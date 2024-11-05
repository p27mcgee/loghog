/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.public_.tables.records;


import org.jooq.Record1;
import org.jooq.generated.public_.tables.CtxMisfits;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class CtxMisfitsRecord extends UpdatableRecordImpl<CtxMisfitsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>PUBLIC.CTX_MISFITS.LINE</code>.
     */
    public void setLine(Integer value) {
        set(0, value);
    }

    /**
     * Getter for <code>PUBLIC.CTX_MISFITS.LINE</code>.
     */
    public Integer getLine() {
        return (Integer) get(0);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    @Override
    public Record1<Integer> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached CtxMisfitsRecord
     */
    public CtxMisfitsRecord() {
        super(CtxMisfits.CTX_MISFITS);
    }

    /**
     * Create a detached, initialised CtxMisfitsRecord
     */
    public CtxMisfitsRecord(Integer line) {
        super(CtxMisfits.CTX_MISFITS);

        setLine(line);
        resetChangedOnNotNull();
    }
}
