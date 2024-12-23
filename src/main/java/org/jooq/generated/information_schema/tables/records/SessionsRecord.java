/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables.records;


import java.time.OffsetDateTime;

import org.jooq.generated.information_schema.tables.Sessions;
import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class SessionsRecord extends TableRecordImpl<SessionsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.SESSION_ID</code>.
     */
    public void setSessionId(Integer value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.SESSION_ID</code>.
     */
    public Integer getSessionId() {
        return (Integer) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.USER_NAME</code>.
     */
    public void setUserName(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.USER_NAME</code>.
     */
    public String getUserName() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.SERVER</code>.
     */
    public void setServer(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.SERVER</code>.
     */
    public String getServer() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.CLIENT_ADDR</code>.
     */
    public void setClientAddr(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.CLIENT_ADDR</code>.
     */
    public String getClientAddr() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.CLIENT_INFO</code>.
     */
    public void setClientInfo(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.CLIENT_INFO</code>.
     */
    public String getClientInfo() {
        return (String) get(4);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.SESSION_START</code>.
     */
    public void setSessionStart(OffsetDateTime value) {
        set(5, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.SESSION_START</code>.
     */
    public OffsetDateTime getSessionStart() {
        return (OffsetDateTime) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.ISOLATION_LEVEL</code>.
     */
    public void setIsolationLevel(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.ISOLATION_LEVEL</code>.
     */
    public String getIsolationLevel() {
        return (String) get(6);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.EXECUTING_STATEMENT</code>.
     */
    public void setExecutingStatement(String value) {
        set(7, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.EXECUTING_STATEMENT</code>.
     */
    public String getExecutingStatement() {
        return (String) get(7);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SESSIONS.EXECUTING_STATEMENT_START</code>.
     */
    public void setExecutingStatementStart(OffsetDateTime value) {
        set(8, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SESSIONS.EXECUTING_STATEMENT_START</code>.
     */
    public OffsetDateTime getExecutingStatementStart() {
        return (OffsetDateTime) get(8);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.CONTAINS_UNCOMMITTED</code>.
     */
    public void setContainsUncommitted(Boolean value) {
        set(9, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.CONTAINS_UNCOMMITTED</code>.
     */
    public Boolean getContainsUncommitted() {
        return (Boolean) get(9);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.SESSION_STATE</code>.
     */
    public void setSessionState(String value) {
        set(10, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.SESSION_STATE</code>.
     */
    public String getSessionState() {
        return (String) get(10);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.BLOCKER_ID</code>.
     */
    public void setBlockerId(Integer value) {
        set(11, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.BLOCKER_ID</code>.
     */
    public Integer getBlockerId() {
        return (Integer) get(11);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SESSIONS.SLEEP_SINCE</code>.
     */
    public void setSleepSince(OffsetDateTime value) {
        set(12, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SESSIONS.SLEEP_SINCE</code>.
     */
    public OffsetDateTime getSleepSince() {
        return (OffsetDateTime) get(12);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached SessionsRecord
     */
    public SessionsRecord() {
        super(Sessions.SESSIONS);
    }

    /**
     * Create a detached, initialised SessionsRecord
     */
    public SessionsRecord(Integer sessionId, String userName, String server, String clientAddr, String clientInfo, OffsetDateTime sessionStart, String isolationLevel, String executingStatement, OffsetDateTime executingStatementStart, Boolean containsUncommitted, String sessionState, Integer blockerId, OffsetDateTime sleepSince) {
        super(Sessions.SESSIONS);

        setSessionId(sessionId);
        setUserName(userName);
        setServer(server);
        setClientAddr(clientAddr);
        setClientInfo(clientInfo);
        setSessionStart(sessionStart);
        setIsolationLevel(isolationLevel);
        setExecutingStatement(executingStatement);
        setExecutingStatementStart(executingStatementStart);
        setContainsUncommitted(containsUncommitted);
        setSessionState(sessionState);
        setBlockerId(blockerId);
        setSleepSince(sleepSince);
        resetChangedOnNotNull();
    }
}
