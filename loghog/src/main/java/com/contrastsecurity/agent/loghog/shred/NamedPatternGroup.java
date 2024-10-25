package com.contrastsecurity.agent.loghog.shred;

public class NamedPatternGroup {
    public static final String LOG_TIMESTAMP_EXTRACTOR = "?<log_timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3})";
    public static final String LOG_THREAD_EXTRACTOR = "\\[(?<log_thread>\\S+) \\S+]";
    
    public static final String LOG_LEVEL_ERROR = "ERROR";
    public static final String LOG_LEVEL_WARN = "WARN";
    public static final String LOG_LEVEL_INFO = "INFO";
    public static final String LOG_LEVEL_DEBUG = "DEBUG";
    public static final String LOG_LEVEL_TRACE = "TRACE";
    public static final String LOG_LEVEL = "(" + LOG_LEVEL_ERROR +
            "|" + LOG_LEVEL_WARN + "|" + LOG_LEVEL_INFO +
            "|" + LOG_LEVEL_DEBUG + "|" + LOG_LEVEL_TRACE + ")";
}
