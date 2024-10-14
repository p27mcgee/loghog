package com.contrastsecurity.agent.loghog;

import picocli.CommandLine;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

@Command(name = "load", mixinStandardHelpOptions = true, version = "load 1.0",
         description = "Loads an agent log file.")
public class LoadLogCommand implements Runnable {

    @Option(names = {"-l", "--logfile"}, description = "The log file to load")
    private String name = "World";

    @Override
    public void run() {
        System.out.printf("Hello, %s!%n", name);
    }

    public static void main(String[] args) {
        new CommandLine(new LoadLogCommand()).execute(args);
    }
}