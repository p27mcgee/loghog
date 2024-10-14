package com.contrastsecurity.agent.loghog;

public class Loghog {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("loghog requires a comand line argument specifying the path to a log file to load, e.g.: ");            
            System.out.println("java -jar loghog.jar ~/logs/some-log.err");
        }
    }    
}

