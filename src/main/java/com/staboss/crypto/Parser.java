package com.staboss.crypto;

import kotlin.io.FilesKt;
import kotlin.text.Charsets;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.io.File;

public final class Parser {
    @Option(name = "-b", usage = "specify binary output")
    public boolean binary = false;

    @Option(name = "-e", usage = "encrypt message", forbids = {"-d"})
    public boolean encrypt = false;

    @Option(name = "-d", usage = "decrypt message", forbids = {"-e"})
    public boolean decrypt = false;

    @Option(name = "-s", usage = "source file", required = true, metaVar = "FILE")
    public String sourceFile;

    @Option(name = "-r", usage = "result file", metaVar = "FILE")
    public String resultFile;

    @Option(name = "-k", usage = "secret key", required = true, metaVar = "KEY")
    public String key;

    @Option(name = "-c", usage = "AES or DES", required = true, metaVar = "CIPHER")
    public String cipher;

    public String message;

    private static Parser parser = null;
    private static CmdLineParser cmdLineParser = null;

    private Parser() {
    }

    public static Parser getInstance() {
        if (parser == null) {
            parser = new Parser();
            cmdLineParser = new CmdLineParser(parser);
        }
        return parser;
    }

    public boolean parseArgs(String[] args) {
        try {
            cmdLineParser.parseArgument(args);
            File file = new File(sourceFile);
            if (!file.exists() || (!encrypt && !decrypt) || key.length() % 8 != 0 || cipher.isEmpty()) {
                throw new IllegalArgumentException("Check input parameters!");
            }
            if (cipher.equals("AES") || cipher.equals("DES")) {
                message = FilesKt.readText(file, Charsets.UTF_8);
                return true;
            } else {
                throw new IllegalArgumentException("Check cipher type!");
            }
        } catch (IllegalArgumentException | CmdLineException e) {
            System.err.println(e.getMessage() + "\n");
            usage();
            return false;
        }
    }

    public static void usage() {
        System.err.println("usage: java -jar crypto-symmetric.jar [-b] -e|-d -c CIPHER -s FILE [-r FILE] -k KEY\n");
        System.err.println(arguments);
    }

    private static final String arguments = "optional arguments:\n" +
            "  -b         : specify binary output\n" +
            "  -d         : decrypt message\n" +
            "  -e         : encrypt message\n" +
            "  -k KEY     : secret key\n" +
            "  -s FILE    : source file\n" +
            "  -r FILE    : result file\n" +
            "  -c CIPHER  : AES or DES";
}
