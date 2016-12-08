package tech.fennec.Utils;

import tech.fennec.LogLevel;

import java.text.SimpleDateFormat;

/**
 * Created by Igor Rudym on 15-Nov-16.
 */

public class MoonLog {

    //Return string of bytes in hex format
    public static String hex(byte n) {
        // call toUpperCase() if that's required
        return String.format("%02X", n);
    }

    public static String hex(short n) { return String.format("0x%04X", n); }
    public static String hex(int n) {
        return String.format("0x%08X", n);
    }

    public static String hex(long n) {
        return String.format("0x%08X", n);
    }

    public static String toHexString(byte[] buffer) {
        if(buffer == null) return "null";
        return MoonLog.toHexString(buffer, buffer.length);
    }

    public static String toHexString(byte[] buffer, int size) {
        String out = "";
        for(int i=0; i<size; i++) {
            out += MoonLog.hex(buffer[i]) + " ";
            //if (i % 4 == 0) out += " | ";
        }
        return out;
    }

    /**
     * covert byte array to hex string with small letters and without separators
     * @param buffer - byte array
     * @return string
     */
    public static String toHexStringSmall(byte[] buffer) {
        String out = "";
        for(int i=0;i<buffer.length;i++) {
            out += String.format("%02x", buffer[i]);
        }
        return out;
    }

    public static String toASCIIString(byte[] buffer, int size) {
        String out ="";
        for(int i=0; i<size; i++)
            out += (char)buffer[i];
        return out;
    }


    public static void println(LogLevel level, String message) {
        String level_str = "DEBUG";
        switch (level) {
            case ERROR: level_str = "ERROR"; break;
            case INFO: level_str = "INFO"; break;
        }
        SimpleDateFormat time_formatter = new SimpleDateFormat("yyyy-MM-dd_HH:mm");
        String current_time_str = time_formatter.format(System.currentTimeMillis());
        System.out.println("[" + level_str + "]:" + current_time_str + " :: " + message);
    }

    public static void info(String message) {
        MoonLog.println(LogLevel.INFO, message);
    }

    public static void error(String message) {
        MoonLog.println(LogLevel.ERROR, message);
    }

    public static void debug(String message) {
        MoonLog.println(LogLevel.DEBUG, message);
    }
}
