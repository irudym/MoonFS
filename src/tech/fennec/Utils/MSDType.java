package tech.fennec.Utils;

import jdk.nashorn.internal.runtime.ECMAException;

/**
 * Created by Igor Rudym on 28-Nov-16.
 * http://stackoverflow.com/questions/5398557/java-library-for-dealing-with-win32-filetime
 */
public class MSDType {
    /** Difference between Filetime epoch and Unix epoch (in ms). */
    private static final long FILETIME_EPOCH_DIFF = 11644473600000L;

    /** One millisecond expressed in units of 100s of nanoseconds. */
    private static final long FILETIME_ONE_MILLISECOND = 10 * 1000;

    public static long filetimeToMillis(final long filetime) {
        return (filetime / FILETIME_ONE_MILLISECOND) - FILETIME_EPOCH_DIFF;
    }

    public static long millisToFiletime(final long millis) {
        return (millis + FILETIME_EPOCH_DIFF) * FILETIME_ONE_MILLISECOND;
    }

    public static class GUIDPacket {
        public int data1;     //4 bytes
        public short data2;   //2 bytes
        public int data3;     //2 bytes
        public byte[] data4;  //8 bytes

        public GUIDPacket(byte[] buffer)  throws Exception {
            fillStructure(buffer);
        }

        public byte[] toByteArray() {
            Buffer dataBuf = new Buffer(16);
            return dataBuf.getBuffer();
        }

        public int getStructureSize() {
            return 16;
        }

        public void fillStructure(byte[] buffer) throws Exception {
            Buffer dataBuf = new Buffer(buffer);
            data1 = dataBuf.getLong();
            data2 = dataBuf.getShort();
            data3 = dataBuf.getShort();
            data4 = dataBuf.getArray(8);
        }

        public String toString() {
            return String.format("%08x", data1) + "-" + String.format("%04x", data2) + "-" + String.format("%04x", data3) + "-" +
                    MoonLog.toHexStringSmall(data4);
        }
    }
}
