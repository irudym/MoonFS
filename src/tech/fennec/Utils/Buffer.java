package tech.fennec.Utils;

import java.nio.charset.StandardCharsets;

/**
 * Created by Igor Rudym on 19-Nov-16.
 */
//TODO: Maybe rename it to DataBuffer to avoid mistakes in the code?
public class Buffer {
    //1 byte
    public static byte toUChar(byte[] buffer, int offset) {
        return buffer[offset];
    }

    //2 bytes
    //TODO: Need to change to short type
    public static short toUShot(byte[] buffer, int offset) {
        return (short)((buffer[offset] << 8) | (buffer[offset+1] & 0xff));
    }

    //2 bytes little endian
    public static short toLShort(byte[] buffer, int offset) {
        return (short)((buffer[offset] & 0xff) | (buffer[offset+1] << 8));
    }

    //4 bytes little endian
    public static int toLLong(byte[] buffer, int offset) {
        return (buffer[offset] & 0xff) | (buffer[offset+1] << 8) | (buffer[offset+2] << 16) | (buffer[offset+3] << 24);
    }

    //4 bytes
    public static int toULong(byte[] buffer, int offset) {
        return (buffer[offset] << 24) | (buffer[offset+1] << 16) | (buffer[offset+2] << 8) | (buffer[offset+3] & 0xff);
    }

    public static byte[] toArray(String string) {
        return string.getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] longToArray(long num) {
        byte[] res = new byte[8];
        res[0] = (byte)(num & 0xff);
        int shift = 8;
        for(int i=1; i<8; i++) {
            res[i] = (byte)((num >> shift) & 0xff);
        }
        return res;
    }

    private byte[] dataBuffer;
    private int offset;
    private boolean littleEndian = true;

    public Buffer(byte[] buf) {
        dataBuffer = buf;
        offset = 0;
    }

    public Buffer(int size) {
        offset = 0;
        dataBuffer = new byte[size];
    }

    public Buffer bigEndian() {
        littleEndian = false;
        return this;
    }

    //DEPRECATED
    public void setLittleEndian(boolean value) {
        littleEndian = value;
    }

    public byte[] getBuffer() {
        return dataBuffer;
    }

    //DEPRECATED
    public byte getChar() {
        return toUChar(dataBuffer, offset++);
    }

    public byte getByte() {
        if(!littleEndian) littleEndian = true;
        return  toUChar(dataBuffer, offset++);
    }

    /**
     * Covert 2 bytes from data buffer to int value and shift point in the buffer to 2 bytes
     * @return 2 byte value representation from data buffer
     */
    public short getShort() {
        short res = 0;
        if(!littleEndian) {
            res = toUShot(dataBuffer, offset);
            littleEndian = true;
        }
            else res = toLShort(dataBuffer, offset);
        offset += 2;
        return res;
    }

    /**
     * Covert 4 bytes from data buffer to int value and shift point in the buffer to 2 bytes
     * @return 4 byte value representation from data buffer
     */
    public int getLong() {
        int res;
        if(!littleEndian) {
            res = toULong(dataBuffer, offset);
            littleEndian = true;
        } else res = toLLong(dataBuffer, offset);
        offset+=4;
        return res;
    }

    public byte[] getArray(int size) {
        byte[] res = new byte[size];
        System.arraycopy(dataBuffer, offset, res, 0, size);
        offset += size;
        return res;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public int putChar(byte value) {
        dataBuffer[offset++] = value;
        return offset;
    }

    public int putShort(short value) {
        //put little endian
        if(littleEndian) {
            dataBuffer[offset++] = (byte) (value & 0xff);
            dataBuffer[offset++] = (byte) ((value >> 8) & 0xff);
        } else {
            dataBuffer[offset++] = (byte) ((value >> 8) & 0xff);
            dataBuffer[offset++] = (byte) (value & 0xff);
            littleEndian = true;
        }
        return offset;
    }

    public int putLong(long value) {
        //put in little endian form
        if(littleEndian) {
            dataBuffer[offset++] = (byte) (value & 0xff);
            dataBuffer[offset++] = (byte) ((value >> 8) & 0xff);
            dataBuffer[offset++] = (byte) ((value >> 16) & 0xff);
            dataBuffer[offset++] = (byte) ((value >> 24) & 0xff);
        } else {
            dataBuffer[offset++] = (byte) ((value >> 24) & 0xff);
            dataBuffer[offset++] = (byte) ((value >> 16) & 0xff);
            dataBuffer[offset++] = (byte) ((value >> 8) & 0xff);
            dataBuffer[offset++] = (byte) (value & 0xff);
            littleEndian = true;
        }
        return offset;
    }

    public int putArray(byte[] data) {
        System.arraycopy(data, 0, dataBuffer, offset, data.length);
        offset += data.length;
        return offset;
    }
}
