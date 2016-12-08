package tech.fennec.Protocol.Commands;

import tech.fennec.Protocol.SMBPacket;
import tech.fennec.Utils.Buffer;

/**
 * Created by irudym on 25-Nov-16.
 */
public class SMB2_Session_Setup_Response extends SMBPacket {
    public short StructureSize = 9;         //2 bytes, The server MUST set this to 9, indicating the size of the fixed part of the response structure not including the header.
    public short SessionFlags;              //2 bytes
    public short SecurityBufferOffset = 9;  //2 bytes
    public short SecurityBufferLength;      //2 bytes
    public byte[] Buffer_variable;          //variable

    /**
     * Put structure fields to byte array
     * @return byte array with response data
     */
    public byte[] response() {
        Buffer dataBuf = new Buffer(8 + Buffer_variable.length);

        dataBuf.putShort(StructureSize); //should  be 9
        dataBuf.putShort(SessionFlags);
        dataBuf.putShort(SecurityBufferOffset); //should be 9
        dataBuf.putShort(SecurityBufferLength);
        dataBuf.putArray(Buffer_variable);

        return dataBuf.getBuffer();
    }

    /**
     * Get size on bytes of the structure
     * @return size of the structure
     */
    public int getPacketSize() {
        return 8 + Buffer_variable.length;
    }

    /**
     * Fill structure field with data from the buffer
     * @param buffer - raw data
     */
    public void fillStructure(byte[] buffer) throws Exception {
    }
}
