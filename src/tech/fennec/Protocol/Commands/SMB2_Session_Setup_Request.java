package tech.fennec.Protocol.Commands;

import tech.fennec.Protocol.SMBPacket;
import tech.fennec.Utils.Buffer;

/**
 * Created by irudym on 25-Nov-16.
 */
public class SMB2_Session_Setup_Request extends SMBPacket {
    public short StructureSize;        //2 bytes
    public byte Flags;                 //1 byte
    public byte SecurityMode;          //1 byte
    public int Capabilities;           //4 bytes
    public int Channel;                //4 bytes
    public short SecurityBufferOffset; //2 bytes
    public short SecurityBufferLength; //2 bytes
    public byte[] PreviousSessionId;   //8 bytes
    public byte[] Buffer_variable;     //variable

    /**
     * Put structure fields to byte array
     * @return byte array with response data
     */
    public byte[] response() {
        return null;
    }

    /**
     * Get size on bytes of the structure
     * @return size of the structure
     */
    public int getPacketSize() {
        return StructureSize;
    }

    /**
     * Fill structure field with data from the buffer
     * @param buffer - raw data
     */
    public void fillStructure(byte[] buffer) throws Exception {
        Buffer dataBuf = new Buffer(buffer);
        StructureSize = dataBuf.getShort();
        Flags =dataBuf.getByte();
        SecurityMode = dataBuf.getByte();
        Capabilities = dataBuf.getLong();
        Channel = dataBuf.getLong();
        SecurityBufferOffset = dataBuf.getShort();
        SecurityBufferLength = dataBuf.getShort();
        PreviousSessionId = dataBuf.getArray(8);
        Buffer_variable = dataBuf.getArray(SecurityBufferLength);
    }
}
