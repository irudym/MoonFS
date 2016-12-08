package tech.fennec.Protocol.Commands;

import tech.fennec.Protocol.SMBPacket;
import tech.fennec.Utils.Buffer;
import tech.fennec.Utils.MoonLog;

/**
 * Created by Igor Rudym on 25-Nov-16.
 */
public class SMB2_NegotiateResponse extends SMBPacket {
    public short StructureSize;   //2 bytes  - The server MUST set this field to 65, indicating the size of the response structure, not including the header
    public short SecurityMode;    //2 bytes
    public short DialectRevision; //2 bytes
    public short NegotiateContextCount_Reserved; //2 bytes
    public byte[] ServerGuid;   //16 bytes
    public int Capabilities;    //4 bytes
    public int MaxTransactSize; //4 bytes
    public int MaxReadSize;     //4 bytes
    public int MaxWriteSize;    //4 bytes
    public byte[] SystemTime;   //8 bytes
    public byte[] ServerStartTime;//8 bytes
    public short SecurityBufferOffset; //2 bytes
    public short SecurityBufferLength; //2 bytes
    public int NegotiateContextOffset_Reserved2;    //4 bytes
    public byte[] Buffer_variable; //depends of SecurityBufferOffset and SecurityBufferLength
    public byte[] Padding_variable; //Optional padding between the end of the Buffer field and the first negotiate context in the NegotiateContextList so that the first negotiate context is 8-byte aligned.
    public byte[] NegotiateContextList_variable; //If the DialectRevision field is 0x0311, a list of negotiate contexts. The first negotiate context in the list MUST appear at the byte offset indicated by the SMB2 NEGOTIATE response's NegotiateContextOffset. Subsequent negotiate contexts MUST appear at the first 8-byte aligned offset following the previous negotiate context.

    public SMB2_NegotiateResponse() {
        //set default values
        SecurityBufferLength = 0;
        Buffer_variable = new byte[0];
    }
    /**
     * Put structure fields to byte array
     * @return byte array with response data
     */
    public byte[] response() {
        Buffer dataBuff = new Buffer(getPacketSize());

        dataBuff.putShort(StructureSize);
        dataBuff.putShort(SecurityMode);
        dataBuff.putShort(DialectRevision);
        dataBuff.putShort(NegotiateContextCount_Reserved);
        dataBuff.putArray(ServerGuid);
        dataBuff.putLong(Capabilities);
        dataBuff.putLong(MaxTransactSize);
        dataBuff.putLong(MaxReadSize);
        dataBuff.putLong(MaxWriteSize);
        dataBuff.putArray(SystemTime);
        dataBuff.putArray(ServerStartTime);
        dataBuff.putShort(SecurityBufferOffset);
        dataBuff.putShort(SecurityBufferLength);
        dataBuff.putLong(NegotiateContextOffset_Reserved2);
        if(SecurityBufferLength!=0) dataBuff.putArray(Buffer_variable);

        //fields below are optional
        //dataBuff.putArray(Padding_variable);
        //dataBuff.putArray(NegotiateContextList_variable);
        return dataBuff.getBuffer();
    }

    /**
     * Get size on bytes of the structure
     * @return size of the structure
     */
    public int getPacketSize() {
        //adjust Structure size as the real size is 64 bytes (not 65)
        return StructureSize + SecurityBufferLength - 1;
    }

    /**
     * Fill structure field with data from the buffer
     * @param buffer - raw data
     */
    public void fillStructure(byte[] buffer) throws Exception {

    }

    public String toString() {
        return "\t----------------------------------" +
                "\n\t| StructureSize     | " + MoonLog.hex(StructureSize) + " |"+
                "\n\t| SecurityMode      | " + MoonLog.hex(SecurityMode) + " |"+
                "\n\t| DialectRevision   | " + MoonLog.hex(DialectRevision) + " |"+
                "\n\t| NCC_Reserved      | " + MoonLog.hex(NegotiateContextCount_Reserved) + " |"+
                "\n\t| ServerGuid        | " + MoonLog.toHexString(ServerGuid) + " |"+
                "\n\t| Capabilities      | " + MoonLog.hex(Capabilities) + " |"+
                "\n\t| MaxTransactSize   | " + MoonLog.hex(MaxTransactSize) + " |"+
                "\n\t| MaxReadSize       | " + MoonLog.hex(MaxReadSize) + " |"+
                "\n\t| MaxWriteSize      | " + MoonLog.hex(MaxWriteSize) + " |"+
                "\n\t| SystemTime        | " + MoonLog.toHexString(SystemTime) + " |"+
                "\n\t| ServerStartTime   | " + MoonLog.toHexString(ServerStartTime) + " |"+
                "\n\t| SecurityBufferOff | " + MoonLog.hex(SecurityBufferOffset) + " |"+
                "\n\t| SecurityBufferLen | " + MoonLog.hex(SecurityBufferLength) + " |"+
                "\n\t| NCO_Reserved2     | " + MoonLog.hex(NegotiateContextOffset_Reserved2) + " |"+
                "\n\t| Buffer            | " + MoonLog.toHexString(Buffer_variable) + " |"+
                //"\n\t| NegotiateConte... | " + MoonLog.toHexString(NegotiateContextList_variable) + " |"+
                "\n\t----------------------------------";
    }
}
