package tech.fennec.Protocol.Commands;

import tech.fennec.Protocol.SMBPacket;
import tech.fennec.Utils.Buffer;
import tech.fennec.Utils.MoonLog;

/**
 * Created by Igor Rudym on 01-Dec-16.
 */
public class SMB2_NegotiateContext extends SMBPacket {

    public static short SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x001;
    public static short SMB2_ENCRYPTION_CAPABILITIES = 0x0002;

    public short ContextType;       //2 bytes
    public short DataLength;        //2 bytes
    public int Reserved = 0;            //4 bytes
    public byte[] Data_variable;    //DataLength bytes


    public SMB2_NegotiateContext(byte[] buffer) throws Exception {
        fillStructure(buffer);
    }

    @Override
    //TODO: call it to toByteArray()
    public byte[] response() {
        Buffer dataBuf = new Buffer(getPacketSize());

        dataBuf.putShort(ContextType);
        dataBuf.putShort(DataLength);
        dataBuf.putLong(Reserved);      //should be 0
        dataBuf.putArray(Data_variable);
        return dataBuf.getBuffer();
    }

    @Override
    public int getPacketSize() {
        return 8 + DataLength;
    }

    @Override
    public void fillStructure(byte[] buffer) throws Exception {
        Buffer dataBuf = new Buffer(buffer);
        ContextType = dataBuf.getShort();
        DataLength = dataBuf.getShort();
        Reserved = dataBuf.getLong();
        Data_variable = dataBuf.getArray(DataLength);
    }

    public String toString() {
        String out = "\tType: ";
        if(ContextType == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) out +="SMB2_PREAUTH_INTEGRITY_CAPABILITIES\n";
         else out = "SMB2_ENCRYPTION_CAPABILITIES\n";
        out+= "\tDataLength: " + DataLength + "\n\tData_variable: " + MoonLog.toHexString(Data_variable) + "\n";

        return out;
    }
}
