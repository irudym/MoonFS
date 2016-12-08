package tech.fennec.Protocol.Commands;

import tech.fennec.Utils.MSDType;
import tech.fennec.Utils.MoonLog;
import tech.fennec.Protocol.SMBPacket;
import tech.fennec.Utils.Buffer;

import javax.lang.model.element.NestingKind;

/**
 * Created by Igor Rudym on 25-Nov-16.
 */
public class SMB2_NegotiateRequest extends SMBPacket {

    public class SMB2_NegotiateContextInfo  extends SMBPacket {
        public int NegotiateContextOffset;  //4 bytes
        public short NegotiateContextCount;   //2 bytes
        public short Reserved2;               //2 bytes

        @Override
        public byte[] response() {
            return new byte[0];
        }

        @Override
        public int getPacketSize() {
            return 8;
        }

        @Override
        public void fillStructure(byte[] buffer) throws Exception {
            Buffer dataBuf = new Buffer(buffer);
            NegotiateContextOffset = dataBuf.getLong();
            NegotiateContextCount = dataBuf.getShort();
            Reserved2 = dataBuf.getShort();
        }

        public SMB2_NegotiateContextInfo(byte[] buffer) throws Exception {
            fillStructure(buffer);
        }
    }

    public short StructureSize;   //2 bytes
    public short DialectCount;    //2 bytes
    public short SecurityMode;    //2 bytes
    public short Reserved;        //2 bytes
    public int Capabilities;    //4 bytes
    public MSDType.GUIDPacket ClientGuid;   //16 bytes
    public byte[] ContextOffset_StartTime;  //8 bytes
    //public byte[] Dialects_variable;        //variable
    public SMB2_Dialects Dialects;          //variable = DialectsCount*2 bytes
    public byte[] Padding_variable;         //variable
    public byte[] NegotiateContextList_variable = null; //8 bytes

    public SMB2_NegotiateContextInfo NegotiateContextInfo = null;
    public SMB2_NegotiateContext[] NegotiateContext = null;

    public SMB2_NegotiateRequest(byte[] buffer) throws Exception {
        fillStructure(buffer);
    }

    public byte[] response() {
        byte[] res = new byte[getPacketSize()];

        return res;
    }


    public int getPacketSize() {
        return 60;
    }


    public void fillStructure(byte[] buffer) throws Exception {
        Buffer dataBuf = new Buffer(buffer);
        try {
            StructureSize = dataBuf.getShort();
            DialectCount = dataBuf.getShort();
            SecurityMode = dataBuf.getShort();
            Reserved = dataBuf.getShort();
            Capabilities = dataBuf.getLong();
            ClientGuid = new MSDType.GUIDPacket(dataBuf.getArray(16));
            ContextOffset_StartTime = dataBuf.getArray(16);
            Dialects = new SMB2_Dialects(dataBuf.getArray(DialectCount * 2));
            //Padding_variable = dataBuf.getArray(8);
            //NegotiateContextList_variable = dataBuf.getArray(8);
            //If the Dialects field contains 0x0311, this field (ContextOffset_StartTime) is interpreted as the NegotiateContextOffset, NegotiateContextCount, and Reserved2 fields.
            if(Dialects.hasDialect("0x0311")) {
                NegotiateContextInfo = new SMB2_NegotiateContextInfo(ContextOffset_StartTime);
                NegotiateContextInfo.NegotiateContextOffset -= 64;  //adjust the offset by SMB header size. actually I want to complain
                                                                    //that some strange people work at Microsoft, why did they put offset
                                                                    //counting from the start of the SMB header but not the command packet!?

                //dataBuf.setOffset(NegotiateContextInfo.NegotiateContextOffset);

                NegotiateContext = new SMB2_NegotiateContext[NegotiateContextInfo.NegotiateContextCount];
                int context_offset = 0;
                MoonLog.debug("Context offset: " + NegotiateContextInfo.NegotiateContextOffset);

                for(int i=0;i<NegotiateContextInfo.NegotiateContextCount;i++) {
                    int buf_len = buffer.length - NegotiateContextInfo.NegotiateContextOffset - context_offset;

                    MoonLog.debug("NegotiateContext count: " + i +"/"+ NegotiateContextInfo.NegotiateContextCount);
                    MoonLog.debug("Additional context_offset: " + context_offset);
                    MoonLog.debug("Buffer length: " + buffer.length + "-" + (NegotiateContextInfo.NegotiateContextOffset + context_offset) +"="+buf_len);
                    byte[] context_buffer = new byte[buf_len];
                    MoonLog.debug("Copy buffer with offset: " + (NegotiateContextInfo.NegotiateContextOffset + context_offset));
                    System.arraycopy(buffer, NegotiateContextInfo.NegotiateContextOffset + context_offset,
                            context_buffer,0,buf_len);
                    MoonLog.debug("Context_buffer: " + MoonLog.toHexString(context_buffer));
                    NegotiateContext[i] = new SMB2_NegotiateContext(context_buffer);

                    //align offset by octets, that's doesn't make any sense to align context data block with offset, whyyyy!?
                    if(NegotiateContext[i].getPacketSize() % 8 == 0)
                        context_offset += NegotiateContext[i].getPacketSize();
                    else {
                        int fixed = NegotiateContext[i].getPacketSize()/8;
                        context_offset += (fixed+1)*8;
                    }
                }

            }
        } catch (Exception e) {
            MoonLog.error("Cannot fill SMB2_NegotiateRequest: " + e.getMessage());
        }
    }

    public String toString() {
        String out =  "\t----------------------------------" +
                "\n\t| StructureSize     | " + MoonLog.hex(StructureSize) + " |"+
                "\n\t| DialectCount      | " + MoonLog.hex(DialectCount) + " |"+
                "\n\t| SecurityMode      | " + MoonLog.hex(SecurityMode) + " |"+
                "\n\t| Reserved          | " + MoonLog.hex(Reserved) + " |"+
                "\n\t| Capabilities      | " + MoonLog.hex(Capabilities) + " |"+
                "\n\t| ClientGuid        | " + ClientGuid + " |"+
                "\n\t| Context_StartTime | " + MoonLog.toHexString(ContextOffset_StartTime) + " |"+
                "\n\t| Dialects          | " + Dialects +"\n";
                //"\n\t| Padding           | " + MoonLog.toHexString(Padding_variable) + " |"+
                //"\n\t| NegotiateConte... | " + MoonLog.toHexString(NegotiateContextList_variable) + " |"+

        if(NegotiateContext!=null) {
            for(int i=0;i<NegotiateContext.length;i++)
                out += NegotiateContext[i];
        }
        out += "\n\t----------------------------------";
        return out;
    }
}
