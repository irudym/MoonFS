package tech.fennec.Protocol.Commands;

import tech.fennec.Protocol.SMBPacket;
import tech.fennec.Utils.Buffer;
import tech.fennec.Utils.MoonLog;

/**
 * Created by irudym on 01-Dec-16.
 */
public class SMB2_Dialects extends SMBPacket {

    public String[] dialects = null;

    public SMB2_Dialects(byte[] buffer) throws Exception {
        fillStructure(buffer);
    }

    @Override
    public byte[] response() {
        return new byte[0];
    }

    @Override
    public int getPacketSize() {
        return dialects.length*2;
    }

    @Override
    public void fillStructure(byte[] buffer) throws Exception {
        if(buffer == null) throw new Exception("cannot execute SMB2_Dialect fillStructure functio due to null buffer");
        Buffer dataBuf = new Buffer(buffer);
        int count = buffer.length/2;
        dialects = new String[count];
        for(int i=0;i<count;i++) {
            dialects[i] = MoonLog.hex(dataBuf.getShort());
        }
    }

    public boolean hasDialect(String dialect) {
        if(dialects == null) return false;

        for(int i=0;i<dialects.length; i++)
            if(dialects[i].equals(dialect)) return true;
        return false;
    }

    public String toString() {
        String out = "";
        if(dialects != null)
            for(int i=0;i<dialects.length;i++)
                out+="\t"+dialects[i] + "\n";
        return out;
    }
}
