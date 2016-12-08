package tech.fennec.Protocol;

import tech.fennec.Utils.MoonLog;
import tech.fennec.Utils.Buffer;

/**
 * Created by Igor Rudym on 15-Nov-16.
 */
public class SMBCommand {
    public static byte SMB_COM_NEGOTIATE = 0x72;

    //SMB2 commands
    public static short SMB2_NEGOTIATE = 0x0000;
    public static short SMB2_SESSION_SETUP = 0x0001;
    public static short SMB2_LOGOFF = 0x0002;
    public static short SMB2_TREE_CONNECT = 0x0003;
    public static short SMB2_TREE_DISCONNECT = 0x0004;
    public static short SMB2_CREATE = 0x0005;
    public static short SMB2_CLOSE = 0x0006;
    public static short SMB2_FLUSH = 0x0007;
    public static short SMB2_READ = 0x0008;
    public static short SMB2_WRITE = 0x0009;
    public static short SMB2_LOCK = 0x000A;
    public static short SMB2_IOCTL = 0x000B;
    public static short SMB2_CANCEL = 0x000C;
    public static short SMB2_ECHO = 0x000D;
    public static short SMB2_QUERY_DIRECTORY = 0x000E;
    public static short SMB2_CHANGE_NOTIFY = 0x000F;
    public static short SMB2_QUERY_INFO = 0x0010;
    public static short SMB2_SET_INFO = 0x0011;
    public static short SMB2_OPLOCK_BREAK = 0x0012;


    class SMB_Parameters1 extends SMBPacket {
        public byte WordCount;  //uchar
        public int DialectIndex;       //ushort 2 bytes

        public byte[] response() {
            byte[] res = new byte[4];
            res[0] = WordCount;
            res[1] = (byte)((DialectIndex >>8) & 0xff);
            res[2] = (byte)(DialectIndex & 0xff);
            res[3] = 0;

            return res;
        }

        public int getPacketSize() {
            return 4;
        }

        public void fillStructure(byte[] buffer) {

        }
    }


    public class SMB_Parameters_Negotiate extends SMBPacket {
        byte WordCount;
        int DialectIndex;
        byte SecurityMode;
        int MaxMpxCount;
        int MaxNumberVcs;
        long MaxBufferSize;
        long MaxRawSize;
        long SessionKey;
        long Capabilities;
        byte[] SystemTime;
        int ServerTimeZone;
        byte ChallengeLength;

        public int getPacketSize() {return 35;}

        public byte[] response() {
            byte[] result = new byte[getPacketSize()];
            //TODO: need to fill buffer here
            return result;
        }

        public void fillStructure(byte[] buffer) throws Exception {
            Buffer dataBuf = new Buffer(buffer);

            WordCount = dataBuf.getChar();
            DialectIndex = dataBuf.getShort();
            SecurityMode = dataBuf.getChar();
            MaxMpxCount = dataBuf.getShort();
            MaxNumberVcs = dataBuf.getShort();
            MaxBufferSize = dataBuf.getLong();
            MaxRawSize = dataBuf.getLong();
            SessionKey = dataBuf.getLong();
            Capabilities = dataBuf.getLong();
            SystemTime = dataBuf.getArray(8);
            ServerTimeZone = dataBuf.getShort();
            ChallengeLength = dataBuf.getChar();

            if(dataBuf.getOffset() != getPacketSize()) {
                throw(new Exception("SMB_Parameters_Negotiate packet size mismatch"));
            }
        }

        public String toString() {
            String res = "\t--------------------------------" +
                    "\n\t| WordCount       | " + MoonLog.hex(WordCount) + "         |"+
                    "\n\t| DialectIndex    | " + MoonLog.hex(DialectIndex) + " |"+
                    "\n\t| SecurityMode    | " + MoonLog.hex(SecurityMode) + "         |"+
                    "\n\t| MaxMpxCount     | " + MoonLog.hex(MaxMpxCount) + " |"+
                    "\n\t| MaxNumberVcs    | " + MoonLog.hex(MaxNumberVcs) + " |"+
                    "\n\t| MaxBufferSize   | " + MoonLog.hex(MaxBufferSize) + " |"+
                    "\n\t| MaxRawSize      | " + MoonLog.hex(MaxRawSize) + " |"+
                    "\n\t| SessionKey      | " + MoonLog.hex(SessionKey) + " |"+
                    "\n\t| Capabilities    | " + MoonLog.hex(Capabilities) + " |"+
                    "\n\t| ServerTimeZone  | " + MoonLog.hex(ServerTimeZone) + " |"+
                    "\n\t| ChallengeLength | " + MoonLog.hex(ChallengeLength) + "         |"+
                    "\n\t--------------------------------";
            return res;
        }
    }

    public SMB_Parameters_Negotiate getParametersNegotiateHeader(byte[] buffer) throws Exception {
        SMB_Parameters_Negotiate header = new SMB_Parameters_Negotiate();
        header.fillStructure(buffer);
        return header;
    }


    public class SMB_Data extends SMBPacket {
        public int ByteCount = 0; //2 bytes
        byte[] bytes;

        public byte[] response() {
            byte[] res = new byte[ByteCount + 2];
            res[0] = (byte)((ByteCount >> 8) & 0xff);
            res[1] = (byte)(ByteCount & 0xff);
            if(ByteCount!=0) {
                System.arraycopy(bytes, 0 , res, 2, ByteCount);
            }
            return res;
        }

        public void fillStructure(byte[] buffer) throws Exception {
            Buffer dataBuf = new Buffer(buffer);
            ByteCount = dataBuf.getShort();
            if(ByteCount < 0x0010) {
                throw new Exception("The number of bytes in SMBData MUST be greater than or equal to 0x0010");
            }
            if(ByteCount > buffer.length)
                throw new Exception("Number of bytes in SMB data: " + ByteCount + " exceeds the buffer size: " + buffer.length);
            bytes = new byte[ByteCount];
            System.arraycopy(dataBuf.getArray(ByteCount),0, bytes,0, ByteCount);
        }

        public String toString() {
            return "\t--------------------------------" +
                    "\n\t| ByteCount  | " + MoonLog.hex(ByteCount) + " |"+
                    "\n\t| Bytes: " + MoonLog.toHexString(bytes);
        }

        public int getPacketSize() {
            return ByteCount+2;
        }
    }

    public SMB_Data getData(byte[] buffer) throws Exception {
        SMB_Data data = new SMB_Data();
        data.fillStructure(buffer);
        return data;
    }

}
