package tech.fennec.Protocol;

/**
 * Created by irudym on 19-Nov-16.
 */
public class SMBProtocol {
    SMB smbTransport;
    SMBCommand smbCommand;

    public SMBProtocol() {
        smbTransport = new SMB();
        smbCommand = new SMBCommand();
    }

    public SMB.SMB_Header getSMBHeader(byte[] buffer) throws Exception {
        return smbTransport.getSMBHeader(buffer);
    }

    public SMB.SMB2_HeaderSync getSMB2Header(byte[] buffer) throws Exception {
        return smbTransport.getSMB2SyncHeader(buffer);
    }

    public SMBCommand.SMB_Parameters_Negotiate getSMBParametersNegotiateHeader(byte [] buffer) throws Exception {
        return smbCommand.getParametersNegotiateHeader(buffer);
    }

    public SMB.TCP_Header getTCPHeader(byte[] buffer) throws Exception {
        return smbTransport.getTCPHeader(buffer);
    }

    public SMBCommand.SMB_Data getSMBData(byte[] buffer) throws Exception {
        return smbCommand.getData(buffer);
    }
 }
