package tech.fennec.Protocol;

/**
 * Created by irudym on 16-Nov-16.
 */
public abstract class SMBPacket {
    /**
     * Put structure fields to byte array
     * @return byte array with response data
     */
    //TODO: need to rename it to toByteArray()
    public abstract byte[] response();

    /**
     * Get size on bytes of the structure
     * @return size of the structure
     */
    public abstract int getPacketSize();

    /**
     * Fill structure field with data from the buffer
     * @param buffer - raw data
     */
    public abstract void fillStructure(byte[] buffer) throws Exception;
}
