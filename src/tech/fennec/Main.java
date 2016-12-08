package tech.fennec;

import tech.fennec.Debug.MoonSniffer;

public class Main {

    public static void main(String[] args) {

        if(args.length>1) {
            if(args[0].equals("--debug")) {
                //--debug 192.168.64.128
                System.out.println("Start moonServer in debug mode.");
                System.out.println("Sniffing address: " + args[1] + "\n");
                MoonSniffer sniffer = new MoonSniffer(args[1], 445);
                byte[] buf = sniffer.testSeq("test1.seq");
                sniffer.sendData(buf, buf.length);
            }
        } else {
            MoonServer server = MoonServer.createServer(445);
        }
    }
}
