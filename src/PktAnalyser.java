import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;

/**
 * PktAnalyser.java
 * 
 * This code reads the content of datafile provided
 * in .bin format and prints the contents of the datafile
 * 
 * The code works for Ether, IP, and ICMP, TCP, and UDP headers
 * 
 * Created by Darryl Pinto on 9/5/2017.
 */
public class PktAnalyser {

    private static int PROTOCOL = -1;


    /**
     * The main method
     *
     * @param args Command line arguments, args[0] is the path to the datafile (.bin file)
     * @throws IOException IOException thrown if FileInputStream fails.
     */
    public static void main(String[] args) throws IOException {

        String fileName = args[0];
        FileInputStream inputFileStream = new FileInputStream(fileName);

        int singleByte = inputFileStream.read();
        StringBuilder hexString = new StringBuilder();

        while (singleByte != -1) {

            String byteString = Integer.toHexString(singleByte);
            if (byteString.length() == 1)
                byteString = "0" + byteString;

            hexString.append(byteString);

            singleByte = inputFileStream.read();
        }


        getEthernetHeader(hexString);
        getIPHeader(hexString);

        switch (PROTOCOL) {
            case 1:
                getICMPHeader(hexString);
                break;
            case 6:
                getTCPHeader(hexString);
                break;
            case 17:
                getUDPHeader(hexString);
                break;
        }

    }

    /**
     * Method to print Ethernet Header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void getEthernetHeader(StringBuilder hexString) {

        System.out.println("ETHER:  ----- Ether Header ----- \n" + "ETHER: ");

        System.out.println("ETHER:  Packet Size\t= " +
                hexString.length() / 2 + " bytes");


        printMACAddress(hexString, "Destination");

        printMACAddress(hexString, "Source\t");

        printEther_IPType(hexString);

        System.out.println("ETHER:");


    }

    /**
     * Method to print IP type, if IPv4 or IPv6 in the Ether header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printEther_IPType(StringBuilder hexString) {

        String IP_typeString = popStringFromHexdump(hexString, 4);

        String IP_type = "";

        if (IP_typeString.equals("0800"))
            IP_type = "IPv4";
        else if (IP_typeString.equals("86dd"))
            IP_type = "IPv6";

        System.out.printf("ETHER:  Ethertype\t= %s (%s)\n",
                IP_typeString, IP_type);

    }

    /**
     * Method to print MAC address in Ether header
     *
     * @param hexString   StringBuilder object containing the hexdump
     * @param addressType String says if source or destination address
     */
    private static void printMACAddress(StringBuilder hexString,
                                        String addressType) {

        char[] address = new char[12];
        hexString.getChars(0, address.length, address, 0);
        hexString.delete(0, address.length);

        System.out.print("ETHER:  " + addressType + "\t= ");

        for (int i = 0; i < address.length; i += 2) {
            String part = "" + address[i] + address[i + 1];
            if (part.charAt(0) == '0') {
                System.out.print(part.charAt(1));
            } else
                System.out.print(part);

            if (i != address.length - 2)
                System.out.print(":");
            else
                System.out.print(",");

        }
        System.out.println();


    }

    /**
     * Method to print the contents of IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     * @throws UnknownHostException Exception thrown when no host is found
     */
    private static void getIPHeader(StringBuilder hexString) throws UnknownHostException {

        System.out.println("IP:   ----- IP Header ----- \n" + "IP: ");

        printIP_Version(hexString);

        printIP_IHL(hexString);

        printIP_TypeOfService(hexString);

        printIP_Length(hexString);

        printIP_Identification(hexString);

        printIP_FlagFragment(hexString);

        printIP_TTL(hexString);

        printIP_Protocol(hexString);

        print_Checksum(hexString, "IP");

        printIP_Address(hexString, "Source");

        printIP_Address(hexString, "Destination");

        System.out.println("IP:   No options \n" + "IP: ");

    }

    /**
     * Method to print the version in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_Version(StringBuilder hexString) {
        char[] version = new char[1];
        hexString.getChars(0, version.length, version, 0);
        hexString.delete(0, version.length);
        System.out.println("IP:   Version = " + version[0]);

    }

    /**
     * Method to print Internet Header Length in the IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_IHL(StringBuilder hexString) {
        char[] IHL = new char[1];  // Internet Header Length
        hexString.getChars(0, IHL.length, IHL, 0);
        hexString.delete(0, IHL.length);
        int internetHeaderLength = ((int) IHL[0] - 48) * 4; // ASCII of 0 = 48
        System.out.println("IP:   Header Length = " + internetHeaderLength);

    }

    /**
     * Method to print type of service in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_TypeOfService(StringBuilder hexString) {

        HashMap<String, String> toS_Lookup = new HashMap<>();
        toS_Lookup.put("111", "Network Control");
        toS_Lookup.put("110", "Inter-network Control");
        toS_Lookup.put("101", "CRITIC/ECP");
        toS_Lookup.put("100", "Flash Override");
        toS_Lookup.put("011", "Flash");
        toS_Lookup.put("010", "Immediate");
        toS_Lookup.put("001", "Priority");
        toS_Lookup.put("000", "Routine");

        String typeOfServiceHex = popStringFromHexdump(hexString, 2);
        System.out.println("IP:   Type of Service = 0x" + typeOfServiceHex);

        String typeOfServiceBinary = convertHexToBinary(typeOfServiceHex);

        String precedence = typeOfServiceBinary.substring(0, 3);
        char delay = typeOfServiceBinary.charAt(3);
        char throughput = typeOfServiceBinary.charAt(4);
        char reliability = typeOfServiceBinary.charAt(5);

        System.out.printf("IP:\t\txxx. .... = %s (%s)\n",
                precedence, toS_Lookup.get(precedence));

        System.out.printf("IP:\t\t...%c .... = ", delay);

        if (delay == '0')
            System.out.println("Normal Delay");
        else
            System.out.println("Low Delay");

        System.out.printf("IP:\t\t.... %c... = ", throughput);

        if (throughput == '0')
            System.out.println("Normal Throughput");
        else
            System.out.println("High throughput");

        System.out.printf("IP:\t\t.... .%c.. = ", reliability);

        if (reliability == '0')
            System.out.println("Normal Reliability");
        else
            System.out.println("High Reliability");

    }

    /**
     * Method to print length in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_Length(StringBuilder hexString) {

        String IPLength = popStringFromHexdump(hexString, 4);

        System.out.printf("IP:   Total Length = %d bytes\n",
                Integer.parseInt(IPLength, 16));

    }

    /**
     * Method to print Identification in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_Identification(StringBuilder hexString) {

        String identification = popStringFromHexdump(hexString, 4);

        System.out.printf("IP:   Identification = %d \n",
                Integer.parseInt(identification, 16));

    }

    /**
     * Method to print Flag and Fragment Offset in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_FlagFragment(StringBuilder hexString) {

        String fragment = popStringFromHexdump(hexString, 4);


        System.out.println("IP:   Flags = 0x" + fragment.charAt(0));

        String fragmentBinary = convertHexToBinary(fragment);
        System.out.printf("IP:   \t.%c.. .... =", fragmentBinary.charAt(1));
        if (fragmentBinary.charAt(1) == '0')
            System.out.println(" may fragment");
        else
            System.out.println(" do not fragment");


        System.out.printf("IP:   \t..%c. .... =", fragmentBinary.charAt(2));
        if (fragmentBinary.charAt(2) == '0')
            System.out.println(" last fragment");
        else
            System.out.println(" more fragments");

        int offset = Integer.parseInt(fragmentBinary.
                substring(3, fragmentBinary.length()), 2);

        offset *= 8;
        System.out.printf("IP:   Fragment offset = %d bytes\n", offset);

    }

    /**
     * Method to print Time to Live in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_TTL(StringBuilder hexString) {

        String TTL = popStringFromHexdump(hexString, 2);

        System.out.printf("IP:   Time to live = %d seconds/hops\n",
                Integer.parseInt(TTL, 16));

    }

    /**
     * Method to print Protocol in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printIP_Protocol(StringBuilder hexString) {

        String protocol = popStringFromHexdump(hexString, 2);
        int protocolNo = Integer.parseInt(protocol, 16);
        PROTOCOL = protocolNo;
        System.out.printf("IP:   Protocol = %d ", protocolNo);

        switch (protocolNo) {
            case 1:
                System.out.println("(ICMP)");
                break;
            case 6:
                System.out.println("(TCP)");
                break;
            case 17:
                System.out.println("(UDP)");
                break;

            default:
                System.out.println("Unknown Protocol");
                break;
        }

    }

    /**
     * Method to print IP Address in IP header
     *
     * @param hexString StringBuilder object containing the hexdump
     * @param type      String saying if Source or Destination
     * @throws UnknownHostException Exception thrown when no host is found
     */
    private static void printIP_Address(StringBuilder hexString, String type) throws UnknownHostException {

        char[] address = new char[8];
        hexString.getChars(0, address.length, address, 0);
        hexString.delete(0, address.length);

        String IP_address = "";

        for (int i = 0; i < address.length; i += 2) {
            String partialIP = String.valueOf(address[i]) + String.valueOf(address[i + 1]);
            IP_address += "" + Integer.parseInt(partialIP, 16);

            if (i != address.length - 2)
                IP_address += ".";

        }
        InetAddress inetaddress = InetAddress.getByName(IP_address);

        String IP_hostname = inetaddress.getHostName();

        if (IP_hostname.equals(IP_address))
            IP_hostname = "(hostname unknown)";

        System.out.printf("IP:   %s address = %s, %s\n", type, IP_address, IP_hostname);

    }

    /**
     * Method to get contents of the UDP Header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void getUDPHeader(StringBuilder hexString) {

        System.out.println("UDP:  ----- UDP Header ----- \n" + "UDP: ");

        print_Port(hexString, "Source", "UDP");
        print_Port(hexString, "Destination", "UDP");
        printUDP_Length(hexString);
        print_Checksum(hexString, "UDP");

        print_Data(hexString, "UDP");

    }

    /**
     * Method to length in UDP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printUDP_Length(StringBuilder hexString) {

        String UDP_length = popStringFromHexdump(hexString, 4);

        System.out.printf("UDP:  Length = %d\n", Integer.parseInt(UDP_length, 16));
    }

    /**
     * Method to get contents in TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void getTCPHeader(StringBuilder hexString) {
        System.out.println("TCP:  ----- TCP Header ----- \n" + "TCP: ");

        print_Port(hexString, "Source", "TCP");

        print_Port(hexString, "Destination", "TCP");

        printTCP_Sequence(hexString);

        printTCP_Acknowledgement(hexString);

        printTCP_Offset(hexString);

        printTCP_Reserved_Control(hexString);

        printTCP_Window(hexString);

        print_Checksum(hexString, "TCP");

        printTCP_UrgentPointer(hexString);

        System.out.println("TCP:  No options \n" + "TCP: ");

        print_Data(hexString, "TCP");
    }


    /**
     * Method to print Urgent Pointer of TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printTCP_UrgentPointer(StringBuilder hexString) {

        String urgent = popStringFromHexdump(hexString, 4);

        System.out.printf("TCP:  Urgent Pointer = %d\n", Integer.parseInt(urgent, 16));

    }

    /**
     * Method to print Window in TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printTCP_Window(StringBuilder hexString) {

        String window = popStringFromHexdump(hexString, 4);

        System.out.printf("TCP:  Window = %d\n", Integer.parseInt(window, 16));
    }

    /**
     * Method to print Reserved and Control bits in TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printTCP_Reserved_Control(StringBuilder hexString) {

        String reserved_control = popStringFromHexdump(hexString, 3);
        String reserved_controlBinary = convertHexToBinary(reserved_control);

        System.out.printf("TCP:  Flags = 0x%s \n", reserved_control);

        String neg = "No ";
        String status = "";
        char ch = reserved_controlBinary.charAt(6);
        if (ch == '0')
            status = neg;
        System.out.printf("TCP:\t\t..%c. .... = %surgent pointer \n", ch, status);

        status = "";
        ch = reserved_controlBinary.charAt(7);
        if (ch == '0')
            status = neg;
        System.out.printf("TCP:\t\t...%c .... = %sAcknowledgement \n", ch, status);

        status = "";
        ch = reserved_controlBinary.charAt(8);
        if (ch == '0')
            status = neg;
        System.out.printf("TCP:\t\t.... %c... = %sPush \n", ch, status);

        status = "";
        ch = reserved_controlBinary.charAt(9);
        if (ch == '0')
            status = neg;
        System.out.printf("TCP:\t\t.... .%c.. = %sreset \n", ch, status);

        status = "";
        ch = reserved_controlBinary.charAt(10);
        if (ch == '0')
            status = neg;
        System.out.printf("TCP:\t\t.... ..%c. = %sSyn \n", ch, status);

        status = "";
        ch = reserved_controlBinary.charAt(11);
        if (ch == '0')
            status = neg;
        System.out.printf("TCP:\t\t.... ...%c = %sFin \n", ch, status);
    }

    /**
     * Method to print Offset in TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printTCP_Offset(StringBuilder hexString) {

        String TCP_offset = popStringFromHexdump(hexString, 1);

        System.out.printf("TCP:  Data offset = %d bytes\n", Integer.parseInt(TCP_offset) * 4);
    }

    /**
     * Method to print Acknowledgement in TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printTCP_Acknowledgement(StringBuilder hexString) {

        String TCP_ack = popStringFromHexdump(hexString, 8);

        System.out.printf("TCP:  Acknowledgement number = %d \n", Long.parseLong(TCP_ack, 16));


    }

    /**
     * Method to print Sequence in TCP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printTCP_Sequence(StringBuilder hexString) {

        String sequence = popStringFromHexdump(hexString, 8);

        System.out.printf("TCP:  Sequence number = %d \n", Integer.parseInt(sequence, 16));
    }

    /**
     * Method to get Contents of ICMP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void getICMPHeader(StringBuilder hexString) {

        System.out.println("ICMP:  ----- ICMP Header ----- \n" + "ICMP: ");

        printICMP_Type(hexString);
        printICMP_Code(hexString);
        print_Checksum(hexString, "ICMP");

        System.out.println("ICMP:");

    }

    /**
     * Method to print Code in ICMP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printICMP_Code(StringBuilder hexString) {

        String code = popStringFromHexdump(hexString, 2);

        System.out.printf("ICMP:   Code = %d\n", Integer.parseInt(code, 16));

    }

    /**
     * Method to print Type in ICMP header
     *
     * @param hexString StringBuilder object containing the hexdump
     */
    private static void printICMP_Type(StringBuilder hexString) {


        HashMap<Integer, String> lookup = new HashMap<>();
        lookup.put(0, "Echo Reply");
        lookup.put(3, "Destination Unreachable");
        lookup.put(4, "Source Quench");
        lookup.put(5, "Redirect");
        lookup.put(8, "Echo Request");
        lookup.put(11, "Time Exceeded");
        lookup.put(12, "Parameter Problem");
        lookup.put(13, "Timestamp");
        lookup.put(14, "Timestamp Reply");
        lookup.put(15, "Information Request");
        lookup.put(16, "Information Reply");

        String ICMP_type = popStringFromHexdump(hexString, 2);

        int typeNumber = Integer.parseInt(ICMP_type, 16);
        System.out.printf("ICMP:   Type = %d (%s)\n", typeNumber,
                lookup.get(typeNumber));

    }

    /**
     * Method to print Port
     *
     * @param hexString StringBuilder object containing the hexdump
     * @param type      String stating if type is Destination or Source
     * @param protocol  String stating if protocol is UDP or TCP
     */
    private static void print_Port(StringBuilder hexString, String type, String protocol) {

        String protocol_port = popStringFromHexdump(hexString, 4);

        System.out.printf("%s:  %s port = %d\n", protocol, type, Integer.parseInt(protocol_port, 16));

    }


    /**
     * Print the Data Content
     *
     * @param hexString StringBuilder object containing the hexdump
     * @param protocol  String stating if protocol is UDP or TCP
     */
    private static void print_Data(StringBuilder hexString, String protocol) {

        int payload;
        if (hexString.length() / 2 > 64) {
            System.out.printf("%s:  Data: (first 64 bytes) \n", protocol);
            payload = 64;
        } else {
            payload = hexString.length() / 2;
            System.out.printf("%s:  Data: (%d bytes) \n", protocol, payload);

        }


        for (int i = 0; i < payload; i += 16) {
            String data = popStringFromHexdump(hexString, 32);

            System.out.printf("%s:  ", protocol);

            int counter = 0;
            while (counter <= data.length()) {

                try {
                    System.out.printf("%s ", data.substring(counter, counter + 4));
                } catch (StringIndexOutOfBoundsException e) {
                    System.out.printf("%s ", data.substring(counter, data.length()));

                }
                counter += 4;
            }

            System.out.print("\t\t\"");
            printHexToASCII(data);
            System.out.println("\"");
        }

    }


    /**
     * Prints the Checksum
     *
     * @param hexString StringBuilder object containing the hexdump
     * @param protocol  String stating if protocol is UDP or TCP
     */
    private static void print_Checksum(StringBuilder hexString, String protocol) {

        String checksum = popStringFromHexdump(hexString, 4);

        String spaces = "";
        switch (protocol) {
            case "IP":
            case "ICMP":
                spaces = "   ";
                break;

            case "TCP":
            case "UDP":
                spaces = "  ";
                break;

        }
        System.out.printf("%s:%sChecksum = %s\n", protocol, spaces, checksum);

    }

    /**
     * Method to convert Hexadecimal string to binary string
     *
     * @param hex Hexadecimal String
     * @return Binary Equivalent
     */
    private static String convertHexToBinary(String hex) {

        HashMap<Character, String> converter = new HashMap<>();

        converter.put('0', "0000");
        converter.put('1', "0001");
        converter.put('2', "0010");
        converter.put('3', "0011");
        converter.put('4', "0100");
        converter.put('5', "0101");
        converter.put('6', "0110");
        converter.put('7', "0111");
        converter.put('8', "1000");
        converter.put('9', "1001");
        converter.put('a', "1010");
        converter.put('b', "1011");
        converter.put('c', "1100");
        converter.put('d', "1101");
        converter.put('e', "1110");
        converter.put('f', "1111");

        String binary = "";

        for (int i = 0; i < hex.length(); i++) {
            binary += converter.get(hex.charAt(i));
        }

        return binary;

    }

    /**
     * Method to pop the string from hexdump
     *
     * @param hexString StringBuilder object containing the hexdump
     * @param size      Number of characters to be removed
     * @return String containing first 'size' characters from the hexdump
     */
    private static String popStringFromHexdump(StringBuilder hexString, int size) {

        char[] charArray = new char[size];
        try {

            hexString.getChars(0, charArray.length, charArray, 0);
            hexString.delete(0, charArray.length);
        } catch (StringIndexOutOfBoundsException e) {
            charArray = new char[hexString.length()];
            hexString.getChars(0, hexString.length(), charArray, 0);
            hexString.delete(0, hexString.length());

        }

        String string = "";
        for (char ch : charArray) {
            string += ch;
        }
        return string;

    }

    /**
     * Method to  print ASCII data
     *
     * @param data Hexadecimal data
     */
    private static void printHexToASCII(String data) {


        for (int i = 0; i < data.length(); i += 2) {

            String hex = "" + data.charAt(i) + data.charAt(i + 1);
            Character ch = '.';
            try {
                ch = (char) Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                return;
            }

            if (ch <= 31 || ch >= 127)
                ch = '.';

            System.out.print(ch);
        }

    }

}

