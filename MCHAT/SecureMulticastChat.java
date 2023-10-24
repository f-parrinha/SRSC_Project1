
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class SecureMulticastChat extends Thread {

    // TODO - (version || CHAT_MAGIC_NUMBER || HASHED_USERNAME) || (NONCE || DATA) || HMACkey(mensagem anterior)



    // Definition of opcode for JOIN type
    public static final int JOIN = 1;

    // Definition of opcode for LEAVE type
    public static final int LEAVE = 2;

    // Definition of opcode for a regular message type (sent/received)
    public static final int MESSAGE = 3;

    // Definition of a MAGIC NUMBER (as a global identifier) for the CHAT
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

    // Timeout for sockets
    public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

    // Multicast socket used to send and receive multicast protocol PDUs
    protected MulticastSocket msocket;

    // Username / User-Nick-Name in Chat
    protected String username;

    // Grupo IP Multicast used
    protected InetAddress group;

    // Listener for Multicast events that must be processed
    protected MulticastChatEventListener listener;

    // Control  - execution thread

    protected boolean isActive;

    protected CipherService cipherService;

    // Multicast Chat-Messaging
    public SecureMulticastChat(String username, InetAddress group, int port,
                         int ttl, MulticastChatEventListener listener) throws IOException {

        this.username = username;
        this.group = group;
        this.listener = listener;
        isActive = true;

        // create & configure multicast socket

        msocket = new MulticastSocket(port);
        msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
        msocket.setTimeToLive(ttl);
        msocket.joinGroup(group);

        // start receive thread and send multicast join message
        start();
        sendJoin();

        cipherService = new CipherService();
    }

    /**
     * Sent notification when user wants to leave the Chat-messaging room
     */

    public void terminate() throws IOException {
        isActive = false;
        sendLeave();
    }

    // to process error message
    protected void error(String message) {
        System.err.println(new java.util.Date() + ": MulticastChat: "
                + message);
    }

    // Send a JOIN message
    //
    protected void sendJoin() throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(JOIN);
        dataStream.writeUTF(username);
        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }

    // Process recived JOIN message
    //
    protected void processJoin(DataInputStream istream, InetAddress address,
                               int port) throws IOException {
        String name = istream.readUTF();

        try {
            listener.chatParticipantJoined(name, address, port);
        } catch (Throwable e) {}
    }

    // Send LEAVE
    protected void sendLeave() throws IOException {

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(LEAVE);
        dataStream.writeUTF(username);
        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }

    // Processes a multicast chat LEAVE and notifies listeners

    protected void processLeave(DataInputStream istream, InetAddress address,
                                int port) throws IOException {
        String username = istream.readUTF();

        try {
            listener.chatParticipantLeft(username, address, port);
        } catch (Throwable e) {}
    }

    // Send message to the chat-messaging room
    //
    public void sendMessage(String message) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(MESSAGE);
        dataStream.writeUTF(username);
        dataStream.writeUTF(message);
        dataStream.close();

        byte[] data = cipherService.createMessage(CHAT_MAGIC_NUMBER, username, byteStream.toString());

        DatagramPacket packet = new DatagramPacket(data, data.length, group,
                msocket.getLocalPort());
        msocket.send(packet);
    }


    // Process a received message  //
    //
    protected void processMessage(DataInputStream istream,
                                  InetAddress address,
                                  int port) throws IOException {
        String username = istream.readUTF();
        String message = istream.readUTF();

        try {
            listener.chatMessageReceived(username, address, port, message);
        } catch (Throwable e) {}
    }

    // Loop:
    // reception and demux received datagrams to process,
    // according with message types and opcodes
    //
    public void run() {
        byte[] buffer = new byte[65508];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        while (isActive) {
            try {

                // Set buffer to receive UDP packet
                packet.setLength(buffer.length);
                msocket.receive(packet);

                // Read received datagram

                DataInputStream istream =
                        new DataInputStream(new ByteArrayInputStream(packet.getData(),
                                packet.getOffset(), packet.getLength()));

                long magic = istream.readLong();

                // Only accepts CHAT-MAGIC-NUMBER of the Chat
                if (magic != CHAT_MAGIC_NUMBER) {
                    continue;

                }

                // Let's analyze the received payload and msg types in rceoved datagram
                int opCode = istream.readInt();
                switch (opCode) {
                    case JOIN:
                        processJoin(istream, packet.getAddress(), packet.getPort());
                        break;
                    case LEAVE:
                        processLeave(istream, packet.getAddress(), packet.getPort());
                        break;
                    case MESSAGE:
                        processMessage(istream, packet.getAddress(), packet.getPort());
                        break;
                    default:
                        error("rror; Unknown type " + opCode + " sent from  "
                                + packet.getAddress() + ":" + packet.getPort());
                }

            } catch (InterruptedIOException e) {

                /**
                 * Handler for Interruptions ...
                 * WILL DO NOTHING ,,,
                 * Used for debugging / control if wanted ... to notify the loop interruption
                 */

            } catch (Throwable e) {
                error("Processing error: " + e.getClass().getName() + ": "
                        + e.getMessage());
            }
        }

        try {
            msocket.close();
        } catch (Throwable e) {}
    }
}