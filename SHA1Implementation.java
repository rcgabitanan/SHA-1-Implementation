import java.util.Scanner;

public class SHA1Implementation {
    // Constants used in SHA-1 algorithm
    private static final int H0 = 0x67452301;
    private static final int H1 = 0xEFCDAB89;
    private static final int H2 = 0x98BADCFE;
    private static final int H3 = 0x10325476;
    private static final int H4 = 0xC3D2E1F0;

    public static void main(String[] args) {
        String s;
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter the string you want to be hashed: ");
        s = scan.nextLine();

        String input = s;
        String hash = sha1(input);
        System.out.println("SHA-1 hash of \"" + input + "\": " + hash);
    }

    public static String sha1(String message) {
        byte[] messageBytes = message.getBytes();
        int messageLenBytes = messageBytes.length;
        int numBlocks = ((messageLenBytes + 8) >>> 6) + 1;
        int totalLen = numBlocks << 6;
        byte[] paddedMessage = new byte[totalLen];
        System.arraycopy(messageBytes, 0, paddedMessage, 0, messageLenBytes);
        
        // Padding the message
        paddedMessage[messageLenBytes] = (byte) 0x80;
        long messageLenBits = (long) messageLenBytes << 3;
        for (int i = 0; i < 8; i++) {
            paddedMessage[totalLen - 1 - i] = (byte) ((messageLenBits >>> (8 * i)) & 0xFF);
        }

        int[] H = {H0, H1, H2, H3, H4};
        int[] W = new int[80];

        for (int i = 0; i < numBlocks; i++) {
            int offset = i << 6;
            for (int j = 0; j < 16; j++) {
                W[j] = ((paddedMessage[offset + (j << 2)] & 0xFF) << 24)
                     | ((paddedMessage[offset + (j << 2) + 1] & 0xFF) << 16)
                     | ((paddedMessage[offset + (j << 2) + 2] & 0xFF) << 8)
                     | (paddedMessage[offset + (j << 2) + 3] & 0xFF);
            }

            for (int j = 16; j < 80; j++) {
                W[j] = leftRotate(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1);
            }

            int a = H[0];
            int b = H[1];
            int c = H[2];
            int d = H[3];
            int e = H[4];

            for (int j = 0; j < 80; j++) {
                int f, k;
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (j < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (j < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                int temp = leftRotate(a, 5) + f + e + k + W[j];
                e = d;
                d = c;
                c = leftRotate(b, 30);
                b = a;
                a = temp;
            }

            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
        }

        return String.format("%08x%08x%08x%08x%08x", H[0], H[1], H[2], H[3], H[4]);
    }

    private static int leftRotate(int value, int bits) {
        return (value << bits) | (value >>> (32 - bits));
    }
}
