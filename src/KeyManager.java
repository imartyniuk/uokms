import javax.crypto.KeyGenerator;
import java.util.logging.Logger;

public class KeyManager {

    private static Logger LOG = Logger.getLogger(KeyManager.class.getName());
    private static int bitSize = 128;

    public static void main(String[] args) {
        if (args.length == 1) {
            bitSize = Integer.parseInt(args[0]);
            LOG.info(String.format("Using custom bit size: %d", bitSize));
        } else {
            LOG.info(String.format("Using standard bit size %d", bitSize));
        }

        
    }
}
