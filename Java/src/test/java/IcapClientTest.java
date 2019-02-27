
import org.junit.Test;

import icap.IcapClient;

import static org.junit.Assert.*;

/**
 * Created by user on 14.09.2017.
 */
public class IcapClientTest {

    @Test
    public void scanFile() throws Exception {
        IcapClient icapClient = new IcapClient("192.168.45.219", 1344, "avscan");
        
        boolean result = icapClient.scanFile("/bin/ls");
        assertTrue(result);
    }
}