package icap;

/**
 * Exception that occurs if requested ICAP service not found.
 */
public class ServiceNotFoundException extends IcapException {
    public ServiceNotFoundException(String message) {
        super(message);
    }
}
