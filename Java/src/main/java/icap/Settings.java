package icap;

import lombok.ToString;

@ToString
public class Settings {

    protected String host;
    protected int port;

    protected boolean respModSupport = false;
    protected boolean reqModSupport = false;
    protected boolean previewSupport = false;
    protected boolean notModifiedSupport = false;

    protected String icapService;
}