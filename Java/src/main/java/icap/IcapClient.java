package icap;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: handle situations when server does not supports 204.
// TODO: SSL
// TODO: Authorization
// TODO: From (HTTP/1.1)
// TODO: Referer (HTTP/1.1)
/**
 * ICAP client library. Supports:
 *  - REQMOD
 *  - RESPMOD
 *  - Preview
 *  - 204 (Not Modified)
 */
public class IcapClient {

    private static final Charset StandardCharsetsUTF8 = Charset.forName("UTF-8");

    private Settings settings;

    private Socket client = null;
    private DataOutputStream out;
    private DataInputStream in;

    private final String VERSION   = "1.0";
    private final String USERAGENT = "Imicap connector/1.1";
    private final String ICAPTERMINATOR = "\r\n\r\n";
    private final String HTTPTERMINATOR = "0\r\n\r\n";

    private int stdPreviewSize;
    private final int stdRecieveLength = 8192;
    private final int stdSendLength = 8192;
    private final int SOCKET_TIMEOUT = 1000;

    private String tempString;

    private Logger logger = LoggerFactory.getLogger("icap.Client");

    enum ServerResponse {
        CONTINUE,
        OK,
        CHECK_FAILED,
        SERVICE_NOT_FOUND,
        SERVER_ERROR
    }

    /**
     * Initializes the socket connection and IO streams. It asks the server for the available options and
     * changes settings to match it.
     * @param port The port in the host to use.
     * @param icapService The service to use (fx "avscan").
     * @throws IOException
     * @throws IcapException
     */
    public IcapClient(String host, int port, String icapService) throws IOException, IcapException {
        settings = new Settings();
        settings.icapService = icapService;
        settings.host = host;
        settings.port = port;
        connect();
        Response responseMap = getOptions();
        switch (responseMap.statusCode){
            case 200: {
                // read server feature support
                try {
                    tempString = responseMap.get("Methods");        // https://tools.ietf.org/html/rfc3507#section-4.10.2
                    if(tempString.contains("RESPMOD")){
                        settings.respModSupport = true;
                    }
                    if(tempString.contains("REQMOD")){
                        settings.reqModSupport = true;
                    }
                } catch (NullPointerException e){
                    throw new IcapException("Could not read server methods support");
                }
                tempString = responseMap.get("Allow");              // https://tools.ietf.org/html/rfc3507#section-4.6
                if (tempString != null && tempString.contains("204")){
                    settings.notModifiedSupport = true;
                }
                tempString = responseMap.get("Preview");
                if (tempString != null){
                    settings.previewSupport = true;
                    stdPreviewSize=Integer.parseInt(tempString);
                }
                break;

            }
            case 404: throw new ServiceNotFoundException("No such service!");
            default: throw new IcapException("Non-200 status code from server: " + responseMap.statusCode);
        }
    }

    public IcapClient(Settings settings) throws IcapException, IOException {
        this.settings = settings;
        logger.debug("Got settings: {}", settings);
        connect();
    }

    public Settings getSettings() {
        return settings;
    }

    private void connect() throws IOException, IcapException {
        client = new Socket();
        client.connect(new InetSocketAddress(settings.host, settings.port), SOCKET_TIMEOUT);
        out = new DataOutputStream(client.getOutputStream());
        in = new DataInputStream(client.getInputStream());
        logger.debug("Connection to server established.");
    }

    // TODO move to some better HTTP client implementation
    private class Headers {
        private StringBuilder headers;
        public Headers(String initialString){
            headers = new StringBuilder();
            headers.append(initialString).append("\r\n");
        }
        public void addDate(ZonedDateTime dateTime){
            add("Date", dateTime.format(DateTimeFormatter.RFC_1123_DATE_TIME));
        }
        public void add(String header, String value){
            headers.append(header).append(": ").append(value).append("\r\n");
        }
        public void addIcapHeaders(String host, String userAgent, int previewSize){
            add("Host", host);
            add("User-Agent", userAgent);
            if(settings.notModifiedSupport){
                add("Allow", "204");
            }
            if(settings.previewSupport){
                add("Preview", ""+previewSize);
            }    
        }
        public String toString(){
            return headers.toString() + "\r\n";
        }
    }

    /**
     * Send to server RESPMOD and HTTP response (200 OK)
     * !!! This method doesn't send the file itself !!!
     */
    private void respMod(int previewSize, String filetype, long fileSize) throws IOException{
        Headers httpHeaders = new Headers("HTTP/1.1 200 OK");
        httpHeaders.addDate(ZonedDateTime.now());
        httpHeaders.add("Content-Length", Long.toString(fileSize));
        httpHeaders.add("Content-Type", filetype);
        String httpResponse = httpHeaders.toString();
        Headers icapHeaders = new Headers(
            "RESPMOD icap://"+settings.host+"/"+settings.icapService+" ICAP/"+VERSION
        );
        icapHeaders.addIcapHeaders(settings.host, USERAGENT, previewSize);
        icapHeaders.add("Encapsulated", "res-hdr=0, res-body="+ httpResponse.length());
        String rawHeaders = icapHeaders.toString();
        logger.trace("Send request: \n{}\n{}", rawHeaders, httpResponse);
        sendString(rawHeaders);
        sendString(httpResponse);
    }

    /**
     * Send to server REQMOD and HTTP POST
     * !!! This method doesn't send the file itself !!!
     */
    private void reqMod(int previewSize, String url, String filetype, long fileSize) throws IOException{
        Headers httpHeaders = new Headers("POST "+ url +" HTTP/1.1");
        httpHeaders.addDate(ZonedDateTime.now());
        httpHeaders.add("User-Agent", USERAGENT);
        httpHeaders.add("Content-Length", Long.toString(fileSize));
        httpHeaders.add("Content-Type", filetype);
        String httpResponse = httpHeaders.toString();
        Headers icapHeaders = new Headers(
            "REQMOD icap://"+settings.host+"/"+settings.icapService+" ICAP/"+VERSION
        );
        icapHeaders.addIcapHeaders(settings.host, USERAGENT, previewSize);
        icapHeaders.add("Encapsulated", "req-hdr=0, req-body="+ httpResponse.length());
        sendString(icapHeaders.toString());
        sendString(httpResponse);
    }

    /**
     * Given a filepath, it will send:
     *  - RESPMOD with HTTP response with file in body
     *  - or REQMOD with HTTP POST with file in body, if server doesn't support RESPMOD
     * And returns result of check.
     * @param filename Relative or absolute filepath to a file.
     * @return Returns true when server responded back code 204 (or 200 with unmdified message).
     */
    public boolean scanFile(String filename) throws IOException,IcapException {

        try(FileInputStream fileInStream = new FileInputStream(filename)) {
            long fileSize = fileInStream.available();

            int previewSize = stdPreviewSize;
            if (fileSize < stdPreviewSize || !settings.previewSupport){
                previewSize = (int)fileSize;
            }
            
            if(settings.respModSupport){
                respMod(previewSize,
                    Files.probeContentType(new File(filename).toPath()), 
                    fileSize);
            } else if(settings.reqModSupport){
                reqMod(
                    previewSize, "/"+settings.icapService, 
                    Files.probeContentType(new File(filename).toPath()), 
                    fileSize);
            }

            // Sending preview or, if smaller than previewSize, the whole file.
            byte[] chunk = new byte[previewSize];
            fileInStream.read(chunk);
            // Chunked transfer encoding - add block length in hex before block
            sendHttpChunk(chunk);
            if (fileSize<=previewSize){
                sendString("0; ieof\r\n\r\n");
            }
            else if (previewSize != 0){
                sendString(HTTPTERMINATOR);
            }

            

            if(fileSize>previewSize) {
                if(settings.previewSupport){
                    // Parse the response! It might not be "100 continue"
                    // if fileSize<previewSize, then this is acutally the respond
                    // otherwise it is a "go" for the rest of the file.
                    switch(getCheckResponse()) {
                        case CONTINUE: break;
                        case OK: return true;
                        case CHECK_FAILED: return false;
                        default: return false;
                    }
                }

                //Sending remaining part of file
                byte[] buffer = new byte[stdSendLength];
                while ((fileInStream.read(buffer)) != -1) {
                    sendHttpChunk(buffer);
                }
                //Closing file transfer.
                sendString(HTTPTERMINATOR);
            }
        }
        switch (getCheckResponse()) {
            case OK: return true;
            case CHECK_FAILED: return false;
            default: return false;
        }
    }


    /**
     * Read ICAP server response and say by response code is file OK or not.
     */
    private ServerResponse getCheckResponse() throws IOException, IcapException {
        String response = getHeader(ICAPTERMINATOR);
        Response responseMap = parseHeader(response);
        int status = responseMap.statusCode;
        switch (status){
            case 100: return ServerResponse.CONTINUE;
            case 204: return ServerResponse.OK;
            case 403: return ServerResponse.CHECK_FAILED;
            case 200: {
                // TODO check for servers without not modified support
                logger.debug("Response code 200, file marked as rejected");
                return ServerResponse.CHECK_FAILED;
            }
            default: {
                logger.warn("ICAP unhandled response code: {}", status);
                return ServerResponse.CHECK_FAILED;
            }
        }
    }


    /**
     * Automatically asks for the servers available options and returns the raw response as a String.
     * @return String of the servers response.
     * @throws IOException
     * @throws IcapException
     */
    private Response getOptions() throws IOException, IcapException {
        //Send OPTIONS header and receive response
        //Sending and recieving
        String requestHeader =
                "OPTIONS icap://"+settings.host+"/"+settings.icapService+" ICAP/"+VERSION+"\r\n"
                        + "Host: "+settings.host+"\r\n"
                        + "User-Agent: "+USERAGENT+"\r\n"
                        + "Encapsulated: null-body=0\r\n"
                        + "\r\n";

        logger.trace("send OPTIONS request: \n{}", requestHeader);
        sendString(requestHeader);
        String rawResponse = getHeader(ICAPTERMINATOR);
        logger.trace("got OPTIONS response: \n{}", rawResponse);

        return parseHeader(rawResponse);
    }

    /**
     * Receive an expected ICAP header as response of a request. The returned String should be parsed with parseHeader()
     * @param terminator
     * @return String of the raw response
     * @throws IOException
     * @throws IcapException
     */
    private String getHeader(String terminator) throws IOException, IcapException {
        byte[] endofheader = terminator.getBytes(StandardCharsetsUTF8);
        byte[] buffer = new byte[stdRecieveLength];

        int n;
        int offset=0;
        //stdRecieveLength-offset is replaced by '1' to not receive the next (HTTP) header.
        while((offset < stdRecieveLength) && ((n = in.read(buffer, offset, 1)) != -1)) { // first part is to secure against DOS
            offset += n;
            if (offset>endofheader.length+13){ // 13 is the smallest possible message "ICAP/1.0 xxx "
                byte[] lastBytes = Arrays.copyOfRange(buffer, offset-endofheader.length, offset);
                if (Arrays.equals(endofheader,lastBytes)){
                    return new String(buffer,0,offset, StandardCharsetsUTF8);
                }
            }
        }
        throw new IcapException("Error in getHeader() method");
    }

    private class Response extends HashMap<String, String> {
        public int statusCode;
        public Response(int statusCode) {
            this.statusCode = statusCode;
        }
    }

    /**
     * Given a raw response header as a String, it will parse through it and return a HashMap of the result
     * @param response A raw response header as a String.
     * @return HashMap of the key,value pairs of the response
     */
    private Response parseHeader(String response) throws IcapException {
        /****SAMPLE:****
         * ICAP/1.0 204 Unmodified
         * Server: C-ICAP/0.1.6
         * Connection: keep-alive
         * ISTag: CI0001-000-0978-6918203
         */
        // The status code is located between the first 2 whitespaces.
        // Read status code
        int x = response.indexOf(" ",0);
        int y = response.indexOf(" ",x+1);
        String statusCode = response.substring(x+1,y);
        Response headers = null;
        try {
            headers = new Response(Integer.parseInt(statusCode));
        } catch (NumberFormatException e) {
            throw new IcapException("Failed to parse status code in response");
        }

        // Each line in the sample is ended with "\r\n".
        // When (i+2==response.length()) The end of the header have been reached.
        // The +=2 is added to skip the "\r\n".
        // Read headers
        int i = response.indexOf("\r\n",y);
        i+=2;
        while (i+2!=response.length() && response.substring(i).contains(":")) {

            int n = response.indexOf(":",i);
            String key = response.substring(i, n);

            n += 2;
            i = response.indexOf("\r\n",n);
            String value = response.substring(n, i);

            headers.put(key, value);
            i+=2;
        }
        return headers;
    }

    /**
     * Sends data chunk prior to HTTP/1.1 Chunked Transfer encoding.
     * @param chunk part of data that needs to be send
     * @throws IOException
     */
    private void sendHttpChunk(byte[] chunk) throws IOException {
        // add block length in hex before block
        sendString(Integer.toHexString(chunk.length) +"\r\n");
        sendBytes(chunk);
        sendString("\r\n");
        out.flush();
    }

    /**
     * Sends a String through the socket connection. Used for sending ICAP/HTTP headers.
     * @param requestHeader
     * @throws IOException
     */
    private void sendString(String requestHeader) throws IOException{
        sendBytes(requestHeader.getBytes(StandardCharsetsUTF8));
    }

    /**
     * Sends bytes of data from a byte-array through the socket connection. Used to send filedata.
     * @param chunk The byte-array to send.
     * @throws IOException
     */
    private void sendBytes(byte[] chunk) throws IOException {
        out.write(chunk);
    }

    /**
     * Terminates the socket connecting to the ICAP server.
     * @throws IOException
     */
    private void disconnect() throws IOException {
        if(client != null) {
            client.close();
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            disconnect();
        } finally {
            super.finalize();
        }
    }

}
