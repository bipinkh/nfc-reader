package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static String ApplicationTag = "BpAl";
    private static String ApplicationVersion = "v1.0";
    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;

    private static String infoToShow = ""; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        /**
         *
            byte[] existingData = new byte[16];
            res = utils.writePages(existingData, 0, 6, 4);
            if (res) {
                infoToShow = "Read & Write commands to page 6.";
            } else {
                infoToShow = "Failed to read and write";
            }
         */
        infoToShow = "Issue method words.";

        //todo: use key diversification
        //todo: change the key

        // step 1: read from page 26 to 41
        byte[] message = new byte[64];
        res = utils.readPages(26, 16, message, 0);
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        /*
        byte 56 - 59 are lock bits.
        byte 60 - 63 are counter
         */
        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String uid = bytesToStr( Arrays.copyOfRange(message, 4, 8) );
        String version = bytesToStr( Arrays.copyOfRange(message, 8, 12) );
        Integer counterState = strToInt( bytesToStr( Arrays.copyOfRange(message, 12, 16) ) );
        Integer ticketCount = strToInt( bytesToStr( Arrays.copyOfRange(message, 16, 20) ) );
        Integer validFor = strToInt( bytesToStr( Arrays.copyOfRange(message, 20, 24) ) );
        String mac = bytesToStr( Arrays.copyOfRange(message, 24, 28) ); // first 4 byte
        String firstUse = bytesToStr( Arrays.copyOfRange(message, 28, 32) );
        String lastUse = bytesToStr( Arrays.copyOfRange(message, 32, 36) );
        String logs = bytesToStr( Arrays.copyOfRange(message, 36, 56) );
        Integer counter = strToInt( bytesToStr(Arrays.copyOfRange(message, 60, 64)) );

        boolean issueNewTicket = false;

        System.out.println("Received >>");
        log(message);
        System.out.println(" ------------- ");
        System.out.println(version);


        // step 2: check app tag
        if ( appTag.isEmpty()){
            issueNewTicket = true;
        }else if ( !appTag.equals(ApplicationTag)){
            infoToShow = "Invalid App tag";
            return false;
        }

        // step 3: check the version
        if ( !issueNewTicket && !version.equals(ApplicationVersion)){
            infoToShow = "Invalid version. Current version = "+ApplicationVersion;
            return false;
        }

        // step 4 check if there is UID.  if there isn't it's a blank card, ready to be formatted
        if (uid.isEmpty()){
            uid = UUID.randomUUID().toString().substring(0,4);
            issueNewTicket = true;
        }

        // todo: step 4.2 if not blank and MAC unmatches: abort

        // step 4.3 if not blank and MAC matches: check ticket is expired or not
        long currentTime = new Date().getTime();
        long validityDuration = 1000 * 86400 * validFor;
        Long firstUseTimestamp = isValidTime(firstUse);
        if ( !issueNewTicket && (
                firstUse.isEmpty()
                        && firstUseTimestamp != null
                        && currentTime < (firstUseTimestamp + validityDuration)
                && ( ticketCount+counter >= counter )
        )){
            issueNewTicket = false;
            // step 4.3.1 if not expired: add ticket and increase validity time for
                // a. increase the ticket count
                ticketCount += uses;
                System.arraycopy(toBytes(ticketCount), 0, message, 16, 4);
                // b. increase the validity for
                validFor += daysValid;
                System.arraycopy(toBytes(validFor), 0, message, 20, 4);

                //todo: c. recompute the mac

                // d. push
            log(message);

            res = utils.writePages(message, 0, 26, 16);
            if (res) {
                infoToShow = uses + " tickets added.";
            } else {
                System.out.println( message );
                infoToShow = "Failed to update tickets.";
            }

        }else{
            // step 4.3.2 if expired: issue new tickets with new validity
            issueNewTicket = true;
        }


        if (issueNewTicket){
            // Issuing new ticket
            // a. update the static data
            System.arraycopy( ApplicationTag.getBytes() , 0, message, 0, 4); // APP TAG
            System.arraycopy( ApplicationVersion.getBytes() , 0, message, 8, 4); // APP TAG
            System.arraycopy( uid.getBytes() , 0, message, 4, 4); // UID
            System.arraycopy( toBytes(counter), 0, message, 12, 4); // copying card counter to counter state of static memory
            System.arraycopy( toBytes(uses), 0, message, 16, 4); // ticket count
            System.arraycopy( toBytes(daysValid), 0, message, 20, 4); // valid for
            //todo: add mac

            // b. update the dynamic data
            System.arraycopy( new byte[4] , 0, message, 28, 4); // clear first use

            // d. write all the data
            log(message);

            res = utils.writePages(message, 0, 26, 14); // exclude the last 2 page for lock and counter
            if (res) {
                infoToShow = uses + " tickets issued.";
            } else {
                infoToShow = "Failed to issue tickets.";
            }

        }

        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        /*
        byte[] message = new byte[4];
        res = utils.readPages(6, 1, message, 0);
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }
        */
        infoToShow = "Validate method works";

        // step 1: read from page 6 to 19

        // step 2: check app tag

        // step 3: check the version

        // step 3.1 if app tag or version does not match, abort.

        // step 4 check if there is UID. if not, abort.

        // step 5: check MAC. if it doesn't match, abort.

        // step 6: check the number of tickets remaining using the CNTR and  counter in static data. If no ticekts, abort.

        // step 7: check the time. if expired, abot. or, if it is first use, first_use = blank
            // step 7.1: in case of first use, add first_use and last_use fields and increase CNTR
            // step 7.2: check the last_time used, if within 1 minute, validate but dont increase CNTR

        // step 8: update dynamic data ( last_used, logs)

        // todo: check if 2 WRITES can be merged to 1.

        // todo: use two dynamic data block for odd/even counter.

        return true;
    }

    private static void log(byte[] str){
        System.out.println(Arrays.toString(str));
        for (int i = 0; i < str.length / 4 ; i ++){
            byte[] bytes = Arrays.copyOfRange(str, i * 4, i * 4 + 4);
            System.out.println(Arrays.toString(  bytes) + " " + new String(bytes));
        }

    }

    private static Long isValidTime(String timestamp){
        long dv = strToInt(timestamp)*1000;// its need to be in milisecond
        Date df = new java.util.Date(dv);
        String vv = new SimpleDateFormat("yyyy-MM-dd").format(df);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        dateFormat.setLenient(false);
        try {
            dateFormat.parse(vv.trim());
        } catch (ParseException pe) {
            return null;
        }
        return dv;
    }

    private static Integer strToInt(String s){
        try {
            return Integer.parseInt(s);
        }catch (Exception ex){
            return 0;
        }
    }

    private static String bytesToStr(byte [] b) {
        String s = new String(b);
        char[] charArray = s.toCharArray();
        for(char c:charArray) {
            if(c=='.') continue;
            if (!Character.isLetterOrDigit(c))
                return "";
        }
        return s;
    }


    private static byte[] toBytes(int i)
    {
        byte[] result = new byte[4];
        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i /*>> 0*/);
        return result;
    }

}