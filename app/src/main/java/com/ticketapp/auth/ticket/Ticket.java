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
        String appTag = new String( Arrays.copyOfRange(message, 0, 4) );
        String uid = new String( Arrays.copyOfRange(message, 4, 8) );
        String version = new String( Arrays.copyOfRange(message, 8, 12) );
        Integer counterState = Integer.parseInt( new String( Arrays.copyOfRange(message, 12, 16) ) );
        Integer ticketCount = Integer.parseInt( new String( Arrays.copyOfRange(message, 16, 20) ) );
        Integer validFor = Integer.parseInt( new String( Arrays.copyOfRange(message, 20, 24) ) );
        String mac = new String( Arrays.copyOfRange(message, 24, 28) ); // first 4 byte
        String firstUse = new String( Arrays.copyOfRange(message, 28, 32) );
        String lastUse = new String( Arrays.copyOfRange(message, 32, 36) );
        String logs = new String( Arrays.copyOfRange(message, 36, 56) );
        Integer counter = Integer.parseInt( new String(Arrays.copyOfRange(message, 60, 64)) );

        // step 2: check app tag
        if ( !appTag.equals(ApplicationTag)){
            infoToShow = "Invalid App tag";
            return false;
        }

        // step 3: check the version
        if ( !version.equals(ApplicationVersion)){
            infoToShow = "Invalid version. Current version = "+ApplicationVersion;
            return false;
        }

        boolean issueNewTicket = false;
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

        }else{
            // step 4.3.2 if expired: issue new tickets with new validity
            issueNewTicket = true;
        }


        if (issueNewTicket){
            // Issuing new ticket
            // a. update the static data
            // b. update the dynamic data
            // b.1 replace or clear the first_use field
            // c. calculate mac for static data
            // d. write all the data
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


    private static Long isValidTime(String timestamp){
        long dv = Long.valueOf(timestamp)*1000;// its need to be in milisecond
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

}