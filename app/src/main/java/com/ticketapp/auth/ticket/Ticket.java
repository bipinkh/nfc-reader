package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

/**
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] ourAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key_our).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();
    private static final byte[] ourHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key_our).getBytes();

    private static final byte[] authenticationKey = ourAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = ourHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static String ApplicationTag = "BpAl";
    private static String ApplicationVersion = "v1.0";
    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;
    private final int secondUseTime = 1; // time in seconds to wait before 2nd use

    private static final byte[] counterIncrementBy1 = {1,0,0,0};
    private static final byte[] empty4Bytes = {0,0,0,0};

    private static String infoToShow = ""; // Use this to show messages
    private static Boolean formatCard = false;

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


    public boolean authenticateKeys(){
        // first, try to authenticate with our key
        boolean res = utils.authenticate(authenticationKey);
        if (res) return true;
        // if authenticating with our key fails, authenticate with default key
        res = utils.authenticate(defaultAuthenticationKey);
        if (!res) {
            // if authenticating with default key also fails, then abort
            Utilities.log("Authentication failed in format()", true);
            return false;
        }
        // if authenticating with default key works, change the authentication key to ours
        res = utils.writePages(authenticationKey, 0, 44, 4);
        if (res) {
            Utilities.log("Keys updated", false);
            return true;
        } else {
            Utilities.log("Failed to update keys", true);
            return false;
        }
    }


    /**
     * Function to format the card. Used during debugging when we had to reset all the data fields.
     * Can also be used when the card format functionality is added to the card later.
     */
    private void formatCard(){
        boolean res = utils.writePages(new byte[64], 0, 26, 14);
        if (res) {
            infoToShow = "Formatted the card";
        } else {
            infoToShow = "Fail to format card";
        }
    }


    /**
     * Issue new tickets
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        if (formatCard){
            formatCard();
            return true;
        }

        boolean res;

        // Authenticate
        if (!authenticateKeys()) return false;

        // step 1: read from page 26 to 41
        byte[] message = new byte[64];
        res = utils.readPages(26, 16, message, 0);
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String uid = bytesToStr( Arrays.copyOfRange(message, 4, 8) );
        String version = bytesToStr( Arrays.copyOfRange(message, 8, 12) );
        byte[] counterStateBytes = Arrays.copyOfRange(message, 12, 16);
        Integer counterState = bytesToInt( counterStateBytes );
        int ticketCount = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        int validFor = bytesToInt( Arrays.copyOfRange(message, 20, 24) );
        byte[] mac = Arrays.copyOfRange(message, 24, 28); // first 4 byte
        Date firstUse = bytesToDate( Arrays.copyOfRange(message, 28, 32) );
        //Date lastUse = bytesToDate( Arrays.copyOfRange(message, 32, 36) );
        //String logs = bytesToStr( Arrays.copyOfRange(message, 36, 56) );
        byte[] counterBytes = Arrays.copyOfRange(message, 60, 64);
        reverseByteArray(counterBytes);
        Integer counter = bytesToInt( counterBytes );

        boolean issueNewTicket = false;
        boolean checkMac = true;

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
            checkMac = false;
        }

        // key diversification
        macAlgorithm.setKey( generatehash(new String(ourHMACKey), uid) );

        byte[] staticData;
        byte[] newMac;

        // step 4.2 if not blank and MAC unmatches: abort
        if (checkMac){
            boolean emptyMac = true;
            for (byte b : mac) {
                if (b != 0) {
                    emptyMac = false;
                    break;
                }
            }
            if (emptyMac){
                infoToShow = "Empty MAC";
                return false;
            }
            staticData = Arrays.copyOfRange(message, 0, 24);
            byte[] computedMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
            if (!Arrays.equals(mac, computedMac)){
                infoToShow = "Wrong MAC";
                return false;
            }
        }


        // step 4.3 if not blank and MAC matches: check ticket is expired or not
        long validityDurationInSec =  86400L * validFor; // changing days to seconds

        if ( !issueNewTicket && firstUse == null){
            System.out.println("Adding new tickets because previous tickets aren't used.");
            // step 4.3.1 if not expired: add ticket and increase validity time for
            // a. increase the ticket count
            System.out.println("Ticket count before " + ticketCount);
            ticketCount += uses;
            System.out.println("Ticket count after " + ticketCount);
            System.arraycopy(toBytes(ticketCount), 0, message, 16, 4);
            // b. increase the validity for
            validFor += daysValid;
            System.arraycopy(toBytes(validFor), 0, message, 20, 4);

            //c. recompute the mac
            staticData = Arrays.copyOfRange(message, 0, 24);
            newMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
            System.arraycopy(newMac, 0, message, 24, 4);

            // d. push
            res = utils.writePages(message, 0, 26, 14);
            if (res) infoToShow = uses + " tickets added over "+ (ticketCount - uses) +" unused tickets.";
            else infoToShow = "Failed to update tickets.";
            return true;
        }

        if (
                !issueNewTicket
                && new Date(firstUse.getTime() + validityDurationInSec * 1000).after(new Date()) // expiry time is after current time
                && ( ticketCount+counterState >= counter ) // there is some tickets remaining
        ){
            System.out.println("Adding new tickets on top of non-expired tickets.");
            // step 4.3.1 if not expired: add ticket and increase validity time for
            // a. increase the ticket count
            ticketCount += uses;
            System.arraycopy(toBytes(ticketCount), 0, message, 16, 4);
            // b. increase the validity for
            validFor += daysValid;
            System.arraycopy(toBytes(validFor), 0, message, 20, 4);

            //c. recompute the mac
            staticData = Arrays.copyOfRange(message, 0, 24);
            newMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
            System.arraycopy(newMac, 0, message, 24, 4);

            // d. clear first use
            System.arraycopy( empty4Bytes , 0, message, 28, 4); // clear first use

            // e. push
            res = utils.writePages(message, 0, 26, 14);
            if (res) infoToShow = uses + " tickets added over "+ (ticketCount - uses) +" non-expired tickets.";
            else infoToShow = "Failed to update tickets.";
            return true;
        }

        // Issuing new ticket
        System.out.println("Issuing new tickets because previous tickets expired.");

        // a. update the static data
        System.arraycopy( ApplicationTag.getBytes() , 0, message, 0, 4); // APP TAG
        System.arraycopy( ApplicationVersion.getBytes() , 0, message, 8, 4); // APP version
        System.arraycopy( uid.getBytes() , 0, message, 4, 4); // UID
        System.arraycopy( counterBytes, 0, message, 12, 4); // copying card counter to counter state of static memory
        System.arraycopy( toBytes(uses), 0, message, 16, 4); // ticket count
        System.arraycopy( toBytes(daysValid), 0, message, 20, 4); // valid for
        // add mac
        staticData = Arrays.copyOfRange(message, 0, 24);
        newMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
        System.arraycopy(newMac, 0, message, 24, 4);

        // b. update the dynamic data
        System.arraycopy( empty4Bytes , 0, message, 28, 4); // clear first use
        System.arraycopy( empty4Bytes , 0, message, 32, 4); // clear last use

        // d. write all the data
        res = utils.writePages(message, 0, 26, 14); // exclude the last 2 page for lock and counter
        if (res) infoToShow = uses + " new tickets issued.";
        else infoToShow = "Failed to issue tickets.";
        return true;
    }


    /**
     * Use ticket once
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


        // step 1: read from page 26 to 41
        byte[] message = new byte[64];
        res = utils.readPages(26, 16, message, 0);
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        // starting from page 26
        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String uid = bytesToStr( Arrays.copyOfRange(message, 4, 8) );
        String version = bytesToStr( Arrays.copyOfRange(message, 8, 12) );
        Integer counterState = bytesToInt( Arrays.copyOfRange(message, 12, 16) );
        Integer ticketCount = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        Integer validFor = bytesToInt( Arrays.copyOfRange(message, 20, 24) );
        byte[] mac = Arrays.copyOfRange(message, 24, 28); // first 4 byte
        Date firstUse = bytesToDate( Arrays.copyOfRange(message, 28, 32) );
        Date lastUse = bytesToDate( Arrays.copyOfRange(message, 32, 36) );
        byte[] logs = Arrays.copyOfRange(message, 36, 56);
        byte[] counterBytes = Arrays.copyOfRange(message, 60, 64);
        reverseByteArray(counterBytes);
        Integer counter = bytesToInt( counterBytes );

        // step 2: check app tag
        if ( appTag.isEmpty() || !appTag.equals(ApplicationTag)){
            infoToShow = "Invalid App tag";
            return false;
        }

        // step 3: check the version
        if ( version.isEmpty() || !version.equals(ApplicationVersion)){
            infoToShow = "Invalid version. Current version = "+ApplicationVersion;
            return false;
        }

        // step 4 check if there is UID.  if there isn't it's a blank card, ready to be formatted
        if (uid.isEmpty()){
            infoToShow = "Empty UID";
            return false;
        }

        // key diversification
        macAlgorithm.setKey( generatehash(new String(ourHMACKey), uid) );

        // step 4.2 if not blank and MAC unmatches: abort
        byte[] staticData;
        boolean emptyMac = true;

        for (byte b : mac) {
            if (b != 0) {
                emptyMac = false;
                break;
            }
        }

        if (emptyMac){
            infoToShow = "Empty MAC";
            return false;
        }
        staticData = Arrays.copyOfRange(message, 0, 24);
        byte[] computedMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
        if (!Arrays.equals(mac, computedMac)){
            infoToShow = "Wrong MAC";
            return false;
        }

        // step 6: check the number of tickets remaining using the CNTR and  counter in static data. If no ticekts, abort.
        int remainingTickets = ticketCount - (counter - counterState);
        if ( remainingTickets <= 0){
            infoToShow = "No tickets";
            return false;
        }

        // step 7: check the time. if expired, abort. or, if it is first use, first_use = now
        // step 7.1: in case of first use, add first_use and last_use fields and increase CNTR
        // step 7.2: check the last_time used, if within 1 minute, validate but dont increase CNTR
        long validityDurationInMillis = 1000L * 86400L * validFor;
        long currentDateInMillis = System.currentTimeMillis();
        if (firstUse != null && new Date(firstUse.getTime() + validityDurationInMillis).before(new Date()) ){
            infoToShow = "Tickets expired timewise";
            return false;
        }else if (counterState.equals(counter)){ // "counter state == counter" means the first use
            firstUse = new Date(currentDateInMillis);
            lastUse = firstUse;
            System.arraycopy( toBytes(firstUse), 0, message, 28, 4); // first use
            System.arraycopy( toBytes(lastUse), 0, message, 32, 4); // last ue
            System.arraycopy( counterIncrementBy1, 0, message, 60, 4); // counter increment by 1
            res = utils.writePages(message, 0, 26, 16);
            //res = utils.writePages(counterIncrementBy1, 0, 41, 1);
            if (res) infoToShow = "Ticket validated (1st use). \n"+remainingTickets + " tickets remaining.\nExpires on: " + new Date( currentDateInMillis + validityDurationInMillis ) ;
            else infoToShow = "Failed to validate ticket.";
            return true;
        }else {
            // not the first use
            if ( lastUse != null && (currentDateInMillis- lastUse.getTime())/1000 < secondUseTime ){
                infoToShow = "Ticket validated less than " + secondUseTime + " seconds ago";
                return false;
            }else {
                lastUse = new Date(currentDateInMillis);
                if (firstUse == null){
                    firstUse = lastUse;
                    System.arraycopy( toBytes(firstUse), 0, message, 28, 4); // first use
                }
                System.arraycopy( toBytes(lastUse), 0, message, 32, 4); // last use
                System.arraycopy( ByteBuffer.allocate(4).putInt(1).array(), 0, message, 60, 4); // counter increment by 1
                // write logs: page 36 to 56
                System.arraycopy(logs, 12, logs, 16, 4 );
                System.arraycopy(logs, 8, logs, 12, 4 );
                System.arraycopy(logs, 4, logs, 8, 4 );
                System.arraycopy(logs, 0, logs, 4, 4 );
                System.arraycopy(toBytes(lastUse), 0, logs,0, 4 );
                System.arraycopy(logs, 0, message, 36, 20);
                System.arraycopy( counterIncrementBy1, 0, message, 60, 4); // counter increment by 1
                // write
                res = utils.writePages(message, 0, 26, 16);
                if (res) {
                    infoToShow = "Ticket validated. \n"+remainingTickets + " tickets remaining." +
                            "\nExpires on: " + new Date( firstUse.getTime() + validityDurationInMillis );
                } else infoToShow = "Failed to validate ticket.";
                return true;
            }
        }
    }

    private static Date bytesToDate(byte[] b){
        try {
            int bInt;
            if (b.length == 4){
                byte[] b8 = new byte[8];
                System.arraycopy(b, 0, b8, 4, 4);
                bInt = bytesToInt(b8);
            }else bInt = bytesToInt(b);
            if (bInt <= 0) return null;
            return new Date(bInt*1000L);
        }catch (Exception ex){
            return null;
        }
    }

    private static Integer bytesToInt(byte[] b){
        try {
            return new BigInteger( b ).intValue();
        }catch (Exception ex){
            return 0;
        }
    }

    public static void reverseByteArray(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
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


    public byte[] toBytes(Date d) {
        long l = d.getTime() / 1000; // converting to seconds
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(l);
        return Arrays.copyOfRange(buffer.array(), 4, buffer.array().length); // only the last 4 bytes
    }

    private static byte[] toBytes(int i) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(i);
        return buffer.array();
    }

    private static byte[] generatehash(String masterKey, String uid){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((masterKey+uid).getBytes());
            return Arrays.copyOfRange(hash,0,16);
        }catch (Exception ex){
            return null;
        }

    }

}