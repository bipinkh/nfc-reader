package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

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
    private final int waitingSecondsBetweenTwoTicketIssues = 5; // time in seconds to wait before 2nd use

    private static final byte[] counterIncrementBy1 = {1,0,0,0};
    private static final byte[] empty4Bytes = {0,0,0,0};

    private static String infoToShow = ""; // Use this to show messages
    private static Boolean formatCard = false;

    DateFormat dateFormatter = new SimpleDateFormat("yyyy-mm-dd hh:mm:ss");

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
            Utilities.log("Authentication failed", true);
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

        // read app tag
        byte[] uidBytes = new byte[8];
        String uid  = "";
        res = utils.readPages(0, 2, uidBytes, 0);
        if (res) uid = new String(Base64.getEncoder().encode(uidBytes));
        else {
            infoToShow = "Failed to read UID";
            return false;
        }

        // Authenticate
        if (!authenticateKeys()){
            infoToShow = "Authentication failed";
            return false;
        }

        // step 1: read from page 26 to 41  [26:39 user memory, 40: lock bytes, 41: counter]
        byte[] message = new byte[64];
        res = utils.readPages(26, 16, message, 0);
        if (res) infoToShow = "Read memory. Processing data. ";
        else {
            infoToShow = "Failed to read the memory";
            return false;
        }
        // convert the read bytes to meaningful data for processing
        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String version = bytesToStr( Arrays.copyOfRange(message, 8, 12) );
        byte[] counterStateBytes = Arrays.copyOfRange(message, 12, 16);
        Integer counterState = bytesToInt( counterStateBytes );
        int ticketCount = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        int validFor = bytesToInt( Arrays.copyOfRange(message, 20, 24) );
        byte[] mac = Arrays.copyOfRange(message, 24, 28); // first 4 byte
        Date firstUse = bytesToDate( Arrays.copyOfRange(message, 28, 32) );
        byte[] counterBytes = Arrays.copyOfRange(message, 60, 64);
        reverseByteArray(counterBytes);
        Integer counter = bytesToInt( counterBytes );

        // few variable to track the process
        boolean issueNewTicket = false;
        boolean checkMac = true;

        // step 2: check app tag
        if ( appTag.isEmpty()){
            issueNewTicket = true;
            checkMac = false;
        }else if ( !appTag.equals(ApplicationTag)){
            infoToShow = "Invalid App tag";
            return false;
        }

        // step 3: check the version
        if ( !issueNewTicket && !version.equals(ApplicationVersion)){
            infoToShow = "Invalid version. This app supports card formatted with app version " + ApplicationVersion;
            return false;
        }

        // key diversification
        macAlgorithm.setKey( generateDiversifiedKey(new String(ourHMACKey), uid) );

        byte[] staticData = Arrays.copyOfRange(message, 0, 24);
        byte[] newMac;

        // step 4.2 if not blank and MAC unmatches: abort
        if (checkMac){
            boolean emptyMac = true;
            for (byte b : mac) {
                if (b != 0) { // if at least one of the bytes in the mac is non-zero, then it's not empty.
                    emptyMac = false;
                    break;
                }
            }
            if (emptyMac){
                infoToShow = "Empty MAC";
                return false;
            }
            byte[] computedMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
            if (!Arrays.equals(mac, computedMac)){
                infoToShow = "Wrong MAC";
                return false;
            }
        }


        // step 4.3 if not blank and MAC matches: check ticket is expired or not
        long validityDurationInSec =  86400L * validFor; // changing days to seconds
        int previousRemainingTickets = Math.max(0, counterState + ticketCount - counter);
        boolean hasNonExpiredPreviousTickets = !issueNewTicket && firstUse == null; // if there is no first use at all for previously issued tickets
        if (!hasNonExpiredPreviousTickets){
            // if at least one of the previously issued tickets is used, there may be some non-expired tickets.
            hasNonExpiredPreviousTickets = !issueNewTicket && ( previousRemainingTickets > 0 )
                    && new Date(firstUse.getTime() + validityDurationInSec * 1000).after(new Date()); // expiry time is after current time
        }
        if (hasNonExpiredPreviousTickets){
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

            // e. push.
            /*
            since we changed pages
                P30 (16-20) ticketcount, P31 (20-24) validFor, P32 (24-28) static mac, P33 (28-32) first use,
            we just write these pages only and ignore update of other page.
            So, While writing in card:
                start page = 30
                page count = 4
             */
            byte[] toWrite = Arrays.copyOfRange(message, 16,32);
            res = utils.writePages(toWrite, 0, 30, 4);
            if (!res){
                infoToShow = "Failed to update tickets.";
                return false;
            }
            infoToShow = uses + " tickets added over "+ previousRemainingTickets +" non-expired tickets.";
            return true;
        }

        // Issuing new ticket
        System.out.println("Issuing new tickets because previous tickets expired.");

        // a. update the static data
        System.arraycopy( ApplicationTag.getBytes() , 0, message, 0, 4); // APP TAG
        System.arraycopy( ApplicationVersion.getBytes() , 0, message, 8, 4); // APP version
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

        // read app tag
        byte[] uidBytes = new byte[8];
        String uid  = "";
        res = utils.readPages(0, 2, uidBytes, 0);
        if (res) {
            uid = new String(Base64.getEncoder().encode(uidBytes));
            if (uid.isEmpty()){
                infoToShow = "Empty UID";
                return false;
            }
        } else {
            infoToShow = "Failed to read UID";
            return false;
        }

        // Authenticate
        if (!authenticateKeys()){
            infoToShow = "Authentication failed";
            return false;
        }

        // step 1: read from page 26 to 41
        byte[] message = new byte[64];
        res = utils.readPages(26, 16, message, 0);
        if (!res) {
            infoToShow = "Failed to read";
            return false;
        }

        // starting from page 26
        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
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
            infoToShow = "Invalid version. App only supports version "+ApplicationVersion;
            return false;
        }

        // key diversification
        macAlgorithm.setKey( generateDiversifiedKey(new String(ourHMACKey), uid) );

        // step 4.2 if not blank and MAC unmatches: abort
        boolean emptyMac = true;
        for (byte b : mac) {
            if (b != 0) {
                emptyMac = false; // if at least one byte is non-zero, the mac is non-empty
                break;
            }
        }
        if (emptyMac){
            infoToShow = "Empty MAC";
            return false;
        }
        byte[] staticData = Arrays.copyOfRange(message, 0, 24);
        byte[] computedMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
        if (!Arrays.equals(mac, computedMac)){
            infoToShow = "Invalid MAC";
            return false;
        }

        // step 6: check the number of tickets remaining using the CNTR and  counter in static data. If no ticekts, abort.
        int remainingTickets = Math.max(0, counterState + ticketCount - counter);
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
            infoToShow = "Tickets expired.";
            return false;
        }else if (counterState.equals(counter)){ // means the first use
            firstUse = new Date(currentDateInMillis);
            lastUse = firstUse;
            System.arraycopy( toBytes(firstUse), 0, message, 28, 4); // first use
            System.arraycopy( toBytes(lastUse), 0, message, 32, 4); // last use
            /*
              in case of first use, we write P33 (28-32) firstUse and P34 (32-36) lastUse.
              Once this is updated, we increment the counter.
             */
            res = // write firstUse and lastUse dates and increment counter
                utils.writePages( Arrays.copyOfRange(message, 28,36), 0, 33,2 )
                && utils.writePages(counterIncrementBy1, 0, 41, 1); // !!! WARNING !!!: Update this line only if you are sure of what you are doing!!

            // if res is false: either during updating firstUse and lastUse dates, or during counter update
            if (!res){
                infoToShow = "Failed to validate ticket.";
                return false;
            }

            infoToShow = "Ticket validated (1st use).\n" +
                    (remainingTickets-1) + " tickets remaining.\n" +
                    "Expires on: " + dateFormatter.format( new Date( currentDateInMillis + validityDurationInMillis ) );
            return true;

        }else { // not the first use
            if ( lastUse != null && (currentDateInMillis- lastUse.getTime())/1000 < waitingSecondsBetweenTwoTicketIssues){
                infoToShow = "Ticket validated less than " + waitingSecondsBetweenTwoTicketIssues + " seconds ago";
                return false;
            }else {
                lastUse = new Date(currentDateInMillis);
                if (firstUse == null){
                    firstUse = lastUse;
                    System.arraycopy( toBytes(firstUse), 0, message, 28, 4); // first use
                }
                System.arraycopy( toBytes(lastUse), 0, message, 32, 4); // last use

                // update the first and last use, then increase the counter
                res = utils.writePages( Arrays.copyOfRange(message, 28,36), 0, 33,2 )
                        && utils.writePages(counterIncrementBy1, 0, 41, 1); // !!! WARNING !!!: Update this line only if you are sure of what you are doing!!
                if (!res){
                    infoToShow = "Failed to validate ticket.";
                    return false;
                }

                /*
                there are 5 logs (each 4 bytes) from page 35 to 39 in the card's user memory.
                each new log will replace the oldest log from these pages, so index of new log = (counter%5)+35
                 */
                int pageToUpdate = (counter % 5) + 35;
                utils.writePages( toBytes(lastUse), 0, pageToUpdate, 1);

                infoToShow = "Ticket validated. \n"+ (remainingTickets-1) + " tickets remaining." +
                            "\nExpires on: " + dateFormatter.format( new Date( firstUse.getTime() + validityDurationInMillis ) );
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

    private static byte[] generateDiversifiedKey(String masterKey, String uid){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((masterKey+uid).getBytes());
            return Arrays.copyOfRange(hash,0,16);
        }catch (Exception ex){
            return null;
        }

    }

}