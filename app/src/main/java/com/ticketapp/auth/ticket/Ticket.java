package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    private static final byte[] ourHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key_our).getBytes();
    private static String ApplicationTag = "BpAl";
    private static String ApplicationVersion = "v1.0";

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;
    private final int waitingSecondsBetweenTwoTicketIssues = 5; // time in seconds to wait before 2nd use
    private final int MaxLimitOfTicketNumber = 50; // maximum number of allowed tickets
    private final int MaxLimitOfValidDays = 90; // maximum number of days allowed for validity
    private static Boolean formatCard = false; /// !!! WARNING !!! This variable is set true only during development, to format card. Set it false in production
    private static String infoToShow = ""; // Use this to show messages
    DateFormat dateFormatter = new SimpleDateFormat("MM/dd/yyyy hh:mm");


    private static final byte[] counterIncrementBy1 = {1,0,0,0};
    private static final byte[] empty4Bytes = {0,0,0,0};

    /*
        AUTH0: (byte 0  of page 2Ah or 42d)
            page address from which the auth is required. In our case, page 26 = 1A (hex)
        AUTH1: (byte 0  of page 2Bh or 43d)
            bit_0 == 1 means auth required for WRITE access. bit_0 == 0 means auth required for WRITE & READ access.
     */
    private static final byte auth0Byte = Byte.parseByte("1A", 16);
    private static final byte auth1Byte = Byte.parseByte("00000000", 2);


    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(ourHMACKey);

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
        boolean res = utils.authenticate(ourAuthenticationKey);
        if (res) return true;
        // if authenticating with our key fails, authenticate with default key
        res = utils.authenticate(defaultAuthenticationKey);
        if (!res) {
            // if authenticating with default key also fails, then abort
            Utilities.log("Authentication failed", true);
            return false;
        }
        // if authenticating with default key works, change the authentication key to ours
        res = utils.writePages(ourAuthenticationKey, 0, 44, 4);
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
        boolean res = authenticateKeys() && utils.writePages(new byte[64], 0, 26, 14);
        if (res) {
            infoToShow = "Formatted the card";
        } else {
            infoToShow = "Fail to format card";
        }
    }

    private boolean setAuthConfigurations(){
        byte[] authConfiguration = new byte[8];
        boolean res = utils.readPages(42, 2, authConfiguration, 0);
        if (res){
            authConfiguration[0] = auth0Byte;
            authConfiguration[5] = auth1Byte;
            res = utils.writePages(authConfiguration, 0, 42, 2);
            return res;
        }else {
            return false;
        }
    }


    /**
     * Issue new tickets
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException, IOException {
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
        setAuthConfigurations();

        // step 1: read from page 31 to 41  [31:39 user memory, 40: lock bytes, 41: counter]
        byte[] message = new byte[11*4];
        res = utils.readPages(31, 11, message, 0);
        if (res) infoToShow = "Read memory. Processing data. ";
        else {
            infoToShow = "Failed to read the memory";
            return false;
        }
        // convert the read bytes to meaningful data for processing
        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String version = bytesToStr( Arrays.copyOfRange(message, 4, 8) );
        byte[] counterStateBytes = Arrays.copyOfRange(message, 8, 12);
        Integer counterState = bytesToInt( counterStateBytes );
        int ticketCount = bytesToInt( Arrays.copyOfRange(message, 12, 16) );
        int validFor = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        byte[] mac = Arrays.copyOfRange(message, 20, 24); // first 4 byte
        Date firstUse = bytesToDate( Arrays.copyOfRange(message, 24, 28) );
        byte[] counterBytes = Arrays.copyOfRange(message, 40, 44);
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

        byte[] staticData = Arrays.copyOfRange(message, 0, 20);
        byte[] staticDataMac;

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
        if(previousRemainingTickets > MaxLimitOfTicketNumber){
            // checking the safe limit
            infoToShow = "This card has more than 50 tickets already. Cannot issue any more tickets.";
            return false;
        }
        boolean hasNonExpiredPreviousTickets = firstUse == null; // if there is no first use at all for previously issued tickets
        if (!issueNewTicket && !hasNonExpiredPreviousTickets){
            // if at least one of the previously issued tickets is used, there may be some non-expired tickets.
            hasNonExpiredPreviousTickets = ( previousRemainingTickets > 0 )
                    && new Date(firstUse.getTime() + validityDurationInSec * 1000).after(new Date()); // expiry time is after current time
        }
        if (!issueNewTicket && hasNonExpiredPreviousTickets){
            // step 4.3.1 if not expired: add ticket and increase validity time for
            // a. increase the ticket count
            ticketCount += uses;
            System.arraycopy(toBytes(ticketCount), 0, message, 12, 4);
            // b. increase the validity for
            validFor = Math.min(MaxLimitOfValidDays, daysValid+validFor);
            System.arraycopy(toBytes(validFor), 0, message, 16, 4);

            //c. update the static data, and recompute the mac
            staticData = Arrays.copyOfRange(message, 0, 20);
            staticDataMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
            System.arraycopy(staticDataMac, 0, message, 20, 4);

            // d. clear first use
            System.arraycopy( empty4Bytes , 0, message, 24, 4); // clear first use
            // get new dynamic mac
            byte[] dynamicData = Arrays.copyOfRange(message, 24, 32);
            byte[] newDynamicMac = Arrays.copyOfRange(macAlgorithm.generateMac(dynamicData), 0, 4);
            System.arraycopy( newDynamicMac , 0, message, 32, 4);

            // e. push.
            /*
            P34 (12-16) ticketcount, P35 (16-20) validFor, P36 (20-24) static mac, P37 (24-28) first use, and P39 (dynamic mac)
            we just write these pages only and ignore update of other page.
            So, While writing in card:
                start page = 34
                page count = 4
             */
            byte[] toWrite = Arrays.copyOfRange(message, 12,28);
            res = utils.writePages(toWrite, 0, 34, 4) // updated data
                    && utils.writePages(newDynamicMac, 0, 39, 1); // new dynamic mac
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
        System.arraycopy( ApplicationVersion.getBytes() , 0, message, 4, 4); // APP Version
        System.arraycopy( counterBytes, 0, message, 8, 4); // copying card counter to counter state of static memory
        System.arraycopy( toBytes(uses), 0, message, 12, 4); // ticket count
        System.arraycopy( toBytes(daysValid), 0, message, 16, 4); // valid for

        // update static data, recompute mac and add mac
        staticData = Arrays.copyOfRange(message, 0, 20);
        staticDataMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
        System.arraycopy(staticDataMac, 0, message, 20, 4);

        // b. update the dynamic data
        System.arraycopy( empty4Bytes , 0, message, 24, 4); // clear first use
        System.arraycopy( empty4Bytes , 0, message, 28, 4); // clear last use
        byte[] dynamicData = Arrays.copyOfRange(message, 24, 28); // only the first use is dynamic data
        byte[] newDynamicMac = Arrays.copyOfRange(macAlgorithm.generateMac(dynamicData), 0, 4);
        System.arraycopy( newDynamicMac , 0, message, 32, 4); // dynamic mac

        // d. write all the data
        res = utils.writePages(message, 0, 31, 9); // exclude the last 2 page for lock and counter
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

        // step 1: read from page 31 to 41
        byte[] message = new byte[11*4];
        res = utils.readPages(31, 11, message, 0);
        if (!res) {
            infoToShow = "Failed to read";
            return false;
        }

        // starting from page 31
        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String version = bytesToStr( Arrays.copyOfRange(message, 4, 8) );
        Integer counterState = bytesToInt( Arrays.copyOfRange(message, 8, 12) );
        Integer ticketCount = bytesToInt( Arrays.copyOfRange(message, 12, 16) );
        Integer validFor = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        byte[] staticDataMac = Arrays.copyOfRange(message, 20, 24); // first 4 byte
        Date firstUse = bytesToDate( Arrays.copyOfRange(message, 24, 28) );
        Date lastUse = bytesToDate( Arrays.copyOfRange(message, 28, 32) );
        byte[] dynamicDataMac = Arrays.copyOfRange(message, 32, 36);
        byte[] counterBytes = Arrays.copyOfRange(message, 40, 44);
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

        // check static MAC
        boolean emptyMac = true;
        for (byte b : staticDataMac) {
            if (b != 0) {
                emptyMac = false; // if at least one byte is non-zero, the mac is non-empty
                break;
            }
        }
        if (emptyMac){
            infoToShow = "Failed to validate.\nEmpty MAC for static data.";
            return false;
        }
        byte[] staticData = Arrays.copyOfRange(message, 0, 20);
        byte[] computedStaticMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
        if (!Arrays.equals(staticDataMac, computedStaticMac)){
            infoToShow = "Failed to validate.\nInvalid MAC for static data.";
            return false;
        }

        // check dynamic MAC
        byte[] dynamicData = Arrays.copyOfRange(message, 24, 28);

        if (firstUse != null){
            emptyMac = true;
            for (byte b : dynamicDataMac) {
                if (b != 0) {
                    emptyMac = false; // if at least one byte is non-zero, the mac is non-empty
                    break;
                }
            }
            if (emptyMac){
                infoToShow = "Failed to validate.\nEmpty MAC for dynamic data.";
                return false;
            }
            byte[] computedDynamicMac = Arrays.copyOfRange( macAlgorithm.generateMac(dynamicData), 0, 4);
            if (!Arrays.equals(dynamicDataMac, computedDynamicMac)){
                infoToShow = "Failed to validate.\nInvalid MAC for dynamic data.";
                return false;
            }
        }

        // step 6: check the number of tickets remaining using the CNTR and  counter in static data. If no tickets, abort.
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

        }else if (counterState.equals(counter) || firstUse == null){ // means the first use

            firstUse = new Date(currentDateInMillis);
            System.arraycopy( toBytes(firstUse), 0, message, 24, 4); // first use
            dynamicData = Arrays.copyOfRange(message, 24, 28);
            byte[] newDynamicMac = Arrays.copyOfRange(macAlgorithm.generateMac(dynamicData), 0, 4);

            res = // write firstUse, dynamic mac, and increment counter. 3 WRITE commands only!!
                utils.writePages( Arrays.copyOfRange(message, 24,28), 0, 37,1 ) // first use
                && utils.writePages(newDynamicMac, 0, 39, 1) // dynamic mac
                && utils.writePages(counterIncrementBy1, 0, 41, 1); // increment counter

            // if res is false: either during updating firstUse and lastUse dates, or during counter update
            if (!res){
                infoToShow = "Failed to validate ticket.";
                return false;
            }
            infoToShow = "Ticket validated (1st use).\n" +
                    (remainingTickets-1) + " tickets remaining.\n" +
                    "Expires on: " + dateFormatter.format( new Date( currentDateInMillis + validityDurationInMillis ) );

        }else { // not the first use

            if ( lastUse != null && (currentDateInMillis- lastUse.getTime())/1000 < waitingSecondsBetweenTwoTicketIssues){
                infoToShow = "Ticket validated less than " + waitingSecondsBetweenTwoTicketIssues + " seconds ago";
                return false;
            }

            // increase the counter. If it succeeds, show the validated information. 1 WRITE command only !!
            res = utils.writePages(counterIncrementBy1, 0, 41, 1);
            if (!res){
                infoToShow = "Failed to validate ticket.";
                return false;
            }
            infoToShow = "Ticket validated. \n"+ (remainingTickets-1) + " tickets remaining." +
                        "\nExpires on: " + dateFormatter.format( new Date( firstUse.getTime() + validityDurationInMillis ) );
        }

         /*
                 In the end: whether it's first use or not
                 try to update last use as well, we ignore the response, because it's not critical even if it fails because it is only used to
                 prevent two successive quick tap. it serves no security purpose.
         */
        lastUse = new Date(currentDateInMillis);
        utils.writePages( toBytes(lastUse), 0, 38,1);
        return true;
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