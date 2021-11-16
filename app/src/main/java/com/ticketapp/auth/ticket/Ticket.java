package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Date;

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
         * page 6: number of tickets
         * page 7: validity time unit (day or min)
         * page 8 and 9: first use timestamp
         */
        byte[] existingData = new byte[16];
        res = utils.readPages(6, 4, existingData, 0);

        // first 4 bytes (1 page) is ticket number
        Integer ticketNumber = 0;
        Integer validityTimeUnit = daysValid;

        try {
            ticketNumber = Integer.valueOf( new String(Arrays.copyOfRange(existingData, 0, 4) ) );
        }catch (NumberFormatException ignore){ }


        if (ticketNumber > 0){
            byte[] command = new byte[8];
            ticketNumber += uses;
            // second 4 bytes (1 page) is validity time unit
            Integer existingValidity = Integer.valueOf( new String(Arrays.copyOfRange(existingData, 4, 8) ) );
            validityTimeUnit += existingValidity;

            byte[] timeBytes = String.format("%04d", ticketNumber).getBytes();
            System.arraycopy( timeBytes, 0, command, 0, 4 );

            timeBytes = String.format("%04d", validityTimeUnit).getBytes();
            System.arraycopy( timeBytes, 0, command, 4, 4 );
            //submit
            res = utils.writePages(command, 0, 6, 2);

            // last 8 bytes (2 pages) is first time ticket issue timestamp
            //Long firstUseTimeStr = Long.valueOf( new String(Arrays.copyOfRange(existingData, 8, 16) ) );
            //Date firstUseTime = new Date(firstUseTimeStr*1000);

        }else {
            byte[] command = new byte[16];
            byte[] timeBytes = String.format("%04d", uses).getBytes();
            System.arraycopy( timeBytes, 0, command, 0, 4 );
            timeBytes = String.format("%04d", validityTimeUnit).getBytes();
            System.arraycopy( timeBytes, 0, command, 4, 4 );
            //submit
            res = utils.writePages(command, 0, 6, 4);
        }

        // Set information to show for the user
        if (res) {
            infoToShow = "Read & Write commands to page 6.";
        } else {
            infoToShow = "Failed to read and write";
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

        // Example of reading:
        byte[] message = new byte[4];
        res = utils.readPages(6, 1, message, 0);

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}