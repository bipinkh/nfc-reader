# Network security Project 1: NFC Ticket

###### By Bipin Khatiwada and Alessandro Chiarelli

### Summary

1. Memory design
2. Issuing tickets
3. Validating tickets
4. Threat analysis

### Memory design

The NFC card that we were given, according to the official documentation, is organised in pages, each page is 4 bytes long. In order to do a single read and write operation, we are using contiguous pages in memory, starting from page 26 up until page 41, which is reserved for the counter. All the other pages are not use by our proposed solution so they are either empty or filled with the default values.

Here we outline the purpose of each page in the memory that are used by our application:

- page 26: **App tag**, it is used to make sure that the card has been formatted for our application;
- page 27: **UID**, it is an ID that is identifies the card and it is used as part of the secret key for the card's MAC;
- page 28: **Version**, it is a filed used to save information about the version of our app that has been used to format the card;
- page 29: **Counter State**, it is a field used to check how many tickets are valid in the current card;
- page 30: **Valid For**, it is a field that gives us the number of days that a ticket is valid for;
- page 31: **MAC**, this field stores a MAC that is computed over the previous fields (the ones going from page 26 to 30). The MAC is computed over the "Static data", which are the fields that are modified when issuing tickets. The other fields are modified when validating the ticket and are part of the "dynamic data";
- page 32: **First use**, it contains a timestamp of when the card has been used for the first time after issuing new tickets;
- page 33: **Last use**, it contains a timestamp of the last time a ticket has been validated;
- page 34-39: **Logs**, they contain the last few times tickets have been used for auditing purposes;
- page 41: **Counter**, it is a one way 16-bit counter that we use to count the tickets as they are used.

### Issuing tickets

###### Algorithm explanation

In order to issue tickets and/or format new cards, we use the `issue() ` function available in the file `/app/src/main/java/com/ticketapp/auth/ticket/Ticket.java` . The algorithm works as follows:

1. We first authenticate the card using our own custom method `boolean authenticateKeys()`. [1] If the authentication fails, than `issue()` fails.
2. Secondly, we read the data that is written in the NFC card and then we parse it accordingly
3. We create two flag booleans, their names explain their purpose: `issueNewTicket` and `checkMac`
4. We check if the application tag is present in the card; if it is **not** present, then we have to issue a new ticket, otherwise we check if the tag is equal to the expected one. If it is **not** the value we expect, `issue()` fails.
5. We now check the version tag and make sure that it is the current one; if it isn't then `issue()` fails.
6. We check that the card UID is present since it is used for computing the MAC.
7. We now check the MAC to make sure that the card has not been tampered with. We first build the key (master key || card UID), compute the MAC and then compare it to the one stored in the card.
8. We now check if the ticket is expired or not. We have the following steps:
   1. We get the current time, the validity duration and the timestamp of the first use.
   2. If we do not have a timestamp of first use, we add new tickets since the first ones have not been used. We then increase the ticket count and increase the validity time of said tickets, we compute the new MAC and finally write it to the card.
   3. If instead we have a valid timestamp of first use, but the validity period hasn't expired, we add new tickets on top of the non-expired ones. We increase the ticket count, recompute the MAC and then overwrite the card.

9. The last step is to check if we have to issue a new Ticket, which happens either when all the tickets in the card have expired or if we have a blank card. In this case, we modify all fields as per design.

###### Code

```java
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
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
        Integer counterState = bytesToInt( Arrays.copyOfRange(message, 12, 16) );
        Integer ticketCount = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        Integer validFor = bytesToInt( Arrays.copyOfRange(message, 20, 24) );
        byte[] mac = Arrays.copyOfRange(message, 24, 28); // first 4 byte
        Integer firstUse = bytesToInt( Arrays.copyOfRange(message, 28, 32) );
        Integer lastUse = bytesToInt( Arrays.copyOfRange(message, 32, 36) );
        String logs = bytesToStr( Arrays.copyOfRange(message, 36, 56) );
        Integer counter = bytesToInt( Arrays.copyOfRange(message, 60, 64));

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
        long currentTime = new Date().getTime();
        long validityDuration = 1000 * 86400 * validFor;
        Long firstUseTimestamp = isValidTime(firstUse);

        if ( !issueNewTicket && firstUseTimestamp == null){
            System.out.println("Adding new tickets because previous tickets aren't used.");
            issueNewTicket = false;
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
            log(message);

            res = utils.writePages(message, 0, 26, 14);
            if (res) {
                infoToShow = uses + " tickets added.";
            } else {
                System.out.println( message );
                infoToShow = "Failed to update tickets.";
            }
            return true;
        }

        if ( !issueNewTicket && currentTime < (firstUseTimestamp + validityDuration) && ( ticketCount+counter >= counter )){
            System.out.println("Adding new tickets on top of non-expired tickets.");
            issueNewTicket = false;
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

            // d. push
            log(message);

            res = utils.writePages(message, 0, 26, 14);
            if (res) {
                infoToShow = uses + " tickets added.";
            } else {
                System.out.println( message );
                infoToShow = "Failed to update tickets.";
            }
            return true;
        }else{
            // step 4.3.2 if expired: issue new tickets with new validity
            System.out.println("Issuing new tickets because previous tickets expired.");
            issueNewTicket = true;
        }


        if (issueNewTicket){
            // Issuing new ticket
            // a. update the static data
            System.arraycopy( ApplicationTag.getBytes() , 0, message, 0, 4); // APP TAG
            System.arraycopy( ApplicationVersion.getBytes() , 0, message, 8, 4); // APP version
            System.arraycopy( uid.getBytes() , 0, message, 4, 4); // UID
            System.arraycopy( toBytes(counter), 0, message, 12, 4); // copying card counter to counter state of static memory
            System.arraycopy( toBytes(uses), 0, message, 16, 4); // ticket count
            System.arraycopy( toBytes(daysValid), 0, message, 20, 4); // valid for
            // add mac
            staticData = Arrays.copyOfRange(message, 0, 24);
            newMac = Arrays.copyOfRange( macAlgorithm.generateMac(staticData), 0, 4);
            System.arraycopy(newMac, 0, message, 24, 4);

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
```

[1] This is the code and explanation for `authenticateKeys()`:

```java
public boolean authenticateKeys(){
        boolean res = utils.authenticate(authenticationKey);
        if (res) return true;
        // Authenticate with default key
        res = utils.authenticate(defaultAuthenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in format()", true);
            return false;
        }

        res = utils.writePages(authenticationKey, 0, 44, 4);
        if (res) {
            Utilities.log("Keys updated", false);
            return true;
        } else {
            Utilities.log("Failed to update keys", true);
            return false;
        }
    }
```

- The method first tries to authenticate the card with the authentication key using the provided method from the utils module. 
  - If the authentication succeeds, return true
  - if the authentication does not succeed, then the method tries to authenticate using the default key for the NFC card
    - If the authentication succeeds, then the method writes the key into the NFC card since we have a new blank card
    - Else the method fails since the card has a key that our application does not recognise

### Validating tickets

###### Algorithm explanation

###### Code

```java
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

        String appTag = bytesToStr( Arrays.copyOfRange(message, 0, 4) );
        String uid = bytesToStr( Arrays.copyOfRange(message, 4, 8) );
        String version = bytesToStr( Arrays.copyOfRange(message, 8, 12) );
        Integer counterState = bytesToInt( Arrays.copyOfRange(message, 12, 16) );
        Integer ticketCount = bytesToInt( Arrays.copyOfRange(message, 16, 20) );
        Integer validFor = bytesToInt( Arrays.copyOfRange(message, 20, 24) );
        byte[] mac = Arrays.copyOfRange(message, 24, 28); // first 4 byte
        Integer firstUse = bytesToInt( Arrays.copyOfRange(message, 28, 32) );
        Integer lastUse = bytesToInt( Arrays.copyOfRange(message, 32, 36) );
        byte[] logs = Arrays.copyOfRange(message, 36, 56);
        Integer counter = bytesToInt( Arrays.copyOfRange(message, 60, 64));

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
        if ( ( ticketCount - (counter - counterState) ) <= 0){
            infoToShow = "No tickets";
            return false;
        }

        // step 7: check the time. if expired, abort. or, if it is first use, first_use = now
            // step 7.1: in case of first use, add first_use and last_use fields and increase CNTR
            // step 7.2: check the last_time used, if within 1 minute, validate but dont increase CNTR
        long validityDuration = 1000 * 86400 * validFor;
        long currentDate = System.currentTimeMillis();
        if (firstUse != 0 && ( currentDate - firstUse * 1000) < validityDuration ){
            infoToShow = "Tickets expired timewise";
            return false;
        }else if (firstUse == 0){
            System.arraycopy( timestampToByteArray(currentDate), 0, message, 28, 4); // first use
            System.arraycopy( timestampToByteArray(currentDate), 0, message, 32, 4); // last use
            System.arraycopy( ByteBuffer.allocate(4).putInt(1).array(), 0, message, 60, 4); // counter increment by 1
            res = utils.writePages(message, 0, 26, 16);
            if (res) {
                infoToShow = "Ticket validated";
            } else {
                infoToShow = "Failed to validate ticket.";
            }
            return true;
        }else {
            // not the first use
            if ( ( currentDate/1000 - lastUse ) < 1 ){ // todo: change 1 to 60
                infoToShow = "Ticket validated less than a minute ago";
                return false;
            }else {
                System.arraycopy( timestampToByteArray(currentDate), 0, message, 32, 4); // last use
                System.arraycopy( ByteBuffer.allocate(4).putInt(1).array(), 0, message, 60, 4); // counter increment by 1
                // write logs: page 36 to 56
                System.arraycopy(logs, 12, logs, 16, 4 );
                System.arraycopy(logs, 8, logs, 12, 4 );
                System.arraycopy(logs, 4, logs, 8, 4 );
                System.arraycopy(logs, 0, logs, 4, 4 );
                System.arraycopy(timestampToByteArray(currentDate), 0, logs,0, 4 );
                System.arraycopy(logs, 0, message, 36, 20);
                // write
                res = utils.writePages(message, 0, 26, 16);
                if (res) {
                    infoToShow = "Ticket validated";
                } else {
                    infoToShow = "Failed to validate ticket.";
                }
                return true;
            }
        }
    }
```



### Threat analysis

**Write down all of his concerns and how we mitigate them**
