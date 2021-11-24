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

In order to issue tickets and/or format new cards, we use the `issue() ` function available in the file `/app/src/main/java/com/ticketapp/auth/ticket/Ticket.java` .The algorithm works as follows:

1. We first authenticate the card using our own custom method `boolean authenticateKeys()`. [1] If the authentication fails, than `issue()` fails.
2. Secondly, we read the data that is written in the NFC card and then we parse it accordingly
3. We create two flag booleans, their names explain their purpose: `issueNewTicket` and `checkMac`
4. We check if the application tag is present in the card; if it is **not** present, then we have to issue a new ticket, otherwise we check if the tag is equal to the expected one. If it is **not** the value we expect, `issue()` fails.

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

**Add flowcharts to explain the algorithm**

### Validating tickets

**Add flowcharts to explain the algorithm**

### Threat analysis

**Write down all of his concerns and how we mitigate them**
