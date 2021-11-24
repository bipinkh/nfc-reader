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

**Add flowcharts to explain the algorithm**

### Validating tickets

**Add flowcharts to explain the algorithm**

### Threat analysis

**Write down all of his concerns and how we mitigate them**
