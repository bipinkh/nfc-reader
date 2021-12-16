# Network security Project 1: NFC Ticket

---

####<center>By "Alessandro Chiarelli" and "Bipin Khatiwada"</center>

---

### Summary
1. Design Decision & Features
2. Memory design
3. Key Diversification
4. Threat analysis
5. Issuing tickets
6. Validating tickets
7. Appendix

  ---

### Design Decision & Features
- Unique key for each card, generated using the Serial ID of the card and master secret, that is different that the default password of the card.
- Unique key for MAC generation.
- 2 MACs to validate the integrity of the data in the card: one for static data and other for dynamic data.
- Read and Write protected in all the user memory pages used by the application.
- Multiple taps within 5 seconds *(configurable)* are blocked.
- 3 tickets *(configurable)* are issued in each issue action.
- More than 50 tickets *(configurable)* are not allowed to issue for any card.
- 30 days validity *(configurable)*, are given from the date of first use, while issuing tickets.
- More than 90 days *(configurable)* of validity period is not given to any card, regardless the number of tickets issued.
- If the card has non-expired tickets, those tickets are added during the new issue.
- If the card has non-expired tickets, the validity duration is added on top of the previous value.

---

### Memory design

The NFC card that we use is organised in pages, each of 4 bytes long. In order to easily read and write in a continuous pages, we are using memory pages from page 31 to 41. Page 31 to 39 is a part of user memory, while page 40 is for lock bits and 41 is for internal counter of the card. All the other pages are not use by our proposed solution so they are either empty or filled with the default values.

Here we outline the purpose of each page in the memory that are used by our application:

| Page Number | Page Number (Hex) | Data contained | Remarks |
|:----------:|:-------------:|:------:|:------|
| 0, 1 | 00, 01 | Serial ID | *default card memory* / Serial unique ID of the card. |
| 31 | 1F | App Tag | Identifier to check the card belongs to our app.|
| 32 | 20 | App Version | App version that was used to format the card (if it is). |
| 33 | 21 | Counter State | Value of internal counter when tickets were issued. |
| 34 | 22 | Ticket Count | Number of tickets issued. |
| 35 | 23 | Valid For | Number of days for which tickets are valid for from the "first use" day. |
| 36 | 24 | Static Data MAC | First 4 bytes of the MAC of all data from page 31 to 35. |
| 37 | 25 | First Use | UNIX timestamp to store the date when the card was first used. |
| 38 | 26 | Last Use | UNIX timestamp to store the date when the card was last used. This is used to check & invalidate two successive taps within short time. |
| 39 | 27 | Dynamic Data MAC | First 4 bytes of the MAC of page 37. |
| 40 | 28 | Lock Byte Configuration | *default implementation of card* |
| 41 | 29 | Internal Counter | *default card memory* / A oneway incrementing counter. |
| 42, 43 | 2A, 2B | Auth Configuration | *default card memory* / Set read/write protection in several pages. |
| 44 - 48 | 2C - 30 | Authentication Key | *default card memory* / Key for authentication. |

---

### Key Diversification

![key diversification.jpg](./res/key-diversification.jpg)

---

### Threat analysis

wip

---

### Issuing tickets

#### Algorithm
 ````
 1. Read Serial ID of card. If fails, abort.
 2. Calculate diversified key for authentication and MAC.
 3. Authenticate the card. If fails, abort.
 4. Read byte array from page 31 to 41. Parse all byte array to readable form.
 5. Check if app tag is present to verify this is our card
	 5.1. If App tag is present:
			 5.1.1. issueNewTicket = False
			 5.1.2. Validate if App tag matches. If fails, abort.
			 5.1.3. Validate if App version matches. If fails, abort.
			 5.1.4. Check if the static MAC matches. If fails, abort.
		5.2. If App tag is not present:
			5.2.1. issueNewTicket = True
			5.2.2. Format the card with app tag and version.
6. 
	6.1. if issueNewTicket = False,
			6.1.1. Add the remaining non-expired tickets plus new ticket count. 
			6.1.2. Ensure total ticket count is no more than 50.
			6.1.3. Add the validity period of new tickets plus the previous validity period. 
			6.1.4. Ensure total validity period is no more than 90 days.
	6.2. Else,
			6.2.1. Add App Tag and App version if missing.
			6.2.2. Add counter value to counter state memory.
			6.2.3. Add new tickets to issue.
			6.2.4. Add new validity period.
7. Issue tickets
		7.1. Calculate static MAC and add its first 4 bytes.
		7.2. Set first use period to null.
		7.3. Calculate dynamic MAC and add its first 4 bytes.
		7.4. Write changed pages to the NFC card.
8. return
````
In order to issue tickets and/or format new cards, we use the `issue() ` function available in the file `/app/src/main/java/com/ticketapp/auth/ticket/Ticket.java` .

---

### Validating tickets

##### Algorithm

````
 1. Read Serial ID of card. If fails, abort.
 2. Calculate diversified key for authentication and MAC.
 3. Authenticate the card. If fails, abort.
 4. Read byte array from page 31 to 41. If fails, abort.
	 4.1. Parse all byte array to readable form.
 5. Validate app tag and app version. If either fails, abort.
 6. Validate static data MAC
 7. Check if there are remaining tickets. If no, abort.
 8. Check the first use
	8.1. If counter = counterState, // first validation
		8.1.1. Set firstUse to now
		8.1.2. Calculate dynamic MAC, and store its first 4 bytes.
		8.1.3. Write first use date and dynamic MAC to card.
		8.1.4. Increase the counter by 1.
	8.2. Else,
		8.2.1. Check if this validate is called within 5 seconds of last use. If yes, abort.
		8.2.2. Validate dynamic data MAC
		8.2.3. Check if tickets are expired. If yes, abort.
		8.2.4. Increase the counter by 1.
9. Set last use to now and write to the card.
10.return 
````	
  In order to issue tickets and/or format new cards, we use the `use() ` function available in the file `/app/src/main/java/com/ticketapp/auth/ticket/Ticket.java` . 
 