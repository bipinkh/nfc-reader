# Network security Project 1: NFC Ticket

###### By Bipin Khatiwada and Alessandro Chiarelli

### Summary

1. Memory design
2. Issuing tickets
3. Validating tickets
4. Threat analysis

### Memory design

The NFC card that we were given, according to the official documentation, is organised in pages, each page is 4 bytes long. In order to do a single read and write operation, we are using contiguous pages in memory, starting from page 26 up until page 41, which is reserved for the counter. All the other pages are not use by our proposed solution so they are either empty or filled with the default values.

Here we outline the purpose of each page in the memory:

- page 26:
- page 27:
- page 28:
- page 29:
- page 30:
- page 31:
- page 32:
- page 33:
- page 34:
- page 35:
- page 36:
- page 37:
- page 38:
- page 39:
- page 40:
- page 41:

### Issuing tickets

**Add flowcharts to explain the algorithm**

### Validating tickets

**Add flowcharts to explain the algorithm**

### Threat analysis

**Write down all of his concerns and how we mitigate them**