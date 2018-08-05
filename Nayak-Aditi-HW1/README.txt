The folder includes:

1. Part A (mydns resolver)
2. Part B (mydnsresolver with dnssec)
3. Part C (experiments with part A)

********************************************************************************************
RUN INSTRUCTIONS:
********************************************************************************************

1. Dependencies: Install dnspython
   To run PART A type command in following order: python mydig.py domain-name type
   EG: python mydig.py www.google.com A

2. Dependencies: Install dnspython,dns.query,import dns.rdtypes.ANY.NSEC,dns.rdtypes.ANY.NSEC3
   To run PART A type command in following order: python mydigdsec.py domain-name type
   EG: python mydigdsec.py www.google.com A

3. Dependencies: Install dnspython,matplotlib
   To run the tests for PART A run the automated code in following order: python partc.py

*********************************************************************************************