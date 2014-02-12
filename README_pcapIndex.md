Networking pcapIndex
==========

1. Compile parser.c using 'gcc parser.c -lpcap'

2. Now execute the following command: './a.out dumpfile.dump'

3. Compile queryprocessor.c using 'gcc queryprocessor.c -lpcap'

4. Now execute the following command: './a.out'

5. Enter the query on prompt.

QUERY FORMAT:

AND operator: &
OR operator: |

For giving source ip in query give as : 	srcip=*.*.*.*   where * = 0 to 255
For giving destination ip in query give as : 	dstip=*.*.*.*   where * = 0 to 255
For giving source port in query give as : 	srcport=*	where * = 0 to 65536
For giving destination port in query give as : 	dstport=*   	where * = 0 to 65536
For giving protocol in query give as : 		protocol=*   	where * = tcp  or  udp


ALSO NOTE THAT dump file should contain packets having the following STRUCTURE ONLY:

FRAME
ETHERNET II
IP V4
TCP or UDP
Application layer protocol


ALSO TO BE NOTED THAT WE ARE READING ONLY 100 packets in a dump file
