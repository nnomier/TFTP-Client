# TFTP-CLient
**Trivial File Transfer Protocol (TFTP) is a simple lockstep File Transfer Protocol which allows a client to get a file from or put a file onto a remote host. One of its primary uses is in the early stages of nodes booting from a local area network. TFTP has been used for this application because it is very simple to implement.**

You can read more about it in the RFC  [here](https://tools.ietf.org/html/rfc1350)

## From the RFC
  *Any transfer begins with a request to read or write a file, which
   also serves to request a connection.  If the server grants the
   request, the connection is opened and the file is sent in fixed
   length blocks of 512 bytes.  Each data packet contains one block of
   data, and must be acknowledged by an acknowledgment packet before the
   next packet can be sent.  A data packet of less than 512 bytes
   signals termination of a transfer.  If a packet gets lost in the
   network, the intended recipient will timeout and may retransmit his
   last packet (which may be data or an acknowledgment), thus causing
   the sender of the lost packet to retransmit that lost packet.  The
   sender has to keep just one packet on hand for retransmission, since
   the lock step acknowledgment guarantees that all older packets have
   been received.  Notice that both machines involved in a transfer are
   considered senders and receivers.  One sends data and receives
   acknowledgments, the other sends acknowledgments and receives data.*