
#ifndef CONFIG_H__
#define CONFIG_H__

#define TCP_reachability "Test_2"
#define TCP_performanceFromServerToClient "Test_3"
#define TCP_performanceFromClientToServer "Test_4"
#define UDP_reachability "Test_1"
#define UDP_performanceFromServerToClient "Test_5"
#define UDP_performanceFromClientToServer "Test_6"
#define TEST_prefix "Test_"
#define FINISH "FINISH"
#define SENDRESULTS "SndRes"


/**
 * Here client refers to the user starting the test.
 *
 * Packet formats:
 * The First UDP packet: (always from the client)
 *    for all:                      ( only for Test 5                   )
 *  |___4B___|___4B___|_____6B_____|(|_______8B_______|___ max 51B ___| )
 *  | PKT_ID |   TS   | Test Type  |(|  RATE_TO_SEND  | FILE_NAME |     )
 *  |        |        |            |(|                FILE_NAME_START 22)
 *  |        |        |            |(RATE_TO_SEND_START = 14            )
 *  |        |        TYPE_START = 8
 *  |        TIMESTAM_START = 4
 *  PKT_ID_START = 0
 *
 *
 * UDP packet sender side:
 * (in test 5 from the server and in test 6 from the client)
 *  |___4B___|___4B___|
 *  | PKT_ID |   TS   |
 *  |        |
 *  |        TIMESTAM_START = 4
 *  PKT_ID_START = 0
 *
 *
 * The ACK UDP packet:
 * (in test 5 from the client and in test 6 from the server)
 *     all acks:                         (the last ack for test 6)
 *  |___4B___|___4B___|___4B___|___4B___|(|_______8B_______|
 *  | PKT_ID |   TS   | TS recv|TS ACKed|(|RATE_RECEIVING_PKT|
 *  |        |        |        |        |
 *  |        |        |        |        RATE_RECEIVING_PKT_START = 16
 *  |        |        |        TIMESTAMP_ACK_SENT_START 12
 *  |        |        TIMESTAMP_RECEIVED_START 8
 *  |        TIMESTAM_START = 4
 *  PKT_ID_START = 0
 *  |_________________|
 *           |
 *        copied from sender packet
 *
 * The last UDP packet:
 * (in test 5 from the server and in test 6 from the client)
 *  |___4B___|___4B___|_____6B_____|
 *  | PKT_ID |   TS   |   FINISH   |
 *  |        |        |
 *  |        |        FINISH_START = 8
 *  |        TIMESTAM_START = 4
 *  PKT_ID_START = 0
 *
 *
 * We do not do htonl for pkt id and timestamp because these values will be only
 * read by this host. They are stored in a packet, sent to the receiver, the
 * receiver copies them into an ACK pkt and sends them back to the sender that
 * copies them back into uint32_t variables.
 */
#define PKT_ID_START 0
#define TIMESTAMP_START 4
#define TYPE_START 8
#define RATE_TO_SEND_START 14

#define PKT_ID_LEN 4
#define TIMESTAMP_LEN 4
#define TYPE_LEN 6
#define RATE_TO_SEND_LEN 8

#define FINISH_START 8
#define FINISH_LEN 6

// To do statistics about variation in trip time for data and ack
// (the absolut time can't be calculated because clocls may not be sync)
// the ack delay at receive can be calculated from this
#define TIMESTAMP_RECEIVED_START 8
#define TIMESTAMP_ACK_SENT_START 12
#define RATE_RECEIVING_PKT_START 16

#define TIMESTAMP_RECEIVED_LEN 4
#define TIMESTAMP_ACK_SENT_LEN 4
#define RATE_RECEIVING_PKT_LEN 8

#define FILE_NAME_START 22
// File name [16 random]_test[test number]_itr[iteration number]
#define FILE_NAME_LEN 51

/*
 * TCP packet format:
 * The First TCP packet: (always from the client)
 *                               (only foe sending results)
 *  |_____6B_____|___ max 51B ___|_______8B_______|
 *  | test type  |   file name   |  data length   |
 *  |            |               |                TCP_DATA_START = 65
 *  |            |               TCP_DATA_LEN_START = 57
 *  |            TCP_FILE_NAME_START = 6
 *  |
 *  TCP_TYPE_START = 0
 */

#define TCP_TYPE_START 0
#define TCP_TYPE_LEN 6
#define TCP_FILE_NAME_START 6
#define TCP_FILE_NAME_LEN 51
#define TCP_DATA_LEN_START 57
#define TCP_DATA_LEN_LEN 8
#define TCP_DATA_START 65

#define MAXBYTES  2097152
//TODO:change this to the 12s
#define MAXTIME 4

#define RETRANSMISSION_TIMEOUT 200
#define MAX_RETRANSMISSIONS 10
#define SHUTDOWNTIMEOUT 1000
#define NOPKTTIMEOUT 2000
#define PAYLOADSIZE 1450
#define PAYLOADSIZEF ((double) PAYLOADSIZE)

#endif
