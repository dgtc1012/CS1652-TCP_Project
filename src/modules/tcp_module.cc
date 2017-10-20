// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>

#include "Minet.h"
#include "tcpstate.h"

using namespace std;

// struct TCPState {
//     // need to write this
//     std::ostream & Print(std::ostream &os) const { 
// 	os << "TCPState()" ;len 
// 	return os;
//     }
// };


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	
	    if (event.handle == mux) {
            // call some function
		// ip packet has arrived!
            Packet p;
            unsigned short len;
            bool checksumok;
            MinetReceive(mux,p);
	        TCPHeader tcph;
            len = tcph.EstimateTCPHeaderLength(p);
            p.ExtractHeaderFromPayload<TCPHeader>(len);
	        tcph=p.FindHeader(Headers::TCPHeader);
	        checksumok=tcph.IsCorrectChecksum(p);
	        IPHeader iph;
	        iph=p.FindHeader(Headers::IPHeader);
	        Connection c;
            Buffer b = p.GetPayload();
            cout << "***************PAYLOAD****************\n";
            cout << b << "\n";
	        // note that this is flipped around because
	        // "source" is interepreted as "this machine"
	        iph.GetDestIP(c.src);
	        iph.GetSourceIP(c.dest);
	        iph.GetProtocol(c.protocol);
	        tcph.GetDestPort(c.srcport);
	        tcph.GetSourcePort(c.destport);
            cout << "*************RAW PACKET*************\n";
            cout << p << "\n";
            cout << "*************TCP HEADER*************\n";
            cout << tcph << "\n";
            cout << "*************IP HEADER*************\n";
            cout << iph << "\n";

            cout << "***************Connection List****************\n";
            cout << clist << "\n";

	        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
            if(cs!=clist.end()) {
                cout << "hello world\n";
            }

	    }

	    if (event.handle == sock) {
		// socket request or response has arrived
             cout << "got a socket req/res\n";
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
             //cout << "got a timeout\n";
	}

    }

    MinetDeinit();

    return 0;
}

void TCPStateMachine(TCPHeader &tcph, IPHeader &iph, ConnectionList<TCPState> &clist){
    
    Connection c;
    unsigned char flags;
    unsigned int ack;
    unsigned int seqnum;
    unsigned short window_size;
    unsigned short urgent;
    unsigned char tcph_size;
    unsigned char iph_size;
    unsigned short payload_size;
    unsigned short checksum;

    iph.GetDestIP(c.src);
    iph.GetSourceIP(c.dest);
    iph.GetProtocol(c.protocol);
    //iph.GetHeaderLen(iph_size);

    tcph.GetDestPort(c.srcport);
    tcph.GetSourcePort(c.destport);
    tcph.GetFlags(flags);
    tcph.GetSeqNum(seqnum);
    tcph.GetHeaderLen(tcph_size);
    tcph.GetWinSize(window_size);
    tcph.GetChecksum(checksum);
    tcph.GetUrgentPtr(urgent);
    tcph.GetAckNum(ack);

	ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
    //connection not found in list
    if(cs==clist.end()){
        //if this is a request for a new connection add connection to list, send ack
        if(IS_SYN(flags)){
            //need to select seqnum
            //is this synax for enum?
            //what is timertries
            //TCPState tcp = new TCPState(startSeqNum, eState.SYN_RCVD, 1);
            
        }
        //if it is not a request for a new connection and con doesnt exist then drop the packet
        else{
        }
    }
    //connection found in list
    else{
        //check TCPState
        int currState = cs->state.GetState();
        switch (currState){
            case CLOSED:
                //passive open, create TCB -> LISTEN
                //active open, create TCB snd SYN -> SYN_SENT
                break;
            case LISTEN:
                //Close, delete TCB ->CLOSED
                //rcv SYN, send SYN, ACK -> SYN_RCVD
                //SEND, snd SYN -> SYN_SENT
                break;
            case SYN_RCVD:
                //CLOSE, snd FIN -> FIN_WAIT1
                //rcv ACK of SYN -> ESTABLISHED
                break;
            case SYN_SENT:
                //rcv SYN, snd ACK -> SYN_RCVD
                //rcv SYN, ACK, snd ACK -> ESTABLISHED
                break;
            case SYN_SENT1:
                //?
                break;
            case ESTABLISHED:
                //CLOSE, snd FIN -> FIN_WAIT
                break;
            case SEND_DATA:
                break;
            case CLOSE_WAIT:
                break;
            case FIN_WAIT1:
                break;
            case CLOSING:
                break;
            case LAST_ACK:
                break;
            case FIN_WAIT2:
                break;
            case TIME_WAIT:
                break;
            default:
                break;
        }
        
        //if this is a request for a new connection for a connection that exists, send ack for last valid seqnum??
        if(IS_SYN(flags)){
        
        }
        //update last_acked field for TCPState in connection list and update connection state
        if(IS_ACK(flags)){
        
        }
        //update TCP state, send ack
        if(IS_FIN(flags)){
            
        }
    }
}
