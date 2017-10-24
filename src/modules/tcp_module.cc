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

enum TYPE{
    SYN,
    SYNACK,
    ACK,
    PSHACK,
    FIN,
    FINACK,
    RESET
};


#define BYTES_PER_WORD 4
#define BASE_TCP_HEADER_LEN_IN_WORDS 5

void handle_IP_Packet(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist);
void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CSM, TYPE HeaderType, int size, bool isTimeout);

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
            handle_IP_Packet(mux, sock, clist);

	    }

	    if (event.handle == sock) {
		// socket request or response has arrived
            // cout << "got a socket req/res\n";
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

void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CSM, TYPE HeaderType, int size, bool isTimeout){
    unsigned char flags = 0;
    int psize = size + TCP_HEADER_BASE_LENGTH +IP_HEADER_BASE_LENGTH;
    IPHeader iph;
    TCPHeader tcph;
    
    //set up IP header
    iph.SetSourceIP(CSM.connection.src);
    iph.SetDestIP(CSM.connection.dest);
    iph.SetTotalLength(psize);
    iph.SetProtocol(IP_PROTO_TCP);
    
    p.PushFrontHeader(iph);
    
    //set up TCP header
    tcph.SetSourcePort(CSM.connection.srcport, p);
    tcph.SetDestPort(CSM.connection.destport, p);
    tcph.SetHeaderLen(BASE_TCP_HEADER_LEN_IN_WORDS, p);
    tcph.SetAckNum(CSM.state.GetLastRecvd(), p);
    tcph.SetWinSize(CSM.state.GetN(), p);
    tcph.SetUrgentPtr(0, p);
    
    switch(HeaderType){
        case SYN:
            SET_SYN(flags);
            break;
        case ACK:
            SET_ACK(flags);
            break;
        case SYNACK:
            SET_SYN(flags);
            SET_ACK(flags);
            break;
        case PSHACK:
            SET_PSH(flags);
            SET_ACK(flags);
            break;
        case FIN:
            SET_FIN(flags);
            break;
        case FINACK:
            SET_FIN(flags);
            SET_ACK(flags);
            break;
        case RESET:
            SET_RST(flags);
            break;
        default:
            break;
    }
    tcph.SetFlags(flags, p);
    
    if(isTimeout){
        tcph.SetSeqNum(CSM.state.GetLastAcked(), p);
    }
    else{
        tcph.SetSeqNum(CSM.state.GetLastSent() + 1, p);
    }
    
    tcph.RecomputeChecksum(p);
    
    p.PushBackHeader(tcph);
}

void handle_IP_Packet(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist){
    cerr << "***************Entering handle_IP_Packet********************\n";
    Packet p;
    unsigned short len;
    bool checksumok;
    
    MinetReceive(mux,p);
    
    len = TCPHeader::EstimateTCPHeaderLength(p);
    p.ExtractHeaderFromPayload<TCPHeader>(len);
    TCPHeader tcph;
    tcph=p.FindHeader(Headers::TCPHeader);
    checksumok=tcph.IsCorrectChecksum(p);
    if(!checksumok){
        cerr << "Invalid Checksum\n";
        return;
    }
    IPHeader iph;
    iph=p.FindHeader(Headers::IPHeader);
    
    Connection c;
    Buffer b = p.GetPayload();
    cerr << "***************PAYLOAD****************\n";
    cerr << b << "\n";
    // note that this is flipped around because
    // "source" is interepreted as "this machine"
    
    iph.GetDestIP(c.src);
    iph.GetSourceIP(c.dest);
    iph.GetProtocol(c.protocol);
    tcph.GetDestPort(c.srcport);
    tcph.GetSourcePort(c.destport);
    
//***************************************************************************
    cerr << "*************RAW PACKET*************\n";
    cerr << p << "\n";
    cerr << "*************TCP HEADER*************\n";
    cerr << tcph << "\n";
    cerr << "*************IP HEADER*************\n";
    cerr << iph << "\n";

    cerr << "***************Connection List****************\n";
    cerr << clist << "\n";
//***************************************************************************

    unsigned char flags;
    unsigned int ack;
    unsigned int seqnum;
    unsigned short window_size;
    unsigned short urgent;
    unsigned char tcph_size;
    unsigned char iph_size;
    unsigned short payload_size;
    unsigned short checksum;
    
    tcph.GetFlags(flags);
    tcph.GetSeqNum(seqnum);
    tcph.GetHeaderLen(tcph_size);
    tcph.GetWinSize(window_size);
    tcph.GetChecksum(checksum);
    tcph.GetUrgentPtr(urgent);
    tcph.GetAckNum(ack);

    iph.GetHeaderLength(iph_size);
    iph.GetTotalLength(payload_size);
    
    payload_size = payload_size - (tcph_size * BYTES_PER_WORD) - (iph_size * BYTES_PER_WORD);
    
    Buffer payload;
    
    payload = p.GetPayload().ExtractFront(payload_size);
    
    ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);    
    
    if(cs == clist.end()) {
        cerr << "Connection isnt in the list\n";
    }

    
    unsigned int currState = cs->state.GetState();
    
    switch(currState){
     case CLOSED:
        //********** do we need this? ****************//
        //passive open, create TCB -> LISTEN
        //active open, create TCB snd SYN -> SYN_SENT
        break;
    case LISTEN:
        //Close, delete TCB ->CLOSED
        //rcv SYN, send SYN, ACK -> SYN_RCVD
        //SEND, snd SYN -> SYN_SENT
        if(IS_SYN(flags)){
            //got a SYN, need to send SYNACK for handshake
            
            //updating connection info
            cs->connection = c;
            cs->state.SetState(SYN_RCVD);
            cs->state.last_acked = cs->state.last_sent;
            cs->state.SetLastRecvd(seqnum+1);
            
            //send synack packet
            cs->state.last_sent = cs->state.last_sent + 1;
            
            Packet send;
            
            make_packet(send, *cs, SYNACK, 0, false);
            MinetSend(mux, send);
        }
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
        //************* idk ***************//

     break;
    case CLOSE_WAIT:
        //************* idk **************//
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
}
