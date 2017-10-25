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
        TCPState *newConn = new TCPState(0, LISTEN, 5);\
        Time *t = new Time(2.5);
        ConnectionToStateMapping<TCPState> * newCSM = new ConnectionToStateMapping<TCPState>(c, *t, *newConn, false);
        clist.push_back(*newCSM);
        
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);    
    }
    
    unsigned int currState = cs->state.GetState();
    
    switch(currState){
     case CLOSED:
        //********** do we need this? ****************//
        //passive open, create TCB -> LISTEN
        //active open, create TCB snd SYN -> SYN_SENT
        break;
    case LISTEN:
        cerr << "*****************In LISTEN state************************\n";
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
        cerr << "*********************In SYN_RCVD state******************\n";
        //CLOSE, snd FIN -> FIN_WAIT1
        //rcv ACK of SYN -> ESTABLISHED
        if(IS_ACK(flags)){
            cs->state.SetState(ESTABLISHED);
            cs->state.SetLastAcked(ack);
            cs->state.SetSendRwnd(window_size);
            cs->state.last_sent = cs->state.last_sent + 1;
            
            //turn off timer, we got an ACK
            cs->bTmrActive = false;

            //tell app layer that connection was established
            SockRequestResponse * msg = new SockRequestResponse(WRITE, cs->connection, payload, 0, EOK);
            MinetSend(sock, *msg);
            delete msg;
        }
        break;
    case SYN_SENT:
        cerr << "*****************In SYN_SENT state****************\n";
        //rcv SYN, snd ACK -> SYN_RCVD
        //rcv SYN, ACK, snd ACK -> ESTABLISHED
        if(IS_SYN(flags) && IS_ACK(flags)){
            //got a SYNACK msg, need to send an ACK to establish connection
            cs->state.SetSendRwnd(window_size);
            cs->state.SetLastRecvd(seqnum + 1);
            cs->state.last_acked = ack;
            cs->state.last_sent = cs->state.last_sent + 1;

            //send ack msg
            Packet send;
            make_packet(send, *cs, ACK, 0, false);
            MinetSend(mux, send);

            cs->state.SetState(ESTABLISHED);
            cs->bTmrActive = false;

            SockRequestResponse * msg = new SockRequestResponse(WRITE, cs->connection, payload, 0, EOK);
            MinetSend(sock, *msg);
            delete msg;
        }
        break;
    case SYN_SENT1:
        //?
        break;
    case ESTABLISHED:
        //CLOSE, snd FIN -> FIN_WAIT
        cerr << "********************In ESTABLISHED state*******************\n";
        if(IS_FIN(flags)){
            //we get a fin, so we send an ack and send our own fin
            cerr << "*******************Got FIN*************************\n";
            cs->state.SetState(CLOSE_WAIT);
            cs->state.SetLastRecvd(seqnum+1);
            cs->bTmrActive = true;
            cs->timeout = Time()+8; //picked that arbitrarily
            
            Packet ack_pack;
            make_packet(ack_pack, *cs, ACK, 0, false);
            MinetSend(mux, ack_pack);

            Packet fin;
            make_packet(fin, *cs, FIN, 0, false);
            MinetSend(mux, fin);

            cs->state.SetState(LAST_ACK);
        }
        if(IS_PSH(flags)){
        
        }
        if(IS_ACK(flags)){
        
        }
        break;
    case SEND_DATA:
        //************* idk ***************//

     break;
    case CLOSE_WAIT:
        //************* idk **************//
        break;
    case FIN_WAIT1:
        cerr << "**********************In FIN_WAIT1 state******************\n";
        if(IS_ACK(flags)){
            // got to FIN_WAIT2, waiting for fin from other side
            cs->state.SetState(FIN_WAIT2);
        }
        if(IS_FIN(flags) && IS_ACK(flags)){
            //got a FINACK msg
            cs->state.SetState(TIME_WAIT);
            cs->state.SetLastRecvd(seqnum+1);
            
            Packet close;
            make_packet(close, *cs, ACK, 0, false);
            
            //close connection if no new FIN recvd by timout
            cs->bTmrActive = true;
            cs->timeout = Time() + 2*MSL_TIME_SECS;
            MinetSend(mux, close);
        }
        break;
    case CLOSING:
        break;
    case LAST_ACK:
        cerr << "*********************In LAST_ACK state****************\n";
        if(IS_ACK(flags)){
            cs->state.SetState(CLOSED);
            clist.erase(cs);
        }
        break;
    case FIN_WAIT2:
        cerr << "*********************In FIN_WAIT2 state******************\n";
        if(IS_FIN(flags)){
            //got a FINACK msg
            cs->state.SetState(TIME_WAIT);
            cs->state.SetLastRecvd(seqnum+1);
            
            Packet close;
            make_packet(close, *cs, ACK, 0, false);
            
            //close connection if no new FIN recvd by timout
            cs->bTmrActive = true;
            cs->timeout = Time() + 2*MSL_TIME_SECS;
            MinetSend(mux, close);
        }
        break;
    case TIME_WAIT:
        cerr << "********************In TIME_WAIT state*****************\n";
        //probs resend ack if we get another fin at this point, bc the ack we sent before was lost
        break;
    default:
        break;
    }
}
