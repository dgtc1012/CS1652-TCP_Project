// CS 1652: Data Communications and Networks
// PROJECT 2 DELIVERABLE
// DANNAH GERSH
// DAN MCGRATH

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

#include <cstdlib>

// for min()
#include <algorithm>

#include <iostream>

#include "Minet.h"
#include "tcpstate.h"

using namespace std;

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
void handle_Sock_Req(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist);
void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CSM, TYPE HeaderType, int size, bool isTimeout);
void handle_timeout_event(MinetHandle &mux, ConnectionList<TCPState>::iterator &CSM, ConnectionList<TCPState> &clist);
void send_data(MinetHandle &mux, Buffer &data, ConnectionToStateMapping<TCPState> &ctsm, bool isNew);

int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    srand(time(NULL));
    
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
    
    cerr << "tcp_module DAN MCGRATH DANNAH GERSH handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module DAN MCGRATH DANNAH GERSH handling tcp traffic........"));
   
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
            handle_Sock_Req(mux, sock, clist);
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
        ConnectionList<TCPState>::iterator cs = clist.FindEarliest();
        if(cs != clist.end()){
            if(Time() > (*cs).timeout){
                handle_timeout_event(mux, cs, clist);
            }
        }
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
        return;
    }
    IPHeader iph;
    iph=p.FindHeader(Headers::IPHeader);
    
    Connection c;
    Buffer b = p.GetPayload(); //?
    // note that this is flipped around because
    // "source" is interepreted as "this machine"
    
    iph.GetDestIP(c.src);
    iph.GetSourceIP(c.dest);
    iph.GetProtocol(c.protocol);
    tcph.GetDestPort(c.srcport);
    tcph.GetSourcePort(c.destport);
    
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
        int randnum = rand() % RAND_MAX;
        TCPState *newConn = new TCPState(randnum, LISTEN, 5);\
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
            cs->bTmrActive = true;
            cs->timeout = Time() + 5;

            make_packet(send, *cs, SYNACK, 0, false);
            MinetSend(mux, send);
        }
        break;
    case SYN_RCVD:
        //CLOSE, snd FIN -> FIN_WAIT1
        //rcv ACK of SYN -> ESTABLISHED
        //you have send a SYNACK in response to a SYN, you are waiting for an ACK
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
        //rcv SYN, snd ACK -> SYN_RCVD
        //rcv SYN, ACK, snd ACK -> ESTABLISHED
        //you got a SYNACK, so now you have to send an ACK. Set a timeout on the ack
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
        if(IS_FIN(flags)){
            //we get a fin, so we send an ack and send our own fin
            cs->state.SetSendRwnd(window_size); //I feel like we dont care about this anymore bc we got a fin
            cs->state.SetState(CLOSE_WAIT);
            cs->state.SetLastRecvd(seqnum+1);
            cs->bTmrActive = true;
            cs->timeout = Time()+5; //picked that arbitrarily
            
            Packet ack_pack;
            make_packet(ack_pack, *cs, FINACK, 0, false);
            MinetSend(mux, ack_pack);

            cs->state.SetState(LAST_ACK);
        }
        if(IS_ACK(flags)){
            // if not a duplicate
            if(ack > cs->state.last_acked) {

                cs->state.SetSendRwnd(window_size);

                // clear send buffer 
                int acked_bytes = ack - cs->state.last_acked;
                cs->state.SendBuffer.Erase(0, acked_bytes);
                
                cs->bTmrActive = false;
                cs->state.last_acked = ack;
            }
        
        }
        if(IS_PSH(flags) && payload.GetSize()!=0){
            cs->state.SetSendRwnd(window_size);
            cs->state.SetLastRecvd(seqnum+payload.GetSize());
            
            cs->state.RecvBuffer.AddBack(payload);
            SockRequestResponse *write = new SockRequestResponse(WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK);
            MinetSend(sock, *write);
            delete write;
            
            Packet send;
            make_packet(send, *cs, ACK, 0, false);
            MinetSend(mux, send);
            
            cs->bTmrActive = false;
        }
        break;
    case SEND_DATA:
        // do nothing
     break;
    case CLOSE_WAIT:
        // do nothing
        break;
    case FIN_WAIT1:
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
        if(IS_ACK(flags)){
            cs->state.SetState(CLOSED);
            clist.erase(cs);
        }
        break;
    case FIN_WAIT2:
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
        break;
    default:
        break;
    }
}

void handle_Sock_Req(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist){

    SockRequestResponse req;
    Buffer b;
    MinetReceive(sock, req);


    ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
    //connection not in list
    if(cs == clist.end()){
        switch (req.type){
            //We are the client asking the connect with a server
            case CONNECT:
                {
                    //got a request from socket to create a new connection
                    //need to change to random selection of the seqnum start

                    int randnum = rand() % RAND_MAX;
                    TCPState * state = new TCPState(randnum, SYN_SENT, 5);
                    ConnectionToStateMapping<TCPState> * CTSM = new ConnectionToStateMapping<TCPState>(req.connection, Time()+5, *state, true);
                    CTSM->state.last_acked = 0;
                    
                    Packet sendSyn;
                    make_packet(sendSyn, *CTSM, SYN, 0, false);
                    
                    CTSM->bTmrActive = true;
                    CTSM->timeout = Time() + 5;

                    MinetSend(mux, sendSyn);
                
                    clist.push_back(*CTSM);
                    
                    SockRequestResponse *status = new SockRequestResponse(STATUS, CTSM->connection, b, 0, EOK); //dunno if this should be null
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            //we are the server waiting to accept a connection from the client
            case ACCEPT :
                {
                    //same thing, need to make random
                    int randnum = rand() % RAND_MAX;
                    TCPState * state = new TCPState(randnum, LISTEN, 5);
                    ConnectionToStateMapping<TCPState> * CTSM = new ConnectionToStateMapping<TCPState>(req.connection, Time()+5, *state, true);
                    
                    CTSM->state.last_acked = 0; //why do we do this? if we should shouldnt we do it for connect?
                    
                    SockRequestResponse *status = new SockRequestResponse(STATUS, CTSM->connection, b, 0, EOK); //dunno if this should be null
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            //reply that there is no connection
            case WRITE:
                {
                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, ENOMATCH);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            //reply that there is no connection
            case FORWARD:
                {
                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, ENOMATCH);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            //reply that there is no connection
            case CLOSE:
                {
                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, ENOMATCH);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            //reply that there is no connection
            case STATUS:
                {
                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, ENOMATCH);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            default:
                {
                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, ENOMATCH);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
        }
    }
    else{
        switch(req.type) {
            case CONNECT:
                // already connected
                break;
            case ACCEPT:
                // already listening
                break;
            case WRITE:

                if(cs->state.GetState() == ESTABLISHED) {
                    // check if buffer is full
                    if(cs->state.SendBuffer.GetSize() + req.data.GetSize() >= cs->state.TCP_BUFFER_SIZE) {
                        SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, EBUF_SPACE);
                        MinetSend(sock, *status);
                        delete status;
                    } else {
                        Buffer reqData = req.data;
                        cs->bTmrActive = true;
                        cs->timeout = Time() + 5;
                        //some send data method
                        send_data(mux, reqData, *cs, true);
                        
                        //tell sock data was send successfull
                        SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, req.data.GetSize(), EOK); //not sure this is the correct response
                        MinetSend(sock, *status);
                        
                        delete status;
                    }
                }
                break;
            case FORWARD:
                {
                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, EOK);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            case CLOSE:
                {
                    if(cs->state.GetState() == ESTABLISHED){
                        cs->state.SetState(FIN_WAIT1);
                        cs->state.last_acked += 1;

                        Packet fin;
                        make_packet(fin, *cs, FIN, 0, false);
                        cs->state.SetLastSent((cs->state.GetLastSent()+1)% RAND_MAX);

                        cs->bTmrActive = true;
                        cs->timeout = Time() + 2*MSL_TIME_SECS;
                        MinetSend(mux, fin);    
                    }
                    else if(cs->state.GetState() == LISTEN){
                        cs->state.SetState(CLOSED);
                        clist.erase(cs);
                    }

                    SockRequestResponse *status = new SockRequestResponse(STATUS, req.connection, b, 0, EOK);
                    MinetSend(sock, *status);
                    delete status;
                }
                break;
            case STATUS:
                {
                    //flow control do later
                }
                break;
        }
        
    }
}

void send_data(MinetHandle &mux, Buffer &data, ConnectionToStateMapping<TCPState> &ctsm, bool isNew){
    int dataLen = data.GetSize();
    int sendBufLen = ctsm.state.SendBuffer.GetSize();
    int sendBufIndex;
    int bytesToSend;

    if(isNew){
        sendBufIndex = sendBufLen; //sendBufLen is the length of the send buffer before the new data is added
        ctsm.state.SendBuffer.AddBack(data);
        bytesToSend = dataLen;
    }
    else{
        sendBufIndex = 0;
        bytesToSend = sendBufLen;
    }
    while(bytesToSend > 0){
        //check if bytesToSend > max size of message, if it is
        int payloadLen;
        if(bytesToSend > TCP_MAXIMUM_SEGMENT_SIZE - TCP_HEADER_MAX_LENGTH){
            payloadLen = TCP_MAXIMUM_SEGMENT_SIZE - TCP_HEADER_MAX_LENGTH;
        }
        else{
            payloadLen = bytesToSend;
        }
        Buffer payload = ctsm.state.SendBuffer.Extract(sendBufIndex, payloadLen);
        Packet *p = new Packet(payload);
        make_packet(*p, ctsm, PSHACK, payloadLen, !isNew);
        MinetSend(mux, *p);
        delete p;
        
        ctsm.state.SetLastSent((ctsm.state.GetLastSent() + payloadLen) % RAND_MAX);

        bytesToSend -= payloadLen;

    }


    
}

void handle_timeout_event(MinetHandle &mux, ConnectionList<TCPState>::iterator &CSM, ConnectionList<TCPState> &clist){
    
    unsigned int state = CSM->state.GetState();
    Packet resend;
    Buffer data;
    
    switch(state){
        case LISTEN:
            //no timeouts here
            break;
        case SYN_RCVD:
            //synack was not acked, resend it 
            make_packet(resend, *CSM, SYNACK, 0, true);
            break;
        case SYN_SENT:
            //no ack has occured yet at all, only a syn has been
            make_packet(resend, *CSM, SYN, 0, false);
            MinetSend(mux, resend);
            break;
        case ESTABLISHED:
            //resend with whatever data is there or not
            data = CSM->state.SendBuffer;
            send_data(mux, data, *CSM, false);
//             cout << "got a timeout\n";
            break;
        case FIN_WAIT1:
            //We sent our FIN, waiting for an ack or FINACK that we didnt get, resend FIN
            make_packet(resend, *CSM, FIN, 0, true);
            MinetSend(mux, resend);
            break;
        case FIN_WAIT2:
            //no timeout here, you got a FINACK or FIN from the other side and send an ACK, you dont expect a response
            break;
        case LAST_ACK:
            //no timeout here, we already deleted the connection from the list
            break;
        case TIME_WAIT:
            //this is when time wait ends, its not an actual message timeout
            CSM->state.SetState(CLOSED);
            clist.erase(CSM);
            break;
        default:
            break;
    }
}
