/* enet.cc -- node.js to enet wrapper.
   Copyright (C) 2011 Memeo, Inc. */
   
#include <enet/enet.h>
#include <cstring>
#include <nan.h>

using namespace v8;

#define MY_NODE_DEFINE_CONSTANT(target, name, value)                            \
       (target)->Set(NanNew<String>(name),                               \
                     NanNew<v8::Integer>((int)value),                                   \
                     static_cast<v8::PropertyAttribute>(v8::ReadOnly|v8::DontDelete))

namespace enet
{
    
class Host;
class Peer;

class Packet : public node::ObjectWrap
{
private:
    friend class Host;
    friend class Peer;
    ENetPacket *packet;
    bool isSent;
    
public:
    Packet(const void *data, const size_t dataLength, enet_uint32 flags)
        : isSent(false)
    {
        packet = enet_packet_create(data, dataLength, flags);
    }
    
    Packet(enet_uint32 flags)
        : isSent(false)
    {
        packet = enet_packet_create(NULL, 0, flags);
    }
    
    Packet() : packet(0), isSent(false)
    {
    
    }
    
    ~Packet()
    {
        SetPacket(NULL);
    }
    
    void SetPacket( ENetPacket* p )
    {
    	if (packet && !isSent)
        {
            enet_packet_destroy(packet);
        }
        packet = p;
        isSent = false;
    }
    
    static v8::Persistent<v8::FunctionTemplate> s_ct;

    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = NanNew<v8::FunctionTemplate>(New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(NanNew<String>("Packet"));
        NODE_SET_PROTOTYPE_METHOD(t, "data", Data);
        NODE_SET_PROTOTYPE_METHOD(t, "setData", SetData);
        NODE_SET_PROTOTYPE_METHOD(t, "flags", Flags);
        NODE_SET_PROTOTYPE_METHOD(t, "setFlags", SetFlags);
        NODE_SET_PROTOTYPE_METHOD(t, "destroy", Destroy);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_RELIABLE", ENET_PACKET_FLAG_RELIABLE);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_UNSEQUENCED", ENET_PACKET_FLAG_UNSEQUENCED);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_NO_ALLOCATE", ENET_PACKET_FLAG_NO_ALLOCATE);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_UNRELIABLE_FRAGMENT", ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT);
        target->Set(NanNew<String>("Packet"), t->GetFunction());
        NanAssignPersistent(s_ct,t);
    }
    
    static NAN_METHOD(New)
    {
        Packet *packet = NULL;
        enet_uint32 flags = 0;
        if (args.Length() > 1)
        {
            if (args[0]->IsInt32())
            {
                flags = (enet_uint32) args[0]->Int32Value();
            }
            else if (args[0]->IsUint32())
            {
                flags = args[0]->Uint32Value();
            }
        }
        if (args.Length() > 0)
        {
            if (args[0]->IsObject())
            {
                // Assume it is a Buffer.
                size_t length = node::Buffer::Length(args[0]->ToObject());
                packet = new Packet(node::Buffer::Data(args[0]->ToObject()), length, flags);
            }
            else if (args[0]->IsString())
            {
                v8::String::Utf8Value utf8(args[0]);
                packet = new Packet(*utf8, utf8.length(), flags);
            }
        }
        if (args.Length() == 0)
        {
            packet = new Packet();
        }
        
        if (packet != NULL)
        {
            packet->Wrap(args.This());
        }
        NanReturnValue(args.This());
    }
    
    static v8::Handle<v8::Value> WrapPacket(ENetPacket *p)
    {
        v8::Local<v8::Object> o = NanNew(s_ct)->InstanceTemplate()->NewInstance();
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(o);
        packet->SetPacket(p);
        return o;
    }
    
    static NAN_METHOD(Data)
    {
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args.This());
        if (packet->isSent)
        {
            NanThrowError("packet has been sent and is now invalid");
        }
        NanReturnValue( NanNewBufferHandle((char*)packet->packet->data, packet->packet->dataLength) );
    }
    
    static NAN_METHOD(Flags)
    {
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args.This());
        if (packet->isSent)
        {
            NanThrowError("packet has been sent and is now invalid");
        }
        NanReturnValue( NanNew<Uint32>(packet->packet->flags));
    }
    
    static NAN_METHOD(SetData)
    {
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args.This());
        if (packet->isSent)
        {
            NanThrowError("packet has been sent and is now invalid");
        }
        if (args.Length() > 0)
        {
            if (args[0]->IsObject())
            {
                // Assume it is a Buffer.
                size_t length = node::Buffer::Length(args[0]->ToObject());
                enet_packet_resize(packet->packet, length);
                ::memcpy(packet->packet->data, node::Buffer::Data(args[0]->ToObject()), length);
            }
            else if (args[0]->IsString())
            {
                v8::String::Utf8Value utf8(args[0]);
                enet_packet_resize(packet->packet, utf8.length());
                ::memcpy(packet->packet->data, *utf8, utf8.length());
            }
        }
        else
        {
            enet_packet_resize(packet->packet, 0);
        }
        NanReturnValue(args.This());
    }
    
    static NAN_METHOD(SetFlags)
    {
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args.This());
        if (packet->isSent)
        {
            NanThrowError("packet has been sent and is now invalid");
        }
        if (args.Length() > 0)
        {
            if (args[0]->IsInt32())
            {
                packet->packet->flags = (enet_uint32) args[0]->Int32Value();
            }
            else if (args[0]->IsUint32())
            {
                packet->packet->flags = args[0]->Uint32Value();
            }
        }
        NanReturnValue(args.This());
    }
   
    static NAN_METHOD(Destroy)
    {
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args.This());
        packet->SetPacket(0);
        NanReturnValue(args.This());
    }    
};

class Address: public node::ObjectWrap
{
private:
    friend class Host;
    ENetAddress address;
    
public:
    Address()
    {
        ::memset(&address, 0, sizeof(ENetAddress));
    }
    
    Address(uint32_t host, enet_uint16 port)
    {
        address.host = host;
        address.port = port;
    }
    
    Address(const char *addrstr)
    {
        char *s = ::strdup(addrstr);
        char *chr = ::strrchr(s, ':');
        if (chr != NULL)
        {
            *chr = '\0';
            address.port = atoi(chr + 1);
        }
        enet_address_set_host(&address, (const char *) s);
        ::free(s);
    }
    
    Address(const char *addrstr, enet_uint16 port)
    {
        enet_address_set_host(&address, addrstr);
        address.port = port;        
    }
    
    Address(ENetAddress addr) : address(addr) { }
    
    Address(Address *addr) : address(addr->address) { }
    
    static v8::Persistent<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = NanNew<v8::FunctionTemplate>(New);
        
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(NanNew<String>("Address"));
        // host -- the IP address, as an integer.
        NODE_SET_PROTOTYPE_METHOD(t, "host", Host);
        NODE_SET_PROTOTYPE_METHOD(t, "setHost", SetHost);
        // port -- the port number as an integer.
        NODE_SET_PROTOTYPE_METHOD(t, "port", Port);
        NODE_SET_PROTOTYPE_METHOD(t, "setPort", SetPort);
        // hostname -- the hostname associated with the address, if any
        // set looks up the address via DNS
        NODE_SET_PROTOTYPE_METHOD(t, "hostname", Hostname);
        NODE_SET_PROTOTYPE_METHOD(t, "setHostname", SetHostname);
        // address -- the IP address in dotted-decimal format
        NODE_SET_PROTOTYPE_METHOD(t, "address", GetAddress);
        NODE_SET_PROTOTYPE_METHOD(t, "setAddress", SetHostname); // uses the same function internally.
        MY_NODE_DEFINE_CONSTANT(t, "HOST_ANY", ENET_HOST_ANY);
        MY_NODE_DEFINE_CONSTANT(t, "HOST_BROADCAST", ENET_HOST_BROADCAST);
        MY_NODE_DEFINE_CONSTANT(t, "PORT_ANY", ENET_PORT_ANY);
        target->Set(NanNew<String>("Address"), t->GetFunction());

        NanAssignPersistent(s_ct,t);
    }
    
    static NAN_METHOD(New)
    {
        Address *addr = NULL;
        if (args.Length() == 1)
        {
            if (args[0]->IsString())
            {
                NanAsciiString val(args[0]);
                addr = new Address(*val);
            }
            else if (args[0]->IsUint32())
            {
                addr = new Address(args[0]->Uint32Value(), ENET_PORT_ANY);
            }
            else if (args[0]->IsInt32())
            {
                addr = new Address((uint32_t) args[0]->Int32Value(), ENET_PORT_ANY);
            }
        }
        else if (args.Length() == 2)
        {
            if (args[0]->IsString())
            {
                NanAsciiString val(args[0]);
                if (args[1]->IsUint32())
                {
                    addr = new Address(*val, (enet_uint16) args[1]->Uint32Value());
                }
                else if (args[1]->IsInt32())
                {
                    addr = new Address(*val, (enet_uint16) args[1]->Int32Value());
                }
            }
            else if (args[0]->IsUint32())
            {
                uint32_t val = args[0]->Uint32Value();
                if (args[1]->IsUint32())
                {
                    addr = new Address(val, (enet_uint16) args[1]->Uint32Value());
                }
                else if (args[1]->IsInt32())
                {
                    addr = new Address(val, (enet_uint16) args[1]->Int32Value());
                }                
            }
        }
        else
        {
            addr = new Address();
        }
        if (addr != NULL)
        {
            addr->Wrap(args.This());
        }
        else
        {
            NanThrowError("invalid argument");
        }
        NanReturnValue(args.This());
    }
    
    static v8::Handle<v8::Value> WrapAddress(ENetAddress address)
    {
        v8::Handle<v8::Object> o = NanNew(s_ct)->InstanceTemplate()->NewInstance();
        Address *a = node::ObjectWrap::Unwrap<Address>(o);
        a->address = address;
        return o;        
    }
    
    static NAN_METHOD(Host)
    {
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        NanReturnValue( NanNew<Uint32>(address->address.host) );
    }
    
    static NAN_METHOD(Port)
    {
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        NanReturnValue( NanNew<Uint32>(address->address.port) );
    }
    
    static NAN_METHOD(Hostname)
    {
        char buffer[256];
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        if (enet_address_get_host(&(address->address), buffer, 256) == 0) {
            NanReturnValue(NanNew<String>(buffer));
        }
        NanReturnNull();
    }
    
    static NAN_METHOD(GetAddress)
    {
        char buffer[256];
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        if (enet_address_get_host_ip(&(address->address), buffer, 256) == 0) {
            NanReturnValue(NanNew<String>(buffer));
        }
        NanReturnNull();       
    }
    
    static NAN_METHOD(SetHost)
    {
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        if (args[0]->IsUint32())
        {
            address->address.host = args[0]->Uint32Value();
        }
        NanReturnValue(args.This());
    }

    static NAN_METHOD(SetPort)
    {
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        if (args[0]->IsInt32())
        {
            address->address.port = (enet_uint16) args[0]->Int32Value();
        }
        NanReturnValue(args.This());
    }
    
    static NAN_METHOD(SetHostname)
    {
        Address *address = node::ObjectWrap::Unwrap<Address>(args.This());
        bool success = false;
        if (args[0]->IsString())
        {
            v8::String::Utf8Value utf8(args[0]);
            if (enet_address_set_host(&(address->address), *utf8) == 0)
                success = true;
        }
        NanReturnValue(NanNew<Boolean>(success));
    }
};

class Peer : public node::ObjectWrap
{
private:
     ENetPeer *peer;

public:
    Peer(ENetPeer *peer) : peer(peer) { }
    
    ~Peer() { }
    
    static v8::Persistent<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = NanNew<v8::FunctionTemplate>();
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(NanNew<String>("Peer"));
        NODE_SET_PROTOTYPE_METHOD(t, "send", Send);
        NODE_SET_PROTOTYPE_METHOD(t, "receive", Receive);
        NODE_SET_PROTOTYPE_METHOD(t, "reset", Reset);
        NODE_SET_PROTOTYPE_METHOD(t, "ping", Ping);
        NODE_SET_PROTOTYPE_METHOD(t, "disconnectNow", DisconnectNow);
        NODE_SET_PROTOTYPE_METHOD(t, "disconnect", Disconnect);
        NODE_SET_PROTOTYPE_METHOD(t, "disconnectLater", DisconnectLater);
        NODE_SET_PROTOTYPE_METHOD(t, "address", GetAddress);
        NODE_SET_PROTOTYPE_METHOD(t, "data", GetData);
        NODE_SET_PROTOTYPE_METHOD(t, "setData", SetData);
        target->Set(NanNew<String>("Peer"), t->GetFunction());

        NanAssignPersistent(s_ct, t);
    }
    
    static NAN_METHOD(New)
    {
        Peer *peer = new Peer(NULL);
        peer->Wrap(args.This());
        NanReturnValue(args.This());
    }
    
    static v8::Handle<v8::Value> WrapPeer(ENetPeer *p)
    {
        Peer *peer = new Peer(p);
        v8::Local<v8::Object> o = NanNew(s_ct)->InstanceTemplate()->NewInstance();
        peer->Wrap(o);
        return o;
    }
    
    static NAN_METHOD(Send)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        if (args.Length() != 2 || !args[0]->IsInt32() || !args[1]->IsObject())
        {
            NanThrowError("send requires two arguments, channel number, packet");
        }
        enet_uint8 channel = (enet_uint8) args[0]->Int32Value();
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args[1]->ToObject());
        if (enet_peer_send(peer->peer, channel, packet->packet) < 0)
        {
            NanThrowError("enet.Peer.send error");
        }
        packet->isSent = true;
        NanReturnNull();
    }
    
    static NAN_METHOD(Receive)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        enet_uint8 channelID = 0;
        v8::Local<v8::Array> result = NanNew<Array>(2);
        ENetPacket *packet = enet_peer_receive(peer->peer, &channelID);
        if (packet == NULL)
            NanReturnNull();
        result->Set(0, NanNew<v8::Int32>(channelID));
        v8::Handle<v8::Value> wrapper = Packet::WrapPacket(packet);
        result->Set(1, wrapper);
        NanReturnValue(result);
    }
    
    static NAN_METHOD(Reset)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        enet_peer_reset(peer->peer);
        NanReturnNull();
    }
    
    static NAN_METHOD(Ping)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        enet_peer_ping(peer->peer);
       NanReturnNull();     
    }
    
    static NAN_METHOD(DisconnectNow)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        enet_uint32 data = 0;
        if (args.Length() > 0)
            data = args[0]->Uint32Value();
        enet_peer_disconnect_now(peer->peer, data);
        NanReturnNull();
    }

    static NAN_METHOD(Disconnect)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        enet_uint32 data = 0;
        if (args.Length() > 0)
            data = args[0]->Uint32Value();
        enet_peer_disconnect(peer->peer, data);
        NanReturnNull();     
    }

    static NAN_METHOD(DisconnectLater)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        enet_uint32 data = 0;
        if (args.Length() > 0)
            data = args[0]->Uint32Value();
        enet_peer_disconnect_later(peer->peer, data);
        NanReturnNull();     
    }
    
    static NAN_METHOD(GetAddress)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        NanReturnValue(Address::WrapAddress(peer->peer->address));
    }
    
    static NAN_METHOD(GetData)
    {
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        
        void* p = peer->peer->data;
        uint32_t* pp = (uint32_t*)&p;
        
        NanReturnValue(NanNew<v8::Uint32>( *pp ) );
    }
    
    static NAN_METHOD(SetData)
    {
        uint32_t data = 0;
        if (args.Length() > 0)
            data = args[0]->Uint32Value();
            
        Peer *peer = node::ObjectWrap::Unwrap<Peer>(args.This());
        peer->peer->data = reinterpret_cast<void*>(data);
        NanReturnNull();     
    }
};

class Event : public node::ObjectWrap
{
private:
    ENetEvent event;
    
public:
    Event(ENetEvent event) : event(event)
    {
    }
    
    static v8::Persistent<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = NanNew<v8::FunctionTemplate>();
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(NanNew<String>("Event"));
        NODE_SET_PROTOTYPE_METHOD(t, "type", Type);
        NODE_SET_PROTOTYPE_METHOD(t, "peer", GetPeer);
        NODE_SET_PROTOTYPE_METHOD(t, "channelID", ChannelID);
        NODE_SET_PROTOTYPE_METHOD(t, "data", Data);
        NODE_SET_PROTOTYPE_METHOD(t, "packet", GetPacket);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_NONE", ENET_EVENT_TYPE_NONE);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_CONNECT", ENET_EVENT_TYPE_CONNECT);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_DISCONNECT", ENET_EVENT_TYPE_DISCONNECT);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_RECEIVE", ENET_EVENT_TYPE_RECEIVE);
        target->Set(NanNew<String>("Event"), t->GetFunction());
        NanAssignPersistent(s_ct, t);
    }
    
    static v8::Handle<v8::Value> WrapEvent(ENetEvent e)
    {
        Event *event = new Event(e);
        v8::Handle<v8::Object> o = NanNew(s_ct)->InstanceTemplate()->NewInstance();
        event->Wrap(o);
        return o;
    }
    
    static NAN_METHOD(Type)
    {
        Event *e = node::ObjectWrap::Unwrap<Event>(args.This());
        NanReturnValue(NanNew<v8::Int32>(e->event.type));
    }
    
    static NAN_METHOD(GetPeer)
    {
        Event *e = node::ObjectWrap::Unwrap<Event>(args.This());
        if (e->event.peer == NULL)
            NanReturnNull();
        NanReturnValue(Peer::WrapPeer(e->event.peer));
    }
    
    static NAN_METHOD(ChannelID)
    {
        Event *e = node::ObjectWrap::Unwrap<Event>(args.This());
        NanReturnValue(NanNew<v8::Int32>(e->event.channelID));        
    }
    
    static NAN_METHOD(Data)
    {
        Event *e = node::ObjectWrap::Unwrap<Event>(args.This());
        NanReturnValue(NanNew<v8::Uint32>(e->event.data));     
    }
    
    static NAN_METHOD(GetPacket)
    {
        Event *e = node::ObjectWrap::Unwrap<Event>(args.This());
        if (e->event.packet == NULL){
            NanReturnNull();
        }
        NanReturnValue(Packet::WrapPacket(e->event.packet));
    }
};

class Host : public node::ObjectWrap
{
private:
    ENetHost *host;
    Address *address;
    size_t peerCount;
    size_t channelLimit;
    enet_uint32 incomingBandwidth;
    enet_uint32 outgoingBandwidth;
    
public:
    Host(Address *address_, size_t peerCount, size_t channelLimit, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth)
        : address(0), peerCount(peerCount), channelLimit(channelLimit),
          incomingBandwidth(incomingBandwidth), outgoingBandwidth(outgoingBandwidth)
    {
        ENetAddress *addr = NULL;
        if (address_ != NULL)
        {
            addr = &(address_->address);
            address = new Address(*addr);
        }
        host = enet_host_create(addr, peerCount, channelLimit, incomingBandwidth, outgoingBandwidth);
        if (host == NULL)
        {
            throw "failed to create host";
        }
    }
    
    ~Host()
    {
        enet_host_destroy(host);
        if (address != NULL)
        {
            delete address;
        }
    }
    
    static v8::Persistent<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = NanNew<v8::FunctionTemplate>(New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(NanNew<String>("Host"));
        NODE_SET_PROTOTYPE_METHOD(t, "connect", Connect);
        NODE_SET_PROTOTYPE_METHOD(t, "broadcast", Broadcast);
        NODE_SET_PROTOTYPE_METHOD(t, "address", GetAddress);
        NODE_SET_PROTOTYPE_METHOD(t, "peerCount", PeerCount);
        NODE_SET_PROTOTYPE_METHOD(t, "channelLimit", ChannelLimit);
        NODE_SET_PROTOTYPE_METHOD(t, "setChannelLimit", SetChannelLimit);
        NODE_SET_PROTOTYPE_METHOD(t, "incomingBandwidth", IncomingBandwidth);
        NODE_SET_PROTOTYPE_METHOD(t, "outgoingBandwidth", OutgoingBandwidth);
        NODE_SET_PROTOTYPE_METHOD(t, "setBandwidthLimit", SetBandwidthLimit);
        NODE_SET_PROTOTYPE_METHOD(t, "flush", Flush);
        NODE_SET_PROTOTYPE_METHOD(t, "checkEvents", CheckEvents);
        NODE_SET_PROTOTYPE_METHOD(t, "service", Service);
        NODE_SET_PROTOTYPE_METHOD(t, "fd", FD);
        NODE_SET_PROTOTYPE_METHOD(t, "compress", Compress);
        target->Set(NanNew<String>("Host"), t->GetFunction());
        NanAssignPersistent(s_ct, t);
    }
    
    static NAN_METHOD(New)
    {
        if (args.Length() < 2)
            NanThrowError("constructor takes at least two arguments");
        Address *addr = node::ObjectWrap::Unwrap<Address>(args[0]->ToObject());
        size_t peerCount = args[1]->Int32Value();
        size_t channelCount = 0;
        enet_uint32 incomingBW = 0;
        enet_uint32 outgoingBW = 0;
        if (args.Length() > 2)
            channelCount = args[2]->Int32Value();
        if (args.Length() > 3)
            incomingBW = args[3]->Uint32Value();
        if (args.Length() > 4)
            outgoingBW = args[4]->Uint32Value();
        try
        {
            Host *host = new Host(addr, peerCount, channelCount, incomingBW, outgoingBW);
            host->Wrap(args.This());
            NanReturnValue(args.This());
        }
        catch (...)
        {
            NanThrowError("could not create host");
        }
    }

    static NAN_METHOD(Connect)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        if (args.Length() < 2 || !args[0]->IsObject() || !args[1]->IsInt32())
            NanThrowError("invalid argument");
        Address *address = node::ObjectWrap::Unwrap<Address>(args[0]->ToObject());
        size_t channelCount = args[1]->Int32Value();
        enet_uint32 data = 0;
        if (args.Length() > 2)
        {
            if (!args[2]->IsUint32())
                NanThrowError("invalid data argument");
            data = args[2]->Uint32Value();
        }
        ENetPeer *ep = enet_host_connect(host->host,
            (const ENetAddress *) &(address->address), channelCount, data);
        if (ep == NULL) {
            NanReturnNull();
        }
        NanReturnValue(Peer::WrapPeer(ep));
    }
    
    static NAN_METHOD(Broadcast)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        enet_uint8 channelID = args[0]->Int32Value();
        Packet *packet = node::ObjectWrap::Unwrap<Packet>(args[1]->ToObject());
        enet_host_broadcast(host->host, channelID, packet->packet);
    }
    
    static NAN_METHOD(GetAddress)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        v8::Handle<v8::Value> result = Address::WrapAddress(host->address->address);
        NanReturnValue(result);
    }
    
    static NAN_METHOD(PeerCount)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        NanReturnValue(NanNew<Int32>( (int32_t)host->peerCount));
    }

    static NAN_METHOD(ChannelLimit)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        NanReturnValue(NanNew<Int32>( (int32_t) host->channelLimit));
    }
    
    static NAN_METHOD(SetChannelLimit)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        size_t newLimit = args[0]->Int32Value();
        enet_host_channel_limit(host->host, newLimit);
        host->channelLimit = newLimit;
    }

    static NAN_METHOD(IncomingBandwidth)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        NanReturnValue(NanNew<Uint32>(host->incomingBandwidth));
    }

    static NAN_METHOD(OutgoingBandwidth)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        NanReturnValue(NanNew<Uint32>(host->outgoingBandwidth));
    }
    
    static NAN_METHOD(SetBandwidthLimit)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        enet_uint32 inbw = args[0]->Uint32Value();
        enet_uint32 outbw = args[1]->Uint32Value();
        enet_host_bandwidth_limit(host->host, inbw, outbw);
        host->incomingBandwidth = inbw;
        host->outgoingBandwidth = outbw;
    }
    
    static NAN_METHOD(Flush)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        enet_host_flush(host->host);
    }
    
    static NAN_METHOD(CheckEvents)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        ENetEvent event;
        int ret = enet_host_check_events(host->host, &event);
        if (ret < 0)
            NanThrowError("error checking events");
        if (ret < 1)
            NanReturnNull();
        v8::Handle<v8::Value> result = Event::WrapEvent(event);
        NanReturnValue(result);
    }
    
    static NAN_METHOD(Service)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        enet_uint32 timeout = 0;
        if (args.Length() > 0)
            timeout = args[0]->Uint32Value();
        ENetEvent event;
        int ret = enet_host_service(host->host, &event, timeout);
        if (ret < 0)
            NanThrowError("error servicing host");
        if (ret < 1)
            NanReturnNull();
        v8::Handle<v8::Value> result = Event::WrapEvent(event);
        NanReturnValue(result); 
    }
    
    static NAN_METHOD(FD)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        NanReturnValue(NanNew<Int32>(host->host->socket));
    }
    
    static NAN_METHOD(Compress)
    {
        Host *host = node::ObjectWrap::Unwrap<Host>(args.This());
        int ret = enet_host_compress_with_range_coder(host->host);
        if (ret < 0)
            NanThrowError("error setting up compressor");
        NanReturnValue(NanNew<Int32>(ret));
    }

};

}

v8::Persistent<v8::FunctionTemplate> enet::Packet::s_ct;
v8::Persistent<v8::FunctionTemplate> enet::Address::s_ct;
v8::Persistent<v8::FunctionTemplate> enet::Peer::s_ct;
v8::Persistent<v8::FunctionTemplate> enet::Event::s_ct;
v8::Persistent<v8::FunctionTemplate> enet::Host::s_ct;

extern "C"
{
    void init(v8::Handle<v8::Object> target)
    {
        enet::Packet::Init(target);
        enet::Address::Init(target);
        enet::Event::Init(target);
        enet::Host::Init(target);
        enet::Peer::Init(target);
        
        enet_initialize();
    }
    
    NODE_MODULE(enetnative, init);
}