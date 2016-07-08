/* enet.cc -- node.js to enet wrapper.
   Copyright (C) 2011 Memeo, Inc. */
   
#include <enet/enet.h>
#include <cstring>
#include <nan.h>

using namespace v8;

#define MY_NODE_DEFINE_CONSTANT(target, name, value)                            \
       (target)->Set(Nan::New<String>(name).ToLocalChecked(),                               \
                     Nan::New<v8::Integer>((int)value),                                   \
                     static_cast<v8::PropertyAttribute>(v8::ReadOnly|v8::DontDelete))

namespace enet
{
    
class Host;
class Peer;

class Packet : public Nan::ObjectWrap
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
    
    static Nan::Global<v8::FunctionTemplate> s_ct;

    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = Nan::New<v8::FunctionTemplate>(New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(Nan::New<String>("Packet").ToLocalChecked());
        Nan::SetPrototypeMethod(t, "data", Data);
        Nan::SetPrototypeMethod(t, "setData", SetData);
        Nan::SetPrototypeMethod(t, "flags", Flags);
        Nan::SetPrototypeMethod(t, "setFlags", SetFlags);
        Nan::SetPrototypeMethod(t, "destroy", Destroy);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_RELIABLE", ENET_PACKET_FLAG_RELIABLE);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_UNSEQUENCED", ENET_PACKET_FLAG_UNSEQUENCED);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_NO_ALLOCATE", ENET_PACKET_FLAG_NO_ALLOCATE);
        MY_NODE_DEFINE_CONSTANT(t, "FLAG_UNRELIABLE_FRAGMENT", ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT);
        Nan::Set(target, Nan::New<String>("Packet").ToLocalChecked(), Nan::GetFunction(t).ToLocalChecked());
        s_ct.Reset(t);
    }
    
    static NAN_METHOD(New)
    {
        Packet *packet = NULL;
        enet_uint32 flags = 0;
        if (info.Length() > 1)
        {
            if (info[0]->IsInt32())
            {
                flags = (enet_uint32)info[0]->ToInt32()->Value();
            }
            else if (info[0]->IsUint32())
            {
                flags = (enet_uint32)info[0]->ToUint32()->Value();;
            }
        }
        if (info.Length() > 0)
        {
            if (info[0]->IsObject())
            {
                // Assume it is a Buffer.
                size_t length = node::Buffer::Length(info[0]->ToObject());
                packet = new Packet(node::Buffer::Data(info[0]->ToObject()), length, flags);
            }
            else if (info[0]->IsString())
            {
                v8::String::Utf8Value utf8(info[0]);
                packet = new Packet(*utf8, utf8.length(), flags);
            }
        }
        if (info.Length() == 0)
        {
            packet = new Packet();
        }
        
        if (packet != NULL)
        {
            packet->Wrap(info.This());
        }
        info.GetReturnValue().Set(info.This());
    }
    
    static v8::Handle<v8::Value> WrapPacket(ENetPacket *p)
    {
        v8::Local<v8::Object> o = Nan::NewInstance(Nan::New(s_ct)->InstanceTemplate()).ToLocalChecked();
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(o);
        packet->SetPacket(p);
        return o;
    }
    
    static NAN_METHOD(Data)
    {
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info.This());
        if (packet->isSent)
        {
            Nan::ThrowError("packet has been sent and is now invalid");
        }
        info.GetReturnValue().Set( Nan::NewBuffer((char*)packet->packet->data, packet->packet->dataLength).ToLocalChecked() );
    }
    
    static NAN_METHOD(Flags)
    {
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info.This());
        if (packet->isSent)
        {
            Nan::ThrowError("packet has been sent and is now invalid");
        }
        info.GetReturnValue().Set( Nan::New<Uint32>(packet->packet->flags));
    }
    
    static NAN_METHOD(SetData)
    {
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info.This());
        if (packet->isSent)
        {
            Nan::ThrowError("packet has been sent and is now invalid");
        }
        if (info.Length() > 0)
        {
            if (info[0]->IsObject())
            {
                // Assume it is a Buffer.
                size_t length = node::Buffer::Length(info[0]->ToObject());
                enet_packet_resize(packet->packet, length);
                ::memcpy(packet->packet->data, node::Buffer::Data(info[0]->ToObject()), length);
            }
            else if (info[0]->IsString())
            {
                v8::String::Utf8Value utf8(info[0]);
                enet_packet_resize(packet->packet, utf8.length());
                ::memcpy(packet->packet->data, *utf8, utf8.length());
            }
        }
        else
        {
            enet_packet_resize(packet->packet, 0);
        }
        info.GetReturnValue().Set(info.This());
    }
    
    static NAN_METHOD(SetFlags)
    {
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info.This());
        if (packet->isSent)
        {
            Nan::ThrowError("packet has been sent and is now invalid");
        }
        if (info.Length() > 0)
        {
            if (info[0]->IsInt32())
            {
                packet->packet->flags = (enet_uint32)(info[0]->ToInt32()->Value());
            }
            else if (info[0]->IsUint32())
            {
                packet->packet->flags = (enet_uint32)(info[0]->ToUint32()->Value());
            }
        }
        info.GetReturnValue().Set(info.This());
    }
   
    static NAN_METHOD(Destroy)
    {
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info.This());
        packet->SetPacket(0);
        info.GetReturnValue().Set(info.This());
    }    
};

class Address: public Nan::ObjectWrap
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
    
    static Nan::Global<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = Nan::New<v8::FunctionTemplate>(New);
        
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(Nan::New<String>("Address").ToLocalChecked());
        // host -- the IP address, as an integer.
        Nan::SetPrototypeMethod(t, "host", Host);
        Nan::SetPrototypeMethod(t, "setHost", SetHost);
        // port -- the port number as an integer.
        Nan::SetPrototypeMethod(t, "port", Port);
        Nan::SetPrototypeMethod(t, "setPort", SetPort);
        // hostname -- the hostname associated with the address, if any
        // set looks up the address via DNS
        Nan::SetPrototypeMethod(t, "hostname", Hostname);
        Nan::SetPrototypeMethod(t, "setHostname", SetHostname);
        // address -- the IP address in dotted-decimal format
        Nan::SetPrototypeMethod(t, "address", GetAddress);
        Nan::SetPrototypeMethod(t, "setAddress", SetHostname); // uses the same function internally.
        MY_NODE_DEFINE_CONSTANT(t, "HOST_ANY", ENET_HOST_ANY);
        MY_NODE_DEFINE_CONSTANT(t, "HOST_BROADCAST", ENET_HOST_BROADCAST);
        MY_NODE_DEFINE_CONSTANT(t, "PORT_ANY", ENET_PORT_ANY);
        Nan::Set(target, Nan::New<String>("Address").ToLocalChecked(), Nan::GetFunction(t).ToLocalChecked());

        s_ct.Reset(t);
    }
    
    static NAN_METHOD(New)
    {
        Address *addr = NULL;
        if (info.Length() == 1)
        {
            if (info[0]->IsString())
            {
                Nan::Utf8String val(info[0]);
                addr = new Address(*val);
            }
            else if (info[0]->IsUint32())
            {
                addr = new Address((uint32_t)info[0]->ToUint32()->Value(), ENET_PORT_ANY);
            }
            else if (info[0]->IsInt32())
            {
                addr = new Address((uint32_t)info[0]->ToInt32()->Value(), ENET_PORT_ANY);
            }
        }
        else if (info.Length() == 2)
        {
            if (info[0]->IsString())
            {
                Nan::Utf8String val(info[0]);
                if (info[1]->IsUint32())
                {
                    addr = new Address(*val, (enet_uint16)(info[1]->ToUint32()->Value()));
                }
                else if (info[1]->IsInt32())
                {
                    addr = new Address(*val, (enet_uint16)(info[1]->ToInt32()->Value()));
                }
            }
            else if (info[0]->IsUint32())
            {
                uint32_t val = (uint32_t)(info[0]->ToUint32()->Value());
                if (info[1]->IsUint32())
                {
                    addr = new Address(val, (enet_uint16)(info[1]->ToUint32()->Value()));
                }
                else if (info[1]->IsInt32())
                {
                    addr = new Address(val, (enet_uint16)(info[1]->ToInt32()->Value()));
                }                
            }
        }
        else
        {
            addr = new Address();
        }
        if (addr != NULL)
        {
            addr->Wrap(info.This());
        }
        else
        {
            Nan::ThrowError("invalid argument");
        }
        info.GetReturnValue().Set(info.This());
    }
    
    static v8::Handle<v8::Value> WrapAddress(ENetAddress address)
    {
        v8::Handle<v8::Object> o = Nan::NewInstance(Nan::New(s_ct)->InstanceTemplate()).ToLocalChecked();
        Address *a = Nan::ObjectWrap::Unwrap<Address>(o);
        a->address = address;
        return o;        
    }
    
    static NAN_METHOD(Host)
    {
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        info.GetReturnValue().Set( Nan::New<Uint32>(address->address.host) );
    }
    
    static NAN_METHOD(Port)
    {
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        info.GetReturnValue().Set( Nan::New<Uint32>(address->address.port) );
    }
    
    static NAN_METHOD(Hostname)
    {
        char buffer[256];
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        if (enet_address_get_host(&(address->address), buffer, 256) == 0) {
            info.GetReturnValue().Set(Nan::New<String>(buffer).ToLocalChecked());
        }
        info.GetReturnValue().SetNull();
    }
    
    static NAN_METHOD(GetAddress)
    {
        char buffer[256];
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        if (enet_address_get_host_ip(&(address->address), buffer, 256) == 0) {
            info.GetReturnValue().Set(Nan::New<String>(buffer).ToLocalChecked());
        }
        info.GetReturnValue().SetNull();       
    }
    
    static NAN_METHOD(SetHost)
    {
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        if (info[0]->IsUint32())
        {
            address->address.host = info[0]->ToUint32()->Value();
        }
        info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(SetPort)
    {
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        if (info[0]->IsInt32())
        {
            address->address.port = (enet_uint16)info[0]->ToInt32()->Value();
        }
        info.GetReturnValue().Set(info.This());
    }
    
    static NAN_METHOD(SetHostname)
    {
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info.This());
        bool success = false;
        if (info[0]->IsString())
        {
            v8::String::Utf8Value utf8(info[0]);
            if (enet_address_set_host(&(address->address), *utf8) == 0)
                success = true;
        }
        info.GetReturnValue().Set(Nan::New<Boolean>(success));
    }
};

class Peer : public Nan::ObjectWrap
{
private:
     ENetPeer *peer;

public:
    Peer(ENetPeer *peer) : peer(peer) { }
    
    ~Peer() { }
    
    static Nan::Global<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = Nan::New<v8::FunctionTemplate>();
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(Nan::New<String>("Peer").ToLocalChecked());
        Nan::SetPrototypeMethod(t, "send", Send);
        Nan::SetPrototypeMethod(t, "receive", Receive);
        Nan::SetPrototypeMethod(t, "reset", Reset);
        Nan::SetPrototypeMethod(t, "ping", Ping);
        Nan::SetPrototypeMethod(t, "disconnectNow", DisconnectNow);
        Nan::SetPrototypeMethod(t, "disconnect", Disconnect);
        Nan::SetPrototypeMethod(t, "disconnectLater", DisconnectLater);
        Nan::SetPrototypeMethod(t, "address", GetAddress);
        Nan::SetPrototypeMethod(t, "data", GetData);
        Nan::SetPrototypeMethod(t, "setData", SetData);
        Nan::Set(target, Nan::New<String>("Peer").ToLocalChecked(), Nan::GetFunction(t).ToLocalChecked());

        s_ct.Reset(t);
    }
    
    static NAN_METHOD(New)
    {
        Peer *peer = new Peer(NULL);
        peer->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }
    
    static v8::Handle<v8::Value> WrapPeer(ENetPeer *p)
    {
        Peer *peer = new Peer(p);
        v8::Local<v8::Object> o = Nan::NewInstance(Nan::New(s_ct)->InstanceTemplate()).ToLocalChecked();
        peer->Wrap(o);
        return o;
    }
    
    static NAN_METHOD(Send)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        if (info.Length() != 2 || !info[0]->IsInt32() || !info[1]->IsObject())
        {
            Nan::ThrowError("send requires two arguments, channel number, packet");
        }
        enet_uint8 channel = (enet_uint8)(info[0]->ToInt32()->Value());
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info[1]->ToObject());
        if (enet_peer_send(peer->peer, channel, packet->packet) < 0)
        {
            Nan::ThrowError("enet.Peer.send error");
        }
        packet->isSent = true;
        info.GetReturnValue().SetNull();
    }
    
    static NAN_METHOD(Receive)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        enet_uint8 channelID = 0;
        v8::Local<v8::Array> result = Nan::New<Array>(2);
        ENetPacket *packet = enet_peer_receive(peer->peer, &channelID);
        if (packet == NULL)
            info.GetReturnValue().SetNull();
        Nan::Set(result, 0, Nan::New<v8::Int32>(channelID));
        v8::Handle<v8::Value> wrapper = Packet::WrapPacket(packet);
        Nan::Set(result, 1, wrapper);
        info.GetReturnValue().Set(result);
    }
    
    static NAN_METHOD(Reset)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        enet_peer_reset(peer->peer);
        info.GetReturnValue().SetNull();
    }
    
    static NAN_METHOD(Ping)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        enet_peer_ping(peer->peer);
       info.GetReturnValue().SetNull();     
    }
    
    static NAN_METHOD(DisconnectNow)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        enet_uint32 data = 0;
        if (info.Length() > 0)
            data = (enet_uint32)info[0]->ToInt32()->Value(); 
        enet_peer_disconnect_now(peer->peer, data);
        info.GetReturnValue().SetNull();
    }

    static NAN_METHOD(Disconnect)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        enet_uint32 data = 0;
        if (info.Length() > 0)
            data = (enet_uint32)info[0]->ToInt32()->Value(); 
        enet_peer_disconnect(peer->peer, data);
        info.GetReturnValue().SetNull();     
    }

    static NAN_METHOD(DisconnectLater)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        enet_uint32 data = 0;
        if (info.Length() > 0)
            data = (enet_uint32)info[0]->ToInt32()->Value(); 
        enet_peer_disconnect_later(peer->peer, data);
        info.GetReturnValue().SetNull();     
    }
    
    static NAN_METHOD(GetAddress)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        info.GetReturnValue().Set(Address::WrapAddress(peer->peer->address));
    }
    
    static NAN_METHOD(GetData)
    {
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        
        void* p = peer->peer->data;
        uint32_t* pp = (uint32_t*)&p;
        
        info.GetReturnValue().Set(Nan::New<v8::Uint32>( *pp ) );
    }
    
    static NAN_METHOD(SetData)
    {
        uint32_t data = 0;
        if (info.Length() > 0)
            data = (enet_uint32)info[0]->ToInt32()->Value(); 
            
        Peer *peer = Nan::ObjectWrap::Unwrap<Peer>(info.This());
        peer->peer->data = reinterpret_cast<void*>(data);
        info.GetReturnValue().SetNull();     
    }
};

class Event : public Nan::ObjectWrap
{
private:
    ENetEvent event;
    
public:
    Event(ENetEvent event) : event(event)
    {
    }
    
    static Nan::Global<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = Nan::New<v8::FunctionTemplate>();
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(Nan::New<String>("Event").ToLocalChecked());
        Nan::SetPrototypeMethod(t, "type", Type);
        Nan::SetPrototypeMethod(t, "peer", GetPeer);
        Nan::SetPrototypeMethod(t, "channelID", ChannelID);
        Nan::SetPrototypeMethod(t, "data", Data);
        Nan::SetPrototypeMethod(t, "packet", GetPacket);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_NONE", ENET_EVENT_TYPE_NONE);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_CONNECT", ENET_EVENT_TYPE_CONNECT);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_DISCONNECT", ENET_EVENT_TYPE_DISCONNECT);
        MY_NODE_DEFINE_CONSTANT(t, "TYPE_RECEIVE", ENET_EVENT_TYPE_RECEIVE);
        Nan::Set(target, Nan::New<String>("Event").ToLocalChecked(), Nan::GetFunction(t).ToLocalChecked());
        s_ct.Reset(t);
    }
    
    static v8::Handle<v8::Value> WrapEvent(ENetEvent e)
    {
        Event *event = new Event(e);
        v8::Handle<v8::Object> o = Nan::NewInstance(Nan::New(s_ct)->InstanceTemplate()).ToLocalChecked();
        event->Wrap(o);
        return o;
    }
    
    static NAN_METHOD(Type)
    {
        Event *e = Nan::ObjectWrap::Unwrap<Event>(info.This());
        info.GetReturnValue().Set(Nan::New<v8::Int32>(e->event.type));
    }
    
    static NAN_METHOD(GetPeer)
    {
        Event *e = Nan::ObjectWrap::Unwrap<Event>(info.This());
        if (e->event.peer == NULL)
            info.GetReturnValue().SetNull();
        info.GetReturnValue().Set(Peer::WrapPeer(e->event.peer));
    }
    
    static NAN_METHOD(ChannelID)
    {
        Event *e = Nan::ObjectWrap::Unwrap<Event>(info.This());
        info.GetReturnValue().Set(Nan::New<v8::Int32>(e->event.channelID));        
    }
    
    static NAN_METHOD(Data)
    {
        Event *e = Nan::ObjectWrap::Unwrap<Event>(info.This());
        info.GetReturnValue().Set(Nan::New<v8::Uint32>(e->event.data));     
    }
    
    static NAN_METHOD(GetPacket)
    {
        Event *e = Nan::ObjectWrap::Unwrap<Event>(info.This());
        if (e->event.packet == NULL){
            info.GetReturnValue().SetNull();
        }
        info.GetReturnValue().Set(Packet::WrapPacket(e->event.packet));
    }
};

class Host : public Nan::ObjectWrap
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
    
    static Nan::Global<v8::FunctionTemplate> s_ct;
    
    static void Init(v8::Handle<v8::Object> target)
    {
        v8::Local<v8::FunctionTemplate> t = Nan::New<v8::FunctionTemplate>(New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(Nan::New<String>("Host").ToLocalChecked());
        Nan::SetPrototypeMethod(t, "connect", Connect);
        Nan::SetPrototypeMethod(t, "broadcast", Broadcast);
        Nan::SetPrototypeMethod(t, "address", GetAddress);
        Nan::SetPrototypeMethod(t, "peerCount", PeerCount);
        Nan::SetPrototypeMethod(t, "channelLimit", ChannelLimit);
        Nan::SetPrototypeMethod(t, "setChannelLimit", SetChannelLimit);
        Nan::SetPrototypeMethod(t, "incomingBandwidth", IncomingBandwidth);
        Nan::SetPrototypeMethod(t, "outgoingBandwidth", OutgoingBandwidth);
        Nan::SetPrototypeMethod(t, "setBandwidthLimit", SetBandwidthLimit);
        Nan::SetPrototypeMethod(t, "flush", Flush);
        Nan::SetPrototypeMethod(t, "checkEvents", CheckEvents);
        Nan::SetPrototypeMethod(t, "service", Service);
        Nan::SetPrototypeMethod(t, "fd", FD);
        Nan::SetPrototypeMethod(t, "compress", Compress);
        Nan::Set(target, Nan::New<String>("Host").ToLocalChecked(), Nan::GetFunction(t).ToLocalChecked());
        s_ct.Reset(t);
    }
    
    static NAN_METHOD(New)
    {
        if (info.Length() < 2)
            Nan::ThrowError("constructor takes at least two arguments");
        Address *addr = Nan::ObjectWrap::Unwrap<Address>(info[0]->ToObject());
        size_t peerCount = info[1]->ToInt32()->Value();
        size_t channelCount = 0;
        enet_uint32 incomingBW = 0;
        enet_uint32 outgoingBW = 0;
        if (info.Length() > 2)
            channelCount = info[2]->ToInt32()->Value();
        if (info.Length() > 3)
            incomingBW = info[3]->ToUint32()->Value();
        if (info.Length() > 4)
            outgoingBW = info[4]->ToUint32()->Value();
        try
        {
            Host *host = new Host(addr, peerCount, channelCount, incomingBW, outgoingBW);
            host->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
        }
        catch (...)
        {
            Nan::ThrowError("could not create host");
        }
    }

    static NAN_METHOD(Connect)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        if (info.Length() < 2 || !info[0]->IsObject() || !info[1]->IsInt32())
            Nan::ThrowError("invalid argument");
        Address *address = Nan::ObjectWrap::Unwrap<Address>(info[0]->ToObject());
        size_t channelCount = info[1]->ToInt32()->Value();
        enet_uint32 data = 0;
        if (info.Length() > 2)
        {
            if (!info[2]->IsUint32())
                Nan::ThrowError("invalid data argument");
            data = info[2]->ToUint32()->Value(); 
        }
        ENetPeer *ep = enet_host_connect(host->host,
            (const ENetAddress *) &(address->address), channelCount, data);
        if (ep == NULL) {
            info.GetReturnValue().SetNull();
        }
        info.GetReturnValue().Set(Peer::WrapPeer(ep));
    }
    
    static NAN_METHOD(Broadcast)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        enet_uint8 channelID = info[0]->ToInt32()->Value();
        Packet *packet = Nan::ObjectWrap::Unwrap<Packet>(info[1]->ToObject());
        enet_host_broadcast(host->host, channelID, packet->packet);
    }
    
    static NAN_METHOD(GetAddress)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        v8::Handle<v8::Value> result = Address::WrapAddress(host->address->address);
        info.GetReturnValue().Set(result);
    }
    
    static NAN_METHOD(PeerCount)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        info.GetReturnValue().Set(Nan::New<Int32>( (int32_t)host->peerCount));
    }

    static NAN_METHOD(ChannelLimit)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        info.GetReturnValue().Set(Nan::New<Int32>( (int32_t) host->channelLimit));
    }
    
    static NAN_METHOD(SetChannelLimit)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        size_t newLimit = info[0]->ToInt32()->Value();
        enet_host_channel_limit(host->host, newLimit);
        host->channelLimit = newLimit;
    }

    static NAN_METHOD(IncomingBandwidth)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        info.GetReturnValue().Set(Nan::New<Uint32>(host->incomingBandwidth));
    }

    static NAN_METHOD(OutgoingBandwidth)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        info.GetReturnValue().Set(Nan::New<Uint32>(host->outgoingBandwidth));
    }
    
    static NAN_METHOD(SetBandwidthLimit)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        enet_uint32 inbw = info[0]->ToUint32()->Value();
        enet_uint32 outbw = info[1]->ToUint32()->Value();
        enet_host_bandwidth_limit(host->host, inbw, outbw);
        host->incomingBandwidth = inbw;
        host->outgoingBandwidth = outbw;
    }
    
    static NAN_METHOD(Flush)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        enet_host_flush(host->host);
    }
    
    static NAN_METHOD(CheckEvents)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        ENetEvent event;
        int ret = enet_host_check_events(host->host, &event);
        if (ret < 0)
            Nan::ThrowError("error checking events");
        if (ret < 1)
            info.GetReturnValue().SetNull();
        v8::Handle<v8::Value> result = Event::WrapEvent(event);
        info.GetReturnValue().Set(result);
    }
    
    static NAN_METHOD(Service)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        enet_uint32 timeout = 0;
        if (info.Length() > 0)
            timeout = info[0]->ToUint32()->Value();
        ENetEvent event;
        int ret = enet_host_service(host->host, &event, timeout);
        if (ret < 0)
            Nan::ThrowError("error servicing host");
        if (ret < 1)
            info.GetReturnValue().SetNull();
        v8::Handle<v8::Value> result = Event::WrapEvent(event);
        info.GetReturnValue().Set(result); 
    }
    
    static NAN_METHOD(FD)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        info.GetReturnValue().Set(Nan::New<Int32>(host->host->socket));
    }
    
    static NAN_METHOD(Compress)
    {
        Host *host = Nan::ObjectWrap::Unwrap<Host>(info.This());
        int ret = enet_host_compress_with_range_coder(host->host);
        if (ret < 0)
            Nan::ThrowError("error setting up compressor");
        info.GetReturnValue().Set(Nan::New<Int32>(ret));
    }

};

}

Nan::Global<v8::FunctionTemplate> enet::Packet::s_ct;
Nan::Global<v8::FunctionTemplate> enet::Address::s_ct;
Nan::Global<v8::FunctionTemplate> enet::Peer::s_ct;
Nan::Global<v8::FunctionTemplate> enet::Event::s_ct;
Nan::Global<v8::FunctionTemplate> enet::Host::s_ct;

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