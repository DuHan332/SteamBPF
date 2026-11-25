#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// A bounded wire-format reader. Unknown fields are preserved byte for byte.
namespace bpf {
using Bytes = std::vector<uint8_t>;
constexpr size_t max_packet = 1024 * 1024;
struct Field { uint32_t number, wire; size_t start, payload, end; uint64_t value; };
inline bool varint(const uint8_t* p, size_t n, size_t& i, uint64_t& v) {
    v = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        if (i >= n) return false;
        uint8_t c = p[i++];
        if (shift == 63 && c > 1) return false;
        v |= uint64_t(c & 127) << shift;
        if (!(c & 128)) return true;
    }
    return false;
}
inline bool fields(const uint8_t* p, size_t n, std::vector<Field>& out) {
    if (n > max_packet || (!p && n)) return false;
    size_t i = 0;
    while (i < n) {
        Field f{}; f.start = i; uint64_t tag;
        if (!varint(p,n,i,tag) || !(tag >> 3) || (tag >> 3) > 0x1fffffff) return false;
        f.number = uint32_t(tag >> 3); f.wire = tag & 7; f.payload = i;
        switch (f.wire) {
        case 0: if (!varint(p,n,i,f.value)) return false; break;
        case 1: if (n-i < 8) return false; std::memcpy(&f.value,p+i,8); i+=8; break;
        case 2: {
            uint64_t length;
            if (!varint(p,n,i,length) || length > n-i) return false;
            f.payload = i; i += size_t(length); break;
        }
        case 5: if (n-i < 4) return false; std::memcpy(&f.value,p+i,4); i+=4; break;
        default: return false;
        }
        f.end = i; out.push_back(f);
        if (out.size() > 65536) return false;
    }
    return true;
}
struct Config { bool protection=false, silent=false; };
struct Packet { uint32_t type; size_t body; std::vector<Field> header; };
inline bool packet(const uint8_t* p,size_t n,Packet& v) {
    if (!p || n < 8 || n > max_packet) return false;
    uint32_t type, header;
    std::memcpy(&type,p,4); std::memcpy(&header,p+4,4);
    if (!(type & 0x80000000) || header > n-8) return false;
    v.type=type & 0x7fffffff; v.body=8+header;
    return v.type && v.type <= 20000 && fields(p+8,header,v.header);
}
inline bool rewrite(const uint8_t* p,size_t n,bool incoming,const Config& cfg,Bytes& out) {
    Packet v{};
    if (!packet(p,n,v)) return false;
    bool family=false;
    if (incoming && (cfg.protection || cfg.silent)) {
        // ServiceMethod, ServiceMethodResponse, and ServiceMethodSendToClient.
        if (v.type!=146 && v.type!=147 && v.type!=152) return false;
        for (const auto& h:v.header) if (h.number==12 && h.wire==2) {
            std::string method(reinterpret_cast<const char*>(p+8+h.payload),h.end-h.payload);
            family = method=="FamilyGroupsClient.NotifyRunningApps#1";
        }
    }
    bool games=!incoming && cfg.silent && (v.type==742 || v.type==5410);
    if (!family && !games) return false;
    std::vector<Field> body;
    if (!fields(p+v.body,n-v.body,body)) return false;
    // Validate nested records before changing anything. Malformed data passes through.
    std::vector<bool> remove;
    bool changed=false;
    for (const auto& f:body) {
        bool drop=false;
        if (family && f.number==2 && f.wire==2) {
            std::vector<Field> nested;
            if (!fields(p+v.body+f.payload,f.end-f.payload,nested)) return false;
            drop=true;
        }
        if (games && f.number==1 && f.wire==2) {
            std::vector<Field> game;
            if (!fields(p+v.body+f.payload,f.end-f.payload,game)) return false;
            drop=true;
        }
        remove.push_back(drop); changed|=drop;
    }
    if (!changed) return false;
    out.assign(p,p+v.body);
    for (size_t i=0;i<body.size();++i) if (!remove[i])
        out.insert(out.end(),p+v.body+body[i].start,p+v.body+body[i].end);
    return true;
}
}
