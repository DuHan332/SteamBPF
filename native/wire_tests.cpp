#include "wire.hpp"
#include <cstdio>
#include <stdexcept>
using bpf::Bytes;
void require(bool ok) { if (!ok) throw std::runtime_error("Protocol regression failed"); }
void integer(Bytes& out,uint64_t v) { do { auto c=uint8_t(v&127); v>>=7; out.push_back(c|(v?128:0)); } while(v); }
void nested(Bytes& out,unsigned tag,const Bytes& value) {
    integer(out,(tag<<3)|2); integer(out,value.size()); out.insert(out.end(),value.begin(),value.end());
}
Bytes packet(unsigned type,const Bytes& body,const Bytes& header={}) {
    uint32_t fields[]={type|0x80000000,uint32_t(header.size())};
    Bytes out(reinterpret_cast<uint8_t*>(fields),reinterpret_cast<uint8_t*>(fields)+8);
    out.insert(out.end(),header.begin(),header.end()); out.insert(out.end(),body.begin(),body.end()); return out;
}
int main() {
    Bytes body; nested(body,1,Bytes{0x60,0x2a}); nested(body,1,Bytes{0x60,0x2b});
    nested(body,1,Bytes{0x10,1}); // A record without an owner is also filtered in silent mode.
    body.insert(body.end(),{0x10,0x07}); // Preserve the top-level OS type.
    auto input=packet(5410,body); Bytes out;
    require(!bpf::rewrite(input.data(),input.size(),false,{},out));
    require(bpf::rewrite(input.data(),input.size(),false,{true,true},out));
    require(out==packet(5410,Bytes{0x10,0x07}));
    std::string method="FamilyGroupsClient.NotifyRunningApps#1";
    Bytes header; nested(header,12,Bytes(method.begin(),method.end()));
    Bytes family{0x08,0x2a}; nested(family,2,Bytes{0x08,0x01});
    input=packet(152,family,header);
    require(bpf::rewrite(input.data(),input.size(),true,{true,false},out));
    require(out==packet(152,Bytes{0x08,0x2a},header));
    require(!bpf::rewrite(input.data(),input.size(),false,{true,true},out));
    input=packet(152,family);
    require(!bpf::rewrite(input.data(),input.size(),true,{true,true},out));
    input=packet(999,body);
    require(!bpf::rewrite(input.data(),input.size(),false,{true,true},out));
    // Truncation, overflowing varints, and bad nested records pass through.
    input=packet(5410,Bytes{0x0a,0x05,0x60});
    require(!bpf::rewrite(input.data(),input.size(),false,{true,true},out));
    input=packet(5410,Bytes{0x0a,0x01,0x80});
    require(!bpf::rewrite(input.data(),input.size(),false,{true,true},out));
    input=packet(5410,Bytes{0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02});
    require(!bpf::rewrite(input.data(),input.size(),false,{true,true},out));
    // Every prefix of a real packet is safe to parse, whether valid or truncated.
    for (size_t n=0;n<input.size();++n) bpf::rewrite(input.data(),n,false,{true,true},out);
    std::puts("Native wire tests passed.");
}
