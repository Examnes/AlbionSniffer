#if !defined(SNIFFER_H)
#define SNIFFER_H
#include <pcap.h>
#include <functional>
#include <vector>

typedef std::function<void(const uint8_t *)> external_hendler;

void packet_handler(u_char *args, const pcap_pkthdr *, const u_char *packet);

class sniffer
{
private:
    pcap_t *cap_handler;
    char errbuf[PCAP_ERRBUF_SIZE];

    
    external_hendler handler;
public:
    sniffer(external_hendler callback);
    void start();
    ~sniffer();
};

#endif // SNIFFER_H
