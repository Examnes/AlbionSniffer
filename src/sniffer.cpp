#include "sniffer.h"

sniffer::sniffer(std::function<void(const uint8_t *)> callback)
{
    handler = callback;
}

sniffer::~sniffer()
{
}

void packet_handler(u_char *args, const pcap_pkthdr *, const u_char *packet)
{
    (*reinterpret_cast<external_hendler *>(args))(packet);
}

void sniffer::start()
{
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char dev[] = "enp0s31f6";
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    cap_handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (cap_handler == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    struct bpf_program fp;
    char filter_exp[] = "udp and (port 5055 or port 4535 or port 5056)";
    if (pcap_compile(cap_handler, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(cap_handler));
        exit(2);
    }

    if (pcap_setfilter(cap_handler, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(cap_handler));
        exit(2);
    }

    pcap_loop(cap_handler, -1, (pcap_handler)&packet_handler, (u_char*)&handler);
}