#include <list>

struct PortData
{
    int port;

};


class PcapClient
{
    public:
        int addPort(PortData pd);
        int delPort(int port);
        int startListen();
};