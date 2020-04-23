##include <list>

struct PortData
{
    int port;

};

class PcapClient
{
    std::list<PortData> portList;
    public:
        int addPort(PortData pd);
        int delPort(int port);
        int startListen();
};