#include <iostream>
#include "pcapclient.h"

int main()
{

PcapClient client;
PortData pd;
pd.port = 80;

client.addPort(pd);
client.startListen();
    return 0;
}