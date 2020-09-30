#include <iostream>
#include "sniffer.h"

void cb(const uint8_t * p)
{
    std::cout << "gay!" << std::endl;
}

int main(int argc, char *argv[])
{
    sniffer s = sniffer(&cb);
    s.start();
    return (0);
}