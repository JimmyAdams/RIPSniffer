//===================================================================
// File:        myriprequest.cc
// Author:      Drahoslav Zan
// Email:       izan@fit.vutbr.cz
// Affiliation: Brno University of Technology,
//              Faculty of Information Technology
// Date:        Tue Oct 19 20:10:12 CET 2010
// Project:     RIP and RIPng protocol sniffer (RRPS)
//-------------------------------------------------------------------
// Copyright (C) 2010 Drahoslav Zan
//
// This file is part of RRPS.
//
// RRPS is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// RRPS is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with RRPS. If not, see <http://www.gnu.org/licenses/>.
//===================================================================
// vim: set nowrap sw=2 ts=2


#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "generic.h"
#include "net.h"


using std::cout;
using std::cerr;
using std::endl;


extern char *optarg;
extern int optind, opterr, optopt;

const char *DEFAULT_IP = RIP_IPv4_MCAST;

const char *progName;


static void showUsage(std::ostream & os, int code)
{
	os << "Usage: " << progName << " [OPTIONS]"
		<< endl << "Try '" << progName << " -h' for more information" << endl;
	exit(code);
}

static void showHelp(std::ostream & os, int code)
{
	os << "Usage: " << progName << " [OPTIONS]" << endl << endl
		<< "OPTIONS:" << endl
		<< "  -r <IPv4>/{8-30}  Request for specific route (entire RT)." << endl
		<< "  -i <interface>    Interface for sending." << endl
		<< "  -d <IPv4>         Destination address (" RIP_IPv4_MCAST ")." << endl
		<< "  -p <password>     Simple-password authentication (none)." << endl << endl
		<< "NOTE:" << endl
		<< "According to RFC authentication should not be used with request" << endl
		<< "for entire routing table." << endl;
	exit(code);
}

int main(int argc, char **argv)
{
	progName = argv[0];
	std::string routeAddr;
	const char *ip = RIP_IPv4_MCAST;
	const char *interface = NULL;
	const char *passwd = NULL;
	unsigned routeMaskLen = 0;
	int opt;
	while ((opt = getopt(argc, argv, "r:i:d:p:h")) != -1)
	{
		switch(opt)
		{
			case 'r':
				{
					std::string str = optarg;
					size_t i = str.find_first_of('/');
					if(i == std::string::npos)
					{
						cerr << "ERROR: Subnet mask for route required" << endl;
						showUsage(cerr, 1);
					}
					routeAddr = str.substr(0, i).c_str();
					std::istringstream iss(str.substr(i + 1), std::ios_base::in);
					iss >> routeMaskLen;
					if(iss.fail() || !iss.eof())
					{
						cerr << "ERROR: Invalid subnet mask for route" << endl;
						return 1;
					}
				}
				break;
			case 'i':
				interface = optarg;
				break;
			case 'd':
				ip = optarg;
				break;
			case 'p':
				passwd = optarg;
				break;
			case 'h':
				showHelp(cout, 0);
			default:
				showUsage(cerr, 1);
		}
	}
	if(routeAddr.empty())
	{
		if(passwd != NULL)
			cerr << "WARNING: Requesting entire routing table with authentication" << endl;
	}
	else if(routeMaskLen < 8 || routeMaskLen > 30)
	{
		cerr << "ERROR: Invalid network mask length" << endl;
		return 1;
	}
	else if(routeMaskLen < classfulSubnetLen(routeAddr.c_str()))
		cerr << "WARNING: Supernet for route used" << endl;
	if(optind != argc)
	{
		cerr << "ERROR: Invalid argument -- '" << argv[optind] << "'" << endl;
		return 1;
	}
	u_int8_t buffer[sizeof(RIPHeader::Raw)
		+ sizeof(RIPAuth::Raw) + sizeof(RIPEntry::Raw)];
	ssize_t dataLen = sizeof(buffer);
	try
	{
		u_int8_t *base = buffer;
		size_t len = sizeof(buffer);
		RIPHeader ripHeader;
		base = ripHeader.build(base, len);
		ripHeader.setCmd(RIPHeader::REQUEST);
		ripHeader.setVersion(2);
		if(passwd != NULL)
		{
			RIPAuth ripAuth;
			base = ripAuth.build(base, len);
			ripAuth.setType(RIPAuth::SIMPLE_PASSWORD);
			ripAuth.setPassword(passwd);
		}
		RIPEntry ripEntry;
		base = ripEntry.build(base, len);
		if(routeAddr.empty())
		{
			ripEntry.setAfi(RIPEntry::REQUEST_ENTIRE_RT);
			ripEntry.setIpAddr("0.0.0.0");
			ripEntry.setMetric(RIPEntry::METRIC_INF);
		}
		else
		{
			ripEntry.setAfi(RIPEntry::INET);
			ripEntry.setIpAddr(routeAddr.c_str());
			ripEntry.setMetric(0);
		}
		ripEntry.setRouteTag(0);
		ripEntry.setSubnetMask(subnetMask(routeMaskLen));
		ripEntry.setNextHop("0.0.0.0");
		dataLen -= len;
	}catch(NetException e)
	{
		cerr << "ERROR: " << e << endl;
		return 1;
	}
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(s < 0)
	{
		cerr << "ERROR: socket(): " << strerror(errno) << endl;
		return 1;
	}
	sockaddr_in src;
	memset(&src, 0, sizeof(src));
	src.sin_port = htons(RIP_PORT);
	if(interface != NULL)
	{
		ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
		if(ioctl(s, SIOCGIFADDR, &ifr) == -1)
		{
			cerr << "ERROR: ioctl(): " << strerror(errno) << endl;
			return 1;
		}
		src.sin_family = AF_INET;
		src.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	}
	if(bind(s, (sockaddr *)&src, sizeof(src)) != 0)
	{
		cerr << "ERROR: bind(): " << strerror(errno) << endl;
		return 1;
	}
	sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	switch(inet_pton(AF_INET, ip, &dst.sin_addr))
	{
		case -1:
			cerr << "ERROR: inet_pton(): " << strerror(errno) << endl;
			return 1;
		case 0:
			cerr << "ERROR: inet_pton(): Invalid address -- " << ip << endl;
			return 1;
	}
	dst.sin_family = AF_INET;
	dst.sin_port = htons(RIP_PORT);
	if(sendto(s, buffer, dataLen, 0, (sockaddr *)&dst,
				sizeof(dst)) != dataLen)
	{
		cerr << "ERROR: sendto(): " << strerror(errno) << endl;
		return 1;
	}
	close(s);
	return 0;
}

