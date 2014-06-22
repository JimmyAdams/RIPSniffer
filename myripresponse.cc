//===================================================================
// File:        myripresponse.cc
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

const int DEFAULT_METRICS = 1;
const int DEFAULT_TAG = 0;
const char *DEFAULT_NEXT_HOP = "0.0.0.0";

const char *progName;


static void showUsage(std::ostream & os, int code)
{
	os << "Usage: " << progName
		<< " -r <IPv4>/{8-30} [OPTIONS]"
		<< endl << "Try '" << progName << " -h' for more information" << endl;
	exit(code);
}

static void showHelp(std::ostream & os, int code)
{
	os << "Usage: " << progName
		<< " -r <IPv4>/{8-30} [OPTIONS]" << endl << endl
		<< "OPTIONS:" << endl
		<< "  -r <IPv4>/{8-30}  Spurious route." << endl
		<< "  -i <interface>    Interface for sending." << endl
		<< "  -n <IPv4>         Next-hop address (0.0.0.0)." << endl
		<< "  -m {0-15}         RIP metric (1)." << endl
		<< "  -t {0-65535}      Router tag (0)." << endl
		<< "  -p <password>     Simple-password authentication (none)." << endl;
	exit(code);
}

int main(int argc, char **argv)
{
	progName = argv[0];
	if(argc == 1)
		showUsage(cout, 0);
	std::string spuriousAddr;
	const char *passwd = NULL;
	const char *interface = NULL;
	const char *nextHop = DEFAULT_NEXT_HOP;
	unsigned metric = DEFAULT_METRICS;
	unsigned tag = DEFAULT_TAG;
	unsigned spuriousMaskLen = 0;
	int opt;
	while ((opt = getopt(argc, argv, "r:i:n:m:t:p:h")) != -1)
	{
		switch(opt)
		{
			case 'r':
				{
					std::string str = optarg;
					size_t i = str.find_first_of('/');
					if(i == std::string::npos)
					{
						cerr << "ERROR: Subnet mask for spurious route required" << endl;
						showUsage(cerr, 1);
					}
					spuriousAddr = str.substr(0, i).c_str();
					std::istringstream iss(str.substr(i + 1), std::ios_base::in);
					iss >> spuriousMaskLen;
					if(iss.fail() || !iss.eof())
					{
						cerr << "ERROR: Invalid subnet mask for spurious route" << endl;
						return 1;
					}
				}
				break;
			case 'i':
				interface = optarg;
				break;
			case 'n':
				nextHop = optarg;
				break;
			case 'm':
				{
					std::istringstream iss(optarg, std::ios_base::in);
					iss >> metric;
					if(iss.fail() || !iss.eof())
					{
						cerr << "ERROR: Invalid metric" << endl;
						return 1;
					}
				}
				break;
			case 't':
				{
					std::istringstream iss(optarg, std::ios_base::in);
					iss >> tag;
					if(iss.fail() || !iss.eof())
					{
						cerr << "ERROR: Invalid tag" << endl;
						return 1;
					}
				}
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
	if(spuriousAddr.empty())
	{
		cerr << "ERROR: Spurious route required" << endl;
		return 1;
	}
	if(spuriousMaskLen < 8 || spuriousMaskLen > 30)
	{
		cerr << "ERROR: Invalid network mask length" << endl;
		return 1;
	}
	if(spuriousMaskLen < classfulSubnetLen(spuriousAddr.c_str()))
		cerr << "WARNING: Supernet for route used" << endl;
	if(optind != argc)
	{
		cerr << "ERROR: Invalid argument -- '" << argv[optind] << "'" << endl;
		return 1;
	}
	if(metric > 15)
	{
		cerr << "ERROR: Metrics out of range" << endl;
		return 1;
	}
	if(tag > 65535)
	{
		cerr << "ERROR: Router tag out of range" << endl;
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
		ripHeader.setCmd(RIPHeader::RESPONSE);
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
		ripEntry.setAfi(RIPEntry::INET);
		ripEntry.setRouteTag(tag);
		ripEntry.setIpAddr(spuriousAddr.c_str());
		ripEntry.setSubnetMask(subnetMask(spuriousMaskLen));
		ripEntry.setNextHop(nextHop);
		ripEntry.setMetric(metric);
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
	inet_pton(AF_INET, RIP_IPv4_MCAST, &dst.sin_addr);
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

