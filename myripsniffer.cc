//===================================================================
// File:        myripsniffer.cc
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


#include <cstring>
#include <cstdlib>
#include <cassert>
#include <iostream>
#include <string>

#include <unistd.h>
#include <time.h>

#include "generic.h"
#include "net.h"


using std::cout;
using std::cerr;
using std::endl;


extern char *optarg;
extern int optind, opterr, optopt;

const char *PCAP_FILTER = "((udp) and ((dst port "
	QUOTE_2(RIP_PORT) ") or (dst port " QUOTE_2(RIPNG_PORT) ")))";

const char *BORDER = "================================================="
	"====================================================================";

const size_t DATE_LEN = 	128;
const int PAD_LEN = 			20;
const int PAD2_LEN = 			2 * PAD_LEN;

const char *progName;


static inline void outputRIP(const char *pad, RIPEntry &ripEntry,
		u_int version)
{
	const char *ip = ripEntry.getIpAddr();
	switch(version)
	{
		case 1:
			printf(
					"%s%s/%-*s %-*s %-*u %-*s\n", pad,
					ip, PAD_LEN - (int)strlen(ip) - 1,
					"-", PAD_LEN, "-", PAD_LEN / 2, (u_int)ripEntry.getMetric(),
					PAD_LEN / 2, "-");
			break;
		case 2:
			printf(
					"%s%s/%-*u %-*s %-*u %-*u\n", pad,
					ip, PAD_LEN - (int)strlen(ip) - 1,
					(u_int)subnetLen(ripEntry.getSubnetMask()),
					PAD_LEN, ripEntry.getNextHop(), PAD_LEN / 2, (u_int)ripEntry.getMetric(),
					PAD_LEN / 2, (u_int)ripEntry.getRouteTag());
			break;
		default:
			cerr << "WARNING: outputRIP(): Invalid RIP version" << endl;
	}
}

static inline void outputRIPng(const char *pad, RIPngEntry &ripngEntry,
		u_int version)
{
	const char *ip = ripngEntry.getIpPrefix();
	switch(version)
	{
		case 1:
			printf(
					"%s%s/%-*u  %-*u %-*u\n", pad,
					ip, PAD2_LEN - (int)strlen(ip) - 1,
					ripngEntry.getPrefixLen(), PAD_LEN / 2,
					(u_int)ripngEntry.getMetric(),
					PAD_LEN / 2, (u_int)ripngEntry.getRouteTag());
			break;
		default:
			cerr << "WARNING: outputRIPng(): Invalid RIPng version" << endl;
	}
}

static inline void outputRIPTableHeader(const char *pad)
{
	printf("%s%.*s\n", pad, 2 * PAD_LEN + PAD_LEN / 2 + 3 + 3, BORDER);
	printf("%s%-*s %-*s %-*s %-*s\n", pad,
			PAD_LEN, "IP/SUBNET", PAD_LEN, "NEXT-HOP",
			PAD_LEN / 2, "METRIC", PAD_LEN / 2, "TAG");
	printf("%s%.*s\n", pad, 2 * PAD_LEN + PAD_LEN / 2 + 3 + 3, BORDER);
}

static inline void outputRIPngTableHeader(const char *pad)
{
	printf("%s%.*s\n", pad, 2 * PAD_LEN + PAD_LEN / 2 + 3 + 3, BORDER);
	printf("%s%-*s  %-*s %-*s\n", pad,
			PAD2_LEN, "IP/PREFIX-LENGTH", PAD_LEN / 2,
			"METRIC", PAD_LEN / 2, "TAG");
	printf("%s%.*s\n", pad, 2 * PAD_LEN + PAD_LEN / 2 + 3 + 3, BORDER);
}

static inline void processDatagram(u_int8_t *, const pcap_pkthdr *header,
		const u_int8_t *datagram)
{
	static char date[DATE_LEN];
	EthernetHeader etherHeader;
	tm *d = localtime(&header->ts.tv_sec);
	snprintf(date, DATE_LEN, "[%.2u %s %u %.2u:%.2u:%.2u]",
			d->tm_mday, DATE_MONTH[d->tm_mon], 1900 + d->tm_year,
			d->tm_hour, d->tm_min, d->tm_sec);
	try
	{
		size_t total = header->caplen;
		const u_int8_t *base = datagram;
		base = etherHeader.fill(base, total);
		if(etherHeader.getType() == EthernetHeader::TYPE_IPv4)
		{
			IPv4Header ipv4Header;
			UDPHeader udpHeader;
			RIPHeader ripHeader;
			RIPEntry ripEntry;
			base = ipv4Header.fill(base, total);
			base = udpHeader.fill(base, total);
			base = ripHeader.fill(base, total);
			size_t ripEntriesCount = udpHeader.getDataLen() - ripHeader.length();
			if(ripEntriesCount % sizeof(RIPEntry::Raw))
			{
				cerr << "WARNING: processDatagram(): Invalid RIP entry format" << endl;
				return;
			}
			ripEntriesCount /= sizeof(RIPEntry::Raw);
			cout << date << endl;
			switch(ripHeader.getCmd())
			{
				case RIPHeader::REQUEST:
					cout << "RIP: Received v" << ripHeader.getVersion()
						<< " request from " << ipv4Header.getSrcAddr() << endl;
					break;
				case RIPHeader::RESPONSE:
					cout << "RIP: Received v" << ripHeader.getVersion()
						<< " response from " << ipv4Header.getSrcAddr() << endl;
					break;
				default:
					abort();
			}
			if(!ripEntriesCount)
			{
				cerr << "WARNING: processDatagram(): RIP contain no entries" << endl;
				return;
			}
			base = ripEntry.fill(ripHeader, base, total);
			--ripEntriesCount;
			if(ripEntry.getAfi() == RIPEntry::AUTH_MAGIC)
			{
				RIPAuth auth;
				size_t dummy = ripEntry.length();
				auth.fill(ripHeader, (const u_int8_t *)ripEntry.rawEntry(), dummy);
				cout << "\tAuthentication: ";
				switch(auth.getType())
				{
					case RIPAuth::SIMPLE_PASSWORD:
						cout << "Simple-password (" << RIPAuth::SIMPLE_PASSWORD << ")"
							<< endl;
						break;
					default:
						cout << "Unknown (" << auth.getType() << ")" << endl;
						break;
				}
				cout << "\t\tPassword: " << auth.getPassword() << endl;
				if(ripEntriesCount)
					outputRIPTableHeader("\t");
			}
			else
			{
				outputRIPTableHeader("\t");
				outputRIP("\t", ripEntry, ripHeader.getVersion());
			}
			for(; ripEntriesCount; --ripEntriesCount)
			{
				base = ripEntry.fill(ripHeader, base, total);
				outputRIP("\t", ripEntry, ripHeader.getVersion());
			}
			cout << endl;
		}
		else if(etherHeader.getType() == EthernetHeader::TYPE_IPv6)
		{
			IPv6Header ipv6Header;
			UDPHeader udpHeader;
			RIPngHeader ripngHeader;
			RIPngEntry ripngEntry;
			base = ipv6Header.fill(base, total);
			base = udpHeader.fill(base, total);
			base = ripngHeader.fill(base, total);
			size_t ripEntriesCount = udpHeader.getDataLen() - ripngHeader.length();
			if(ripEntriesCount % sizeof(RIPngEntry::Raw))
			{
				cerr << "WARNING: processDatagram(): Invalid RIPng entry format" << endl;
				return;
			}
			ripEntriesCount /= sizeof(RIPEntry::Raw);
			cout << date << endl;
			switch(ripngHeader.getCmd())
			{
				case RIPHeader::REQUEST:
					cout << "RIPng: Received v" << ripngHeader.getVersion()
						<< " request from " << ipv6Header.getSrcAddr() << endl;
					break;
				case RIPHeader::RESPONSE:
					cout << "RIPng: Received v" << ripngHeader.getVersion()
						<< " response from " << ipv6Header.getSrcAddr() << endl;
					break;
				default:
					abort();
			}
			if(!ripEntriesCount)
			{
				cerr << "WARNING: processDatagram(): RIPng contain no entries" << endl;
				return;
			}
			outputRIPngTableHeader("\t");
			for(; ripEntriesCount; --ripEntriesCount)
			{
				base = ripngEntry.fill(ripngHeader, base, total);
				outputRIPng("\t", ripngEntry, ripngHeader.getVersion());
			}
			cout << endl;
		}
	}catch(NetException exception)
	{
		cerr << "WARNING: " << exception << endl;
		return;
	}
}

static void showUsage(std::ostream & os, int code)
{
	os << "Usage: " << progName << " -i <interface>" << endl
		<< "Try '" << progName << " -h' for more information" << endl;
	exit(code);
}

static void showHelp(std::ostream & os, int code)
{
	os << "Usage: " << progName << " -i <interface>" << endl << endl
		<< "OPTIONS:" << endl
		<< "  -i <interface>  Interface for packet sniffing." << endl;
	exit(code);
}

int main(int argc, char **argv)
{
	progName = argv[0];
	if(argc == 1)
		showUsage(cout, 0);
	std::string interface;
	int opt;
	while ((opt = getopt(argc, argv, "i:h")) != -1)
	{
		switch(opt)
		{
			case 'i':
				interface = optarg;
				break;
			case 'h':
				showHelp(cout, 0);
			default:
				showUsage(cerr, 1);
		}
	}
	if(interface.empty())
	{
		cerr << "ERROR: Interface not specified" << endl;
		return 1;
	}
	if(optind != argc)
	{
		cerr << "ERROR: Invalid argument -- '" << argv[optind] << ":" << endl;
		return 1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_program fp;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	if(pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1)
	{
		cerr << "ERROR: " << errbuf << endl;
		return 1;
	}
	pcap_t *session = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
	if(session == NULL)
	{
		cerr << "ERROR: " << errbuf << endl;
		return 1;
	}
	/* (char *)PCAP_FILTER because of strange
		 compile behaviour on merlin.fit.vutbr.cz */
	if(pcap_compile(session, &fp, (char *)PCAP_FILTER, 0, net) == -1)
	{
		cerr << "ERROR: " << PCAP_FILTER << ": " << pcap_geterr(session) << endl;
		return 1;
	}
	if(pcap_setfilter(session, &fp) == -1)
	{
		cerr << "ERROR: " << PCAP_FILTER << ": " << pcap_geterr(session) << endl;
		return 1;
	}
	pcap_loop(session, -1, &processDatagram, NULL);
	pcap_close(session);
	return 0;
}

