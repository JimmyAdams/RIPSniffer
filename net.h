//===================================================================
// File:        net.h
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


#ifndef _NET_H_
#define _NET_H_ 


#include <string>

#include <pcap.h>
#include <sys/types.h>
#include <netinet/in.h>


typedef const std::string & NetException;


const char * UnpackEtherAddr(const u_int8_t *addr,
		char delim = ':');															// address -> string

const u_int8_t * PackEtherAddr(const char *addr);		// string -> address


/* ========== LAYER 2 ========== */

class EthernetHeader
{
	static const int ADDRESS_DELIMITER = ':';
public:
	enum { TYPE_IPv4 = 0x0800, TYPE_IPv6 = 0x86DD };
public:
	struct Raw
	{
		enum { ETHER_ADDR_LEN = 6 };
	public:
		u_int8_t dstAddr[ETHER_ADDR_LEN];
		u_int8_t srcAddr[ETHER_ADDR_LEN];
		u_int16_t type;
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	EthernetHeader();
	const u_int8_t * fill(const u_int8_t *base, size_t &len);

	/* Get data in suitable form for presentation */
	const char * getDstAddr() const; 				// semicolon notation
	const char * getSrcAddr() const; 				// semicolon notation
	u_int getType() const;

	size_t length() const; 									// length of header
	const Raw * rawHeader() const;
};


/* ========== LAYER 3 ========== */

class IPv4Header
{
public:
	enum { PROTO_UDP = 17 };
public:
	struct Raw
	{
		u_int8_t version_headerLen; 				// 4_4
		u_int8_t dscp_ecn; 									// 6_2
		u_int16_t totalLen;
		u_int16_t id;
		u_int16_t flags_fragmentOff; 				// 2_14
		u_int8_t ttl;
		u_int8_t proto;
		u_int16_t headerChecksum;
		in_addr srcAddr;
		in_addr dstAddr;
	} __attribute__ ((packed));
	struct Options 												// (Raw::headerLen > 5)
	{
		const u_int32_t *options;
		size_t optionChunks;
	};
private:
	Raw *raw;
	Options opt;
public:
	IPv4Header();
	const u_int8_t * fill(const u_int8_t *base, size_t &len);

	/* Get data in suitable form for presentation */
	u_int getVersion() const;
	u_int getDscp() const;
	u_int getEcn() const;
	size_t getDataLen() const;
	u_int getId() const;
	u_int getFlags() const;
	u_int getFragmentOff() const;
	u_int getTtl() const;
	u_int getProto() const;
	u_int getHeaderChecksum() const;
	const char * getSrcAddr() const; 					// colon notation
	const char * getDstAddr() const;			 		// colon notation
	const Options * getOptions() const;

	size_t length() const; 										// length of header
	const Raw * rawHeader() const;
};

class IPv6Header
{
public:
	enum { NEXT_HEADER_UDP = 0x11 };
public:
	struct Raw
	{
		u_int32_t version_trafficCl_flowLabel; 	// 4_8_20
		u_int16_t payloadLen;
		u_int8_t nextHeader;
		u_int8_t hopLimit;
		in6_addr srcAddr;
		in6_addr dstAddr;
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	IPv6Header();
	const u_int8_t * fill(const u_int8_t *base, size_t &len);

	/* Get data in suitable form for presentation */
	u_int getVersion() const;
	u_int getTrafficCl() const;
	u_int getFlowLabel() const;
	size_t getPayloadLen() const;
	u_int getNextHeader() const;
	u_int getHopLimit() const;
	const char * getSrcAddr() const; 					// semicolon notation
	const char * getDstAddr() const;			 		// semicolon notation

	size_t length() const; 										// length of header
	const Raw * rawHeader() const;
};


/* ========== LAYER 4 ========== */

class UDPHeader
{
public:
	struct Raw
	{
		u_int16_t srcPort;
		u_int16_t dstPort;
		u_int16_t len;
		u_int16_t checksum;
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	UDPHeader();
	const u_int8_t * fill(const u_int8_t *base, size_t &len);

	/* Get data in suitable form for presentation */
	u_int getSrcPort() const;
	u_int getDstPort() const;
	size_t getDataLen() const;
	u_int getChecksum() const;

	size_t length() const; 								// length of header
	const Raw * rawHeader() const;
};


/* ========== LAYER 7 ========== */

#define RIP_PORT 							520
#define RIPNG_PORT 						521

#define RIP_IPv4_MCAST 				"224.0.0.9"

const char * subnetMask(size_t len);
size_t subnetLen(const char *mask);
size_t classfulSubnetLen(const char *addr);

class RIPHeader
{
public:
	enum Cmd { REQUEST = 1, RESPONSE = 2 };
public:
	struct Raw
	{
		u_int8_t cmd;
		u_int8_t version;
		u_int16_t zero; 												// must be zero
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	RIPHeader();
	const u_int8_t * fill(const u_int8_t *base, size_t &len);
	u_int8_t * build(u_int8_t *buffer, size_t &len);

	/* Set data to suitable form for sending */
	void setCmd(Cmd c);
	void setVersion(u_int v);

	/* Get data in suitable form for presentation */
	Cmd getCmd() const;
	u_int getVersion() const;

	size_t length() const; 										// length of header
	const Raw * rawHeader() const;
};

class RIPEntry
{
public:
	enum Afi { INET = 2, AUTH_MAGIC = 0xFFFF, REQUEST_ENTIRE_RT = 0 };
	enum { METRIC_INF = 16 };
public:
	struct Raw
	{
		u_int16_t afi;
		u_int16_t routeTag; 										// RIPv1: must be zero
		in_addr ipAddr;
		in_addr subnetMask;  										// RIPv1: must be zero
		in_addr nextHop; 												// RIPv1: must be zero
		u_int32_t metric;
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	RIPEntry();
	const u_int8_t * fill(const RIPHeader &header,
			const u_int8_t *base, size_t &len);
	u_int8_t * build(u_int8_t *buffer, size_t &len);

	/* Set data to suitable form for sending */
	void setAfi(Afi afi);
	void setRouteTag(u_int rt);
	void setIpAddr(const char *ip);
	void setSubnetMask(const char *mask);
	void setNextHop(const char *hop);
	void setMetric(u_int metric);

	/* Get data in suitable form for presentation */
	Afi getAfi() const;
	u_int getRouteTag() const;
	const char * getIpAddr() const;						// colon notation
	const char * getSubnetMask() const;				// colon notation
	const char * getNextHop() const;					// colon notation
	u_int getMetric() const;

	size_t length() const; 										// length of header
	const Raw * rawEntry() const;
};

class RIPAuth
{
public:
	enum Type { SIMPLE_PASSWORD = 2 };
public:
	struct Raw
	{
		enum { RIP_PASSWORD_LEN = 16 };
	public:
		u_int16_t magic; 														// 0xFFFF
		u_int16_t type;
		u_int8_t password[RIP_PASSWORD_LEN];
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	RIPAuth();
	const u_int8_t * fill(const RIPHeader &header,
			const u_int8_t *base, size_t &len);
	u_int8_t * build(u_int8_t *buffer, size_t &len);

	/* Set data to suitable form for sending */
	void setType(Type type);
	void setPassword(const char *password);

	/* Get data in suitable form for presentation */
	Type getType() const;
	const char * getPassword() const;

	size_t length() const; 												// length of header
	const Raw * rawEntry() const;
};

typedef RIPHeader RIPngHeader;

class RIPngEntry
{
public:
	struct Raw
	{
		in6_addr ipPrefix;
		u_int16_t routeTag;
		u_int8_t prefixLen;
		u_int8_t metric;
	} __attribute__ ((packed));
private:
	Raw *raw;
public:
	RIPngEntry();
	const u_int8_t * fill(const RIPngHeader &header,
			const u_int8_t *base, size_t &len);

	/* Get data in suitable form for presentation */
	const char * getIpPrefix() const;
	u_int getRouteTag() const;
	u_int getPrefixLen() const;
	u_int getMetric() const;

	size_t length() const; 									// length of header
	const Raw * rawEntry() const;
};


#endif /* _NET_H_ */
