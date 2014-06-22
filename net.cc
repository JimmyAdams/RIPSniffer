//===================================================================
// File:        net.cc
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
#include <cassert>

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "net.h"


typedef std::string NetError;


/* ========== LAYER 2 ========== */

const char * UnpackEtherAddr(const u_int8_t *addr, char delim)
{
	static char buffer[3 * EthernetHeader::Raw::ETHER_ADDR_LEN];
	sprintf(buffer, "%.2X%c%.2X%c%.2X%c%.2X%c%.2X%c%.2X", addr[0],
		 delim, addr[1], delim, addr[2], delim, addr[3], delim,
		 addr[4], delim, addr[5]);
	return buffer;
}

const u_int8_t * PackEtherAddr(const char *addr)
{
	static u_int buffer[EthernetHeader::Raw::ETHER_ADDR_LEN];
	sscanf(addr, "%2X%*c%2X%*c%2X%*c%2X%*c%2X%*c%2X", &buffer[0],
		&buffer[1], &buffer[2], &buffer[3], &buffer[4],	&buffer[5]);
	u_int8_t *data = (u_int8_t *)buffer;
	data[0] = buffer[0];
	data[1] = buffer[1];
	data[2] = buffer[2];
	data[3] = buffer[3];
	data[4] = buffer[4];
	data[5] = buffer[5];
	return data;
}

/* EthernetHeader */

EthernetHeader::EthernetHeader()
:
	raw(NULL)
{
}

const u_int8_t * EthernetHeader::fill(const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("EthernetHeader::fill(): Buffer too small");
	raw = (Raw *)base;
	len -= szof;
	return base + szof;
}

const char * EthernetHeader::getDstAddr() const
{
	assert(raw != NULL);
	static char buffer[3 * sizeof(raw->dstAddr)];
	strcpy(buffer, UnpackEtherAddr(raw->dstAddr, ADDRESS_DELIMITER));
	return buffer;
}

const char * EthernetHeader::getSrcAddr() const
{
	assert(raw != NULL);
	static char buffer[3 * sizeof(raw->dstAddr)];
	strcpy(buffer, UnpackEtherAddr(raw->srcAddr, ADDRESS_DELIMITER));
	return buffer;
}

u_int EthernetHeader::getType() const
{
	assert(raw != NULL);
	return ntohs(raw->type);
}

size_t EthernetHeader::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const EthernetHeader::Raw * EthernetHeader::rawHeader() const
{
	assert(raw != NULL);
	return raw;
}


/* ========== LAYER 3 ========== */

/* IPv4Header */

IPv4Header::IPv4Header()
:
	raw(NULL)
{
}

const u_int8_t * IPv4Header::fill(const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("IPv4Header::fill(): Buffer too small");
	raw = (Raw *)base;
	size_t loh = length();
	if(len < loh)
		throw NetError("IPv4Header::fill(): Buffer too small");
	if(loh < szof)
		throw NetError("IPv4Header::fill(): Invalid header length");
	if(loh > szof) 																// header contain options
	{
		opt.options = (const u_int32_t *)(base + szof);
		opt.optionChunks = (loh - szof) / sizeof(u_int32_t);
	}
	len -= loh;
	return base + loh;
}

u_int IPv4Header::getVersion() const
{
	assert(raw != NULL);
	return raw->version_headerLen >> 4;
}

u_int IPv4Header::getDscp() const
{
	assert(raw != NULL);
	return raw->dscp_ecn >> 6;
}

u_int IPv4Header::getEcn() const
{
	assert(raw != NULL);
	return raw->dscp_ecn & 0x03;
}

size_t IPv4Header::getDataLen() const
{
	assert(raw != NULL);
	return ntohs(raw->totalLen) - length();
}

u_int IPv4Header::getId() const
{
	assert(raw != NULL);
	return ntohs(raw->id);
}

u_int IPv4Header::getFlags() const
{
	assert(raw != NULL);
	return ntohs(raw->flags_fragmentOff) >> 14;
}

u_int IPv4Header::getFragmentOff() const
{
	assert(raw != NULL);
	return ntohs(raw->flags_fragmentOff) & 0xC0;
}

u_int IPv4Header::getTtl() const
{
	assert(raw != NULL);
	return raw->ttl;
}

u_int IPv4Header::getProto() const
{
	assert(raw != NULL);
	return raw->proto;
}

u_int IPv4Header::getHeaderChecksum() const
{
	assert(raw != NULL);
	return ntohs(raw->headerChecksum);
}

const char * IPv4Header::getSrcAddr() const
{
	assert(raw != NULL);
	static char buffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &raw->srcAddr, buffer, INET_ADDRSTRLEN);
	return buffer;
}

const char * IPv4Header::getDstAddr() const
{
	assert(raw != NULL);
	static char buffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &raw->dstAddr, buffer, INET_ADDRSTRLEN);
	return buffer;
}

const IPv4Header::Options * IPv4Header::getOptions() const
{
	assert(raw != NULL);
	return &opt;
}

size_t IPv4Header::length() const
{
	assert(raw != NULL);
	return (raw->version_headerLen & 0x0F) * sizeof(u_int);
}

const IPv4Header::Raw * IPv4Header::rawHeader() const
{
	assert(raw != NULL);
	return raw;
}

/* IPv6Header */

IPv6Header::IPv6Header()
:
	raw(NULL)
{
}

const u_int8_t * IPv6Header::fill(const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("IPv6Header::fill(): Buffer too small");
	raw = (Raw *)base;
	len -= szof;
	return base + szof;
}

u_int IPv6Header::getVersion() const
{
	assert(raw != NULL);
	return ntohl(raw->version_trafficCl_flowLabel) >> 28;
}

u_int IPv6Header::getTrafficCl() const
{
	assert(raw != NULL);
	return (ntohl(raw->version_trafficCl_flowLabel) & 0x0FFFFFFF)
		>> 20;
}

u_int IPv6Header::getFlowLabel() const
{
	assert(raw != NULL);
	return ntohl(raw->version_trafficCl_flowLabel) & 0x000FFFFF;
}

size_t IPv6Header::getPayloadLen() const
{
	assert(raw != NULL);
	return ntohs(raw->payloadLen);
}

u_int IPv6Header::getNextHeader() const
{
	assert(raw != NULL);
	return raw->nextHeader;
}

u_int IPv6Header::getHopLimit() const
{
	assert(raw != NULL);
	return raw->hopLimit;
}

const char * IPv6Header::getSrcAddr() const
{
	assert(raw != NULL);
	static char buffer[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &raw->srcAddr, buffer, INET6_ADDRSTRLEN);
	return buffer;
}

const char * IPv6Header::getDstAddr() const
{
	assert(raw != NULL);
	static char buffer[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &raw->dstAddr, buffer, INET6_ADDRSTRLEN);
	return buffer;
}

size_t IPv6Header::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const IPv6Header::Raw * IPv6Header::rawHeader() const
{
	assert(raw != NULL);
	return raw;
}


/* ========== LAYER 4 ========== */

/* UDPHeader */

UDPHeader::UDPHeader()
:
	raw(NULL)
{
}

const u_int8_t * UDPHeader::fill(const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("UDPHeader::fill(): Buffer too small");
	raw = (Raw *)base;
	len -= szof;
	return base + szof;
}

u_int UDPHeader::getSrcPort() const
{
	assert(raw != NULL);
	return ntohs(raw->srcPort);
}

u_int UDPHeader::getDstPort() const
{
	assert(raw != NULL);
	return ntohs(raw->dstPort);
}

size_t UDPHeader::getDataLen() const
{
	assert(raw != NULL);
	return ntohs(raw->len) - length();
}

u_int UDPHeader::getChecksum() const
{
	assert(raw != NULL);
	return ntohs(raw->checksum);
}

size_t UDPHeader::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const UDPHeader::Raw * UDPHeader::rawHeader() const
{
	assert(raw != NULL);
	return raw;
}


/* ========== LAYER 7 ========== */

const char * subnetMask(size_t len)
{
	assert(len <= 32);
	static char buffer[INET_ADDRSTRLEN];
	in_addr mask = { (!len) ? 0 : htonl(0xFFFFFFFF << (32 - len)) };
	inet_ntop(AF_INET, &mask, buffer, INET_ADDRSTRLEN);
	/*
	u_int32_t mask = (!len) ? 0 : htonl(0xFFFFFFFF << (32 - len));
	u_int8_t *base = (u_int8_t *)&mask;
	sprintf(buffer, "%u.%u.%u.%u",
			base[0], base[1], base[2], base[3]);
	*/
	return buffer;
}

size_t subnetLen(const char *mask)
{
	in_addr_t len = ntohl(inet_addr(mask));
	size_t count = 0;
	for(size_t i = 0; i < 8 * sizeof(in_addr_t); ++i)
		if(len & (0x80000000 >> i))
			++count;
		else
			break;
	return count;
}

size_t classfulSubnetLen(const char *addr)
{
	in_addr na;
	memset(&na, 0, sizeof(na));
	inet_aton(addr, &na);
	in_addr_t np = inet_netof(na);
	u_int8_t *b = (u_int8_t *)&np;
	size_t len = 0;
	for(size_t i = 0; i < sizeof(np); ++i, len += 8)
		if(!*b++)
			break;
	return len;
}

/* RIPHeader */

RIPHeader::RIPHeader()
:
	raw(NULL)
{
}

const u_int8_t * RIPHeader::fill(const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPHeader::fill(): Buffer too small");
	raw = (Raw *)base;
	if(raw->zero != 0)
		throw NetError("RIPHeader::fill(): Invalid RIP header");
	len -= szof;
	return base + szof;
}

u_int8_t * RIPHeader::build(u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPHeader::build(): Buffer too small");
	memset(base, 0, szof);
	raw = (Raw *)base;
	len -= szof;
	return base + szof;
}

void RIPHeader::setCmd(Cmd c)
{
	assert(raw != NULL);
	raw->cmd = c;
}

void RIPHeader::setVersion(u_int v)
{
	assert(raw != NULL);
	raw->version = v;
}

RIPHeader::Cmd RIPHeader::getCmd() const
{
	assert(raw != NULL);
	switch(raw->cmd)
	{
		case REQUEST:
			return REQUEST;
		case RESPONSE:
			return RESPONSE;
		default:
			throw NetError("RIPHeader::getCmd(): Invalid command");
	}
}

u_int RIPHeader::getVersion() const
{
	assert(raw != NULL);
	return raw->version;
}

size_t RIPHeader::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const RIPHeader::Raw * RIPHeader::rawHeader() const
{
	assert(raw != NULL);
	return raw;
}

/* RIPEntry */

RIPEntry::RIPEntry()
:
	raw(NULL)
{
}

const u_int8_t * RIPEntry::fill(const RIPHeader &header,
		const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPEntry::fill(): Buffer too small");
	raw = (Raw *)base;
	if(header.getVersion() == 1)
	{
		if(raw->routeTag != 0
				|| raw->subnetMask.s_addr != 0 || raw->nextHop.s_addr != 0)
			throw NetError("RIPEntry::fill(): Invalid RIP v1 entry");
	}
	len -= szof;
	return base + szof;
}

u_int8_t * RIPEntry::build(u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPEntry::build(): Buffer too small");
	memset(base, 0, szof);
	raw = (Raw *)base;
	len -= szof;
	return base + szof;
}

void RIPEntry::setAfi(Afi afi)
{
	assert(raw != NULL);
	raw->afi = htons(afi);
}

void RIPEntry::setRouteTag(u_int rt)
{
	assert(raw != NULL);
	raw->routeTag = htons(rt);
}

void RIPEntry::setIpAddr(const char *ip)
{
	assert(raw != NULL);
	switch(inet_pton(AF_INET, ip, &raw->ipAddr))
	{
		case -1:
			throw NetError(std::string("RIPEntry::setIpAddr(): inet_pton(): ")
					+ strerror(errno));
		case 0:
			throw NetError(std::string("RIPEntry::setIpAddr(): inet_pton(): "
						"Invalid address -- ") + ip);
	}
}

void RIPEntry::setSubnetMask(const char *mask)
{
	assert(raw != NULL);
	switch(inet_pton(AF_INET, mask, &raw->subnetMask))
	{
		case -1:
			throw NetError(std::string("RIPEntry::setSubnetMask(): inet_pton(): ")
					+ strerror(errno));
		case 0:
			throw NetError(std::string("RIPEntry::setSubnetMask(): inet_pton(): "
						"Invalid subnet mask -- ") + mask);
	}
}

void RIPEntry::setNextHop(const char *hop)
{
	assert(raw != NULL);
	switch(inet_pton(AF_INET, hop, &raw->nextHop))
	{
		case -1:
			throw NetError(std::string("RIPEntry::setNextHop(): inet_pton(): ")
					+ strerror(errno));
		case 0:
			throw NetError(std::string("RIPEntry::setNextHop(): inet_pton(): "
						"Invalid address -- ") + hop);
	}
}

void RIPEntry::setMetric(u_int metric)
{
	assert(raw != NULL);
	raw->metric = htonl(metric);
}

RIPEntry::Afi RIPEntry::getAfi() const
{
	assert(raw != NULL);
	switch(ntohs(raw->afi))
	{
		case INET:
			return INET;
		case AUTH_MAGIC:
			return AUTH_MAGIC;
		case 0:
			if(getMetric() == METRIC_INF)
				return REQUEST_ENTIRE_RT;
		default:
			throw NetError("RIPEntry::getAfi(): Invalid afi in RIP entry");
	}
}

u_int RIPEntry::getRouteTag() const
{
	assert(raw != NULL);
	return ntohs(raw->routeTag);
}

const char * RIPEntry::getIpAddr() const
{
	assert(raw != NULL);
	static char buffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &raw->ipAddr, buffer, INET_ADDRSTRLEN);
	return buffer;
}

const char * RIPEntry::getSubnetMask() const
{
	assert(raw != NULL);
	static char buffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &raw->subnetMask, buffer, INET_ADDRSTRLEN);
	return buffer;
}

const char * RIPEntry::getNextHop() const
{
	assert(raw != NULL);
	static char buffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &raw->nextHop, buffer, INET_ADDRSTRLEN);
	return buffer;
}

u_int RIPEntry::getMetric() const
{
	assert(raw != NULL);
	return ntohl(raw->metric);
}

size_t RIPEntry::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const RIPEntry::Raw * RIPEntry::rawEntry() const
{
	assert(raw != NULL);
	return raw;
}

/* RIPAuth */

RIPAuth::RIPAuth()
:
	raw(NULL)
{
}

const u_int8_t * RIPAuth::fill(const RIPHeader &header,
		const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPAuth::fill(): Buffer too small");
	raw = (Raw *)base;
	if(ntohs(raw->magic) != RIPEntry::AUTH_MAGIC)
		throw NetError("RIPAuth::fill(): Invalid magic number");
	if(header.getVersion() == 1)
		throw NetError("RIPAuth::fill(): Authentication for RIP v1 not supported");
	len -= szof;
	return base + szof;
}

u_int8_t * RIPAuth::build(u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPAuth::build(): Buffer too small");
	memset(base, 0, szof);
	raw = (Raw *)base;
	raw->magic = RIPEntry::AUTH_MAGIC;
	len -= szof;
	return base + szof;
}

void RIPAuth::setType(Type type)
{
	assert(raw != NULL);
	raw->type = htons(type);
}

void RIPAuth::setPassword(const char *password)
{
	assert(raw != NULL);
	strncpy((char *)raw->password, password, sizeof(raw->password));
}

RIPAuth::Type RIPAuth::getType() const
{
	assert(raw != NULL);
	switch(ntohs(raw->type))
	{
		case SIMPLE_PASSWORD:
			return SIMPLE_PASSWORD;
		default:
			throw NetError("RIPAuth::getType(): Invalid password type");
	}
}

const char * RIPAuth::getPassword() const
{
	assert(raw != NULL);
	static char buffer[sizeof(raw->password) + 1]; 						// append '\0'
	std::memcpy(buffer, raw->password, sizeof(raw->password));
	buffer[sizeof(raw->password)] = '\0';
	return buffer;
}

size_t RIPAuth::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const RIPAuth::Raw * RIPAuth::rawEntry() const
{
	assert(raw != NULL);
	return raw;
}

/* RIPngEntry */

RIPngEntry::RIPngEntry()
:
	raw(NULL)
{
}

const u_int8_t * RIPngEntry::fill(const RIPngHeader &,
		const u_int8_t *base, size_t &len)
{
	size_t szof = sizeof(Raw);
	if(len < szof)
		throw NetError("RIPngEntry::fill(): Buffer too small");
	raw = (Raw *)base;
	len -= szof;
	return base + szof;
}

const char * RIPngEntry::getIpPrefix() const
{
	assert(raw != NULL);
	static char buffer[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &raw->ipPrefix, buffer, INET6_ADDRSTRLEN);
	return buffer;
}

u_int RIPngEntry::getRouteTag() const
{
	assert(raw != NULL);
	return ntohs(raw->routeTag);
}

u_int RIPngEntry::getPrefixLen() const
{
	assert(raw != NULL);
	return raw->prefixLen;
}

u_int RIPngEntry::getMetric() const
{
	assert(raw != NULL);
	return raw->metric;
}

size_t RIPngEntry::length() const
{
	assert(raw != NULL);
	return sizeof(Raw);
}

const RIPngEntry::Raw * RIPngEntry::rawEntry() const
{
	assert(raw != NULL);
	return raw;
}

