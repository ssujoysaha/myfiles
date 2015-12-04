/* Copyright (c) 2012, Budapest University of Technology and Economics
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Author: Felicián Németh <nemethf@tmit.bme.hu>
 */

#ifndef OPENFLOW_BME_EXT_H
#define OPENFLOW_BME_EXT_H 1

#include "openflow/openflow.h"

#define BME_EXPERIMENTER_ID 0xFF000001 /* BME was the first to request an ID */

struct ofp_bme_action_header {
    uint16_t type;
    uint16_t len;		  /* Length of this struct in bytes. */
    uint8_t pad[4];               /* Align to 64-bits */
};
OFP_ASSERT(sizeof(struct ofp_bme_action_header) == 8);

struct bme_instruction_header {
    uint16_t type;
    uint16_t len;		    /* Length of this struct in bytes. */
};
OFP_ASSERT(sizeof(struct bme_instruction_header) == 4);

enum bme_action_type {
/* 
 * ** experimenter action: Output-by-metadata
 * Output packet to the port_id (port_no) stored in the metadata
 * register.  The register is interpreted as 0xIIIIMMMMPPPPPPPP, where
 * I is ignored, M holds the max_len, and P holds the port_no.  See
 * ofp_action_output.  If Port_id is OFPP_ANY (0xFFFFFFFF), then the
 * packet is dropped.
 */
  BME_OUTPUT_BY_METADATA = 1,

/* ** experimenter action: set-metadata-from-packet(field, offset)
 * Set the metadata register from the currently processed packet. 
 */
  BME_SET_METADATA_FROM_PACKET = 2,

/*
 * ** experimenter action: Set-MPLS-label-from-counter
 * Set the outermost MPLS label from an internal counter and
 * increment the 20-bit-long counter.
 */
  BME_SET_MPLS_LABEL_FROM_COUNTER = 3,

/*
 ** experimenter action: xor-decode( label_a, label_b )
 *
 * A copy of the packet is put into the pending queue.
 *
 * The packet must have 3 mpls headers: flow-id, sequence number 10,
 * and sequence number 01.  
 *
 * Two packets form a pair if they have the same flow-id, one of the
 * packets has one zero seq.no and one non-zero seq.no (NZ), the other
 * packet has two non-zero seq.numbers, and NZ is common in the two
 * packets.
 * 
 * A packet in the pending queue is processed as follows.  If there is
 * a pair packet in the decoding queue, then the two packets are
 * XORed.  If seq_10 is non-zero in the result, then flow-id is set to
 * label_a. If seq_01 is non-zero, then flow-is is set to label_b.
 * The resulting packet is put back to the beginning of the
 * packet-processing pipeline.  Old packets in the decoding queue are
 * dropped.
 */
  BME_XOR_DECODE = 4,

/* ** experimenter action: xor-encode( label_a, label_b )
 *
 * A copy of the packet is put into the pending queue.
 *
 * The packet must have 3 mpls headers: flow-id, sequence number 10,
 * and sequence number 01.  
 *
 * Two packets form a pair if they have the same flow-id, seq_01 is
 * zero in exactly one packet, and seq_10 is zero in exactly one
 * packet as well.
 *
 * A packet in the pending queue is processed as follows.  If there is
 * a pair packet in the encoding queue, then the two packets are XORed
 * and resulting packet with label_a flow-id is put back to the
 * beginning of the packet-processing pipeline.  If no pair packet is
 * found, then the packet is enqueued in the encoding queue.  If a
 * packet waits too long in the encoding queue, then it is dequeued
 * and put back to the beginning of pipeline with label_b flow-id.
 */
  BME_XOR_ENCODE = 5,

/* ** Updata_Distance_in_Metadata( dst_mac_2, port_id )
 *
 * dst_mac_1 is the destination mac address of the packet.
 *
 * The right 48 bits of the 64-bit-long metadata is assumed to store
 * an unsigned integer representing a distance.  This instruction
 * first calculates the 48-bit-long (geographical) distance between
 * dst_mac_1 and dst_mac_2 addresses.  If the result is smaller than
 * the distance stored in the metadata, then the new result is written
 * to the metadata's right 48 bits and the port_id to the remaining 16
 * bits.  Otherwise the metadata register remains intact.
 *
 * The port_id is usually defined as uint32_t, hence here we assume
 * the most significant bits of port_id are all 0.
 */
  BME_UPDATE_DISTANCE_IN_METADATA = 6,

/* ** set-metadata-from-counter( max_num )
 * increment an internal counter and set the metadata register from it.
 * the counter is set to 1 if it reaches max_num.
 */
  BME_SET_METADATA_FROM_COUNTER = 7,

/* ** set_filed_from_metadata( field, offset )
 *
 * sets the filed of the currently processed packet from the metadata
 * register.
 */
  BME_SET_FIELD_FROM_METADATA = 8,

/* ** serialize( mpls_label, timeout )
 *
 * put a copy of the packet into the serializer queue.  the packet
 * must have two mpls headers: a flow id and a sequence number.
 * packets from the queue are put back to the beginning of the
 * pipeline.  if the queue is not empty it waits at most `timeout'
 * milliseconds before assuming a packet is lost.
 */
  BME_SERIALIZE = 9,
};

struct bme_output_by_metadata {
  uint16_t type;                /* BME_OUTPUT_BY_METADATA */
  uint16_t len;                 /* Length of this struct in bytes. */
  uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct bme_output_by_metadata) == 8);

struct ofp_bme_set_metadata {
    uint16_t type;                /* BME_SET_METADATA_FROM_PACKET */
    uint16_t len;                 /* Length of this struct in bytes. */
    uint32_t field;               /* One of OFPFMF_*; If more than one bit is
				     set, the behaviour is undefined */
    uint8_t  offset;              /* the filed value (and its mask) is shifted 
				     offset number of bits to the left */
    uint8_t pad[7];
};
OFP_ASSERT(sizeof(struct ofp_bme_set_metadata) == 16);

struct ofp_bme_set_mpls_label {
  uint16_t type;                /* BME_SET_MPLS_LABEL_FROM_COUNTER */
  uint16_t len;                 /* Length of this struct in bytes. */
  uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_bme_set_mpls_label) == 8);

struct ofp_bme_xor_packet {
    uint16_t type;           /* BME_XOR_* */
    uint16_t len;            /* Length of this struct in bytes. */
    uint32_t label_a;
    uint32_t label_b;
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_bme_xor_packet) == 16);

struct ofp_bme_update_distance {
    uint16_t type;           /* BME_UPDATE_DISTANCE_IN_METADATA */
    uint16_t len;            /* Length of this struct in bytes. */
    uint8_t  hw_addr[OFP_ETH_ALEN]; 
    uint8_t  pad[2];
    uint32_t port;
};
OFP_ASSERT(sizeof(struct ofp_bme_update_distance) == 16);

struct ofp_bme_set_metadata_from_counter {
  uint16_t type;                /* BME_SET_METADATA_FROM_COUNTER */
  uint16_t len;                 /* Length of this struct in bytes. */
  uint32_t max_num;
};
OFP_ASSERT(sizeof(struct ofp_bme_set_metadata_from_counter) == 8);

struct ofp_bme_serialize {
    uint16_t type;           /* BME_SERIALIZE */
    uint16_t len;            /* Length of this struct in bytes. */
    uint32_t mpls_label;
    uint16_t timeout;
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct ofp_bme_serialize) == 16);

/* 
 * enum bme_instruction_type {
 *  BME_ = 1
 * };
 */

#endif /* openflow/bme-ext.h */
