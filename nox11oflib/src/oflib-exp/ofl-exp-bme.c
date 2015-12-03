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
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "openflow/bme-ext.h"
#include "ofl-exp-bme.h"
#include "../oflib/ofl-print.h"
#include "../oflib/ofl-log.h"

#ifndef UNUSED
#define UNUSED __attribute__((__unused__))
#endif

#define LOG_MODULE ofl_exp_bme
OFL_LOG_INIT(LOG_MODULE)

#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

int
ofl_exp_bme_act_pack(struct ofl_action_header *src,
		     struct ofp_action_header *dst)
{
    char *head;
    struct ofl_bme_action_header * ofl_act = 
	(struct ofl_bme_action_header*) src;
    struct ofp_action_experimenter_header *exp =
	(struct ofp_action_experimenter_header *) dst;
    size_t size = sizeof(struct ofp_action_experimenter_header);
    exp->type = htons( OFPAT_EXPERIMENTER );
    exp->experimenter = htonl( BME_EXPERIMENTER_ID );
    head = (char *)exp + sizeof(struct ofp_action_experimenter_header);

    switch (ofl_act->type) {
    case BME_OUTPUT_BY_METADATA: {
	typedef struct ofp_bme_action_header ofp_t;
	typedef struct ofl_bme_action_header ofl_t;
	ofp_t *da;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );

	size += sizeof(ofp_t);
	break;
    }
    case BME_SET_FIELD_FROM_METADATA:
    case BME_SET_METADATA_FROM_PACKET: {
	typedef struct ofp_bme_set_metadata ofp_t;
	typedef struct ofl_bme_set_metadata ofl_t;
	ofp_t *da;
	ofl_t *sa = (ofl_t *) ofl_act;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );
	da->field = htonl( sa->field );
	da->offset = sa->offset;

	size += sizeof(ofp_t);
	break;
    }
    case BME_SET_MPLS_LABEL_FROM_COUNTER: {
	typedef struct ofp_bme_set_mpls_label ofp_t;
	ofp_t *da;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );

	size += sizeof(ofp_t);
	break;
    }
    case BME_XOR_DECODE:
    case BME_XOR_ENCODE: {
	typedef struct ofp_bme_xor_packet ofp_t;
	typedef struct ofl_bme_xor_packet ofl_t;
	ofp_t *da;
	ofl_t *sa = (ofl_t *) ofl_act;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );
	da->label_a = htonl( sa->label_a );
	da->label_b = htonl( sa->label_b );

	size += sizeof(ofp_t);
	break;
    }
    case BME_UPDATE_DISTANCE_IN_METADATA: {
	typedef struct ofp_bme_update_distance ofp_t;
	typedef struct ofl_bme_update_distance ofl_t;
	ofp_t *da;
	ofl_t *sa = (ofl_t *) ofl_act;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );
	da->port = htonl( sa->port );
	memcpy(&(da->hw_addr), &(sa->hw_addr), OFP_ETH_ALEN);

	if (sa->port & 0xFFFF0000) {
	    OFL_LOG_WARN(LOG_MODULE, "Port will be truncated to uint16_t in"
			 " BME_UPDATE_DISTANCE_IN_METADATA (%u)", da->port);
	}

	size += sizeof(ofp_t);
	break;
    }
    case BME_SET_METADATA_FROM_COUNTER: {
	typedef struct ofp_bme_set_metadata_from_counter ofp_t;
	typedef struct ofl_bme_set_metadata_from_counter ofl_t;
	ofp_t *da;
	ofl_t *sa = (ofl_t *) ofl_act;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );
	da->max_num = htonl( sa->max_num );

	size += sizeof(ofp_t);
	break;
    }
    case BME_SERIALIZE: {
	typedef struct ofp_bme_serialize ofp_t;
	typedef struct ofl_bme_serialize ofl_t;
	ofp_t *da;
	ofl_t *sa = (ofl_t *) ofl_act;

	da = (ofp_t *) head;
	da->type = htons( ofl_act->type );
	da->len =  htons( sizeof(ofp_t) );
	da->mpls_label = htonl( sa->mpls_label );
	da->timeout = htons( sa->timeout );

	size += sizeof(ofp_t);
	break;
    }
    default: {
	OFL_LOG_WARN(LOG_MODULE, "pack: unknown action type (%u).",
		     ofl_act->type);
	return 0;
	break;
    }
    }

    exp->len = htons( size );
    return size;
}

ofl_err
ofl_exp_bme_act_unpack(struct ofp_action_header *src, size_t *len,
		       struct ofl_action_header **dst)
{
    struct ofp_bme_action_header *act;
    act = (struct ofp_bme_action_header *)
	((char*) src + sizeof(struct ofp_action_experimenter_header));

    *len -= sizeof(struct ofp_action_experimenter_header);

    if (*len < ntohs(act->len)) {
        OFL_LOG_WARN(LOG_MODULE,
		     "Received BME action has invalid length"
		     "(set to %u, but only %zu received).",
		     ntohs(act->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if ((ntohs(act->len) % 8) != 0) {
        OFL_LOG_WARN(LOG_MODULE,
		     "Received BME action length is not "
		     "a multiple of 64 bits (%u).", ntohs(act->len));
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    switch (ntohs(act->type)) {
    case BME_OUTPUT_BY_METADATA: {
	typedef struct ofp_bme_action_header ofp_t;
	typedef struct ofl_bme_action_header ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    OFL_LOG_WARN(LOG_MODULE,
			 "Received BME_OUTPUT_BY_METADATA action "
			 "has invalid length (%zu).", *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);

	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    case BME_SET_FIELD_FROM_METADATA:
    case BME_SET_METADATA_FROM_PACKET: {
	typedef struct ofp_bme_set_metadata ofp_t;
	typedef struct ofl_bme_set_metadata ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    const char *name = ntohs(act->type) == BME_SET_METADATA_FROM_PACKET?
		"BME_SET_METADATA_FROM_PACKET": "BME_SET_FIELD_FROM_METADATA";

	    OFL_LOG_WARN(LOG_MODULE,
			 "Received %s action has invalid length (%zu).",
			 name, *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);
	da->field = ntohl(sa->field);
	da->offset = sa->offset;

	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    case BME_SET_MPLS_LABEL_FROM_COUNTER: {
	typedef struct ofp_bme_set_mpls_label ofp_t;
	typedef struct ofl_bme_set_mpls_label ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    OFL_LOG_WARN(LOG_MODULE,
			 "Received BME_SET_MPLS_LABEL_FROM_COUNTER action "
			 "has invalid length (%zu).", *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);
	/* da->mpls_label = ntohl(sa->mpls_label); */

	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    case BME_XOR_DECODE:
    case BME_XOR_ENCODE: {
	typedef struct ofp_bme_xor_packet ofp_t;
	typedef struct ofl_bme_xor_packet ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    OFL_LOG_WARN(LOG_MODULE,
			 "Received BME_XOR_* action "
			 "has invalid length (%zu).", *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);
	da->label_a = ntohl(sa->label_a);
	da->label_b = ntohl(sa->label_b);

	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    case BME_UPDATE_DISTANCE_IN_METADATA: {
	typedef struct ofp_bme_update_distance ofp_t;
	typedef struct ofl_bme_update_distance ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    OFL_LOG_WARN(LOG_MODULE,
			 "Received BME_UPDATE_DISTANCE_IN_METADATA action "
			 "has invalid length (%zu).", *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);
	da->port = ntohl(sa->port);
	memcpy(&(da->hw_addr), &(sa->hw_addr), OFP_ETH_ALEN);

	if (da->port & 0xFFFF0000) {
	    OFL_LOG_WARN(LOG_MODULE, "Port is truncated to uint16_t in"
			 " BME_UPDATE_DISTANCE_IN_METADATA (%u)", da->port);
	}
	
	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    case BME_SET_METADATA_FROM_COUNTER: {
	typedef struct ofp_bme_set_metadata_from_counter ofp_t;
	typedef struct ofl_bme_set_metadata_from_counter ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    OFL_LOG_WARN(LOG_MODULE,
			 "Received BME_SET_METADATA_FROM_COUNTER action "
			 "has invalid length (%zu).", *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);
	da->max_num = ntohl(sa->max_num);

	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    case BME_SERIALIZE: {
	typedef struct ofp_bme_serialize ofp_t;
	typedef struct ofl_bme_serialize ofl_t;
	ofp_t *sa;
	ofl_t *da;

	if (*len < sizeof(ofp_t)) {
	    OFL_LOG_WARN(LOG_MODULE,
			 "Received BME_SERIALIZE action "
			 "has invalid length (%zu).", *len);
	    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}

	sa = (ofp_t *) act;
	da = (ofl_t *) malloc(sizeof(ofl_t));

	da->header.type = OFPAT_EXPERIMENTER;
	da->experimenter_id = BME_EXPERIMENTER_ID;
	da->type = ntohs(act->type);
	da->mpls_label = ntohl(sa->mpls_label);
	da->timeout = ntohs(sa->timeout);

	*len -= sizeof(ofp_t);
	*dst = (struct ofl_action_header *) da;
	break;
    }
    default: {
	OFL_LOG_WARN(LOG_MODULE, "Received unknown action type (%u).",
		     ntohs(src->type));
	return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
    }
    }

    return 0;
}

int
ofl_exp_bme_act_free(struct ofl_action_header *act)
{
    struct ofl_bme_action_header * bme_act =
	(struct ofl_bme_action_header*) act;

    switch (bme_act->type) {
    case BME_OUTPUT_BY_METADATA:
    case BME_SET_METADATA_FROM_PACKET:
    case BME_SET_MPLS_LABEL_FROM_COUNTER:
    case BME_XOR_DECODE:
    case BME_XOR_ENCODE:
    case BME_UPDATE_DISTANCE_IN_METADATA:
    case BME_SET_METADATA_FROM_COUNTER:
    case BME_SET_FIELD_FROM_METADATA:
    case BME_SERIALIZE:
	break;
    default: {
	OFL_LOG_WARN(LOG_MODULE, "free: unknown action type (%u).",
		     bme_act->type);
	free(act);
	return 0;
	break;
    }
    }
    free(act);
    return 0;
}

size_t
ofl_exp_bme_act_ofp_len(struct ofl_action_header *act)
{
    struct ofl_bme_action_header * bme_act =
	(struct ofl_bme_action_header*) act;
    size_t size = sizeof(struct ofp_action_experimenter_header);

    switch (bme_act->type) {
    case BME_OUTPUT_BY_METADATA: {
	size += sizeof(struct ofp_bme_action_header);
	break;
    }
    case BME_SET_FIELD_FROM_METADATA:
    case BME_SET_METADATA_FROM_PACKET: {
	size += sizeof(struct ofp_bme_set_metadata);
	break;
    }
    case BME_SET_MPLS_LABEL_FROM_COUNTER: {
	size += sizeof(struct ofp_bme_set_mpls_label);
	break;
    }
    case BME_XOR_DECODE:
    case BME_XOR_ENCODE: {
	size += sizeof(struct ofp_bme_xor_packet);
	break;
    }
    case BME_UPDATE_DISTANCE_IN_METADATA: {
	size += sizeof(struct ofp_bme_update_distance);
	break;
    }
    case BME_SET_METADATA_FROM_COUNTER: {
	size += sizeof(struct ofp_bme_set_metadata_from_counter);
	break;
    }
    case BME_SERIALIZE: {
	size += sizeof(struct ofp_bme_serialize);
	break;
    }
    default: {
	OFL_LOG_WARN(LOG_MODULE, "bme_len: unknown action type (%u).",
		     bme_act->type);
	break;
    }
    }

    return size;
}

char*
ofl_exp_bme_act_to_string(struct ofl_action_header *act)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    struct ofl_bme_action_header * bme_act =
	(struct ofl_bme_action_header*) act;

    switch (bme_act->type) {
    case BME_OUTPUT_BY_METADATA: {
	fprintf(stream, "{BME_out}");
	break;
    }
    case BME_SET_FIELD_FROM_METADATA:
    case BME_SET_METADATA_FROM_PACKET: {
	struct ofl_bme_set_metadata *sa = 
	    (struct ofl_bme_set_metadata *) bme_act;
        const char *name = bme_act->type == BME_SET_METADATA_FROM_PACKET?
	    "setmeta": "setfiled";
	fprintf(stream, "_BME_%s{field=\"%"PRIx32, name, sa->field);
	fprintf(stream, "\", offset=\"%"PRIx8"\"}", sa->offset);
	break;
    }
    case BME_SET_MPLS_LABEL_FROM_COUNTER: {
	fprintf(stream, "{BME_mpls_cntr}");
	break;
    }
    case BME_XOR_DECODE:
    case BME_XOR_ENCODE: {
	struct ofl_bme_xor_packet *sa = (struct ofl_bme_xor_packet *) bme_act;
	fprintf(stream, "_BME_xor_%s"
		"{lbl_succ=\"0x%05"PRIx32"\", lbl_fail=\"0x%05"PRIx32"\"}",
		(bme_act->type == BME_XOR_DECODE? "dec": "enc"),
		sa->label_a, sa->label_b);
	break;
    }
    case BME_UPDATE_DISTANCE_IN_METADATA: {
	struct ofl_bme_update_distance *sa =
	    (struct ofl_bme_update_distance *) bme_act;
	fprintf(stream, "_BME_update_dst{addr=\""ETH_ADDR_FMT"\", port=\"",
		ETH_ADDR_ARGS(sa->hw_addr));
	ofl_port_print(stream, sa->port);
	fprintf(stream, "\"}");
	break;
    }
    case BME_SET_METADATA_FROM_COUNTER: {
	struct ofl_bme_set_metadata_from_counter *sa =
	    (struct ofl_bme_set_metadata_from_counter *) bme_act;
	fprintf(stream, "_BME_set_meta_cntr{max_num=\"%"PRIx32"\"}",
		sa->max_num);
	fprintf(stream, "\"}");
	break;
    }
    case BME_SERIALIZE: {
	struct ofl_bme_serialize *sa = (struct ofl_bme_serialize *) bme_act;
	fprintf(stream, "_BME_serialize{lbl=\"%"PRIx32"\",tmout=%u}",
		sa->mpls_label, sa->timeout);
	fprintf(stream, "\"}");
	break;
    }
    default: {
	OFL_LOG_WARN(LOG_MODULE, "bme_len: unknown action type (%u).",
		     bme_act->type);
	fprintf(stream, "_BME{id=\"%"PRIx32"\"}", bme_act->type);
	break;
    }
    }

    fclose(stream);
    return str;
}

int
ofl_exp_bme_inst_pack(struct ofl_instruction_header *src UNUSED,
		      struct ofp_instruction *dst UNUSED)
{
    return -1;
}

ofl_err
ofl_exp_bme_inst_unpack(struct ofp_instruction *src UNUSED, size_t *len UNUSED,
			struct ofl_instruction_header **dst UNUSED)
{
    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
}

int
ofl_exp_bme_inst_free(struct ofl_instruction_header *i UNUSED)
{
    return -1;
}

size_t
ofl_exp_bme_inst_ofp_len(struct ofl_instruction_header *i UNUSED)
{
    return 0;
}

char*
ofl_exp_bme_inst_to_string(struct ofl_instruction_header *i UNUSED)
{
    return strdup("_BME");
}
