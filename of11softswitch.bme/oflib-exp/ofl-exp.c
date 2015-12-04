/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, Budapest University of Technology and Economics
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
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 * Author: Felicián Németh <nemethf@tmit.bme.hu>
 */

#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include "ofl-exp.h"
#include "ofl-exp-nicira.h"
#include "ofl-exp-openflow.h"
#include "ofl-exp-bme.h"
#include "../oflib/ofl-messages.h"
#include "../oflib/ofl-log.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow-ext.h"
#include "openflow/bme-ext.h"

#define LOG_MODULE ofl_exp
OFL_LOG_INIT(LOG_MODULE)

int
ofl_exp_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst)
{
    struct ofl_action_experimenter *exp = 
	(struct ofl_action_experimenter*) src;

    if (src->type != OFPAT_EXPERIMENTER) {
	OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown action (%u).",
		     src->type);
	return -1;
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_act_pack(src, dst);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to pack unknown EXPERIMENTER message (%u).",
			 exp->experimenter_id);
            return -1;
        }
    }
    /* not reached */
}

ofl_err
ofl_exp_act_unpack(struct ofp_action_header *src, size_t *len,
		   struct ofl_action_header **dst)
{
    struct ofp_action_experimenter_header *exp;

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE,
		     "Received EXPERIMENTER action is shorter than "
		     "ofp_action_experimenter_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_action_experimenter_header *) src;

    switch (htonl(exp->experimenter)) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_act_unpack(src, len, dst);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to unpack unknown EXPERIMENTER action (%u).",
			 htonl(exp->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
    /* not reached */
}

int
ofl_exp_act_free(struct ofl_action_header *act)
{
    struct ofl_action_experimenter *exp = 
	(struct ofl_action_experimenter*) act;

    if (act->type != OFPAT_EXPERIMENTER) {
	OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown action (%u).",
		     act->type);
	//free(act);
	return -1;
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_act_free(act);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to free unknown EXPERIMENTER action (%u).",
			 exp->experimenter_id);
            free(exp);
            return -1;
        }
    }
    /* not reached */
}

size_t
ofl_exp_act_ofp_len(struct ofl_action_header *act)
{
    struct ofl_action_experimenter *exp = 
	(struct ofl_action_experimenter*) act;

    if (act->type != OFPAT_EXPERIMENTER) {
	OFL_LOG_WARN(LOG_MODULE, 
		     "Trying to get the length of unknown action (%u).",
		     act->type);
	return sizeof(struct ofp_action_header);
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_act_ofp_len(act);
        }
        default: {
	    OFL_LOG_WARN(LOG_MODULE, 
			 "Trying to get the length of unknown "
			 "EXPERIMENTER_ID action (%u).",
			 exp->experimenter_id);
	    return sizeof(struct ofp_action_experimenter_header);
	}
    }
    /* not reached */
}

char*
ofl_exp_act_to_string(struct ofl_action_header *act)
{
    struct ofl_action_experimenter *exp = 
	(struct ofl_action_experimenter*) act;

    if (act->type != OFPAT_EXPERIMENTER) {
	char *str;
	size_t str_size;
	FILE *stream = open_memstream(&str, &str_size);
	OFL_LOG_WARN(LOG_MODULE, 
		     "Trying to convert to string unknown action (%u).",
		     act->type);
	fprintf(stream, "act{id=\"0x%"PRIx32"\"}", act->type);
	fclose(stream);
	return str;
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_act_to_string(act);
        }
        default: {
            char *str;
            size_t str_size;
            FILE *stream = open_memstream(&str, &str_size);
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to convert to string unknown "
			 "EXPERIMENTER action (%u).",
			 exp->experimenter_id);
            fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", exp->experimenter_id);
            fclose(stream);
            return str;
        }
    }
    /* not reached */
}

/* *** */

int
ofl_exp_inst_pack(struct ofl_instruction_header *src,
		  struct ofp_instruction *dst)
{
    struct ofl_instruction_experimenter *exp = 
	(struct ofl_instruction_experimenter*) src;

    if (src->type != OFPIT_EXPERIMENTER) {
	OFL_LOG_WARN(LOG_MODULE, 
		     "Trying to pack unknown instruction (%u).", src->type);
	return -1;
    }
    
    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_inst_pack(src, dst);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to pack unknown EXPERIMENTER "
			 "instruction (%u).",
			 exp->experimenter_id);
            return -1;
        }
    }
    /* not reached */
}


ofl_err
ofl_exp_inst_unpack(struct ofp_instruction *src, size_t *len,
		    struct ofl_instruction_header **dst)
{
    struct ofp_instruction_experimenter *exp;

    if (*len < sizeof(struct ofp_instruction_experimenter)) {
        OFL_LOG_WARN(LOG_MODULE,
		     "Received EXPERIMENTER inst is shorter than "
		     "ofp_instruction_experimenter.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_instruction_experimenter *) src;

    switch (htonl(exp->experimenter)) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_inst_unpack(src, len, dst);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to unpack unknown EXPERIMENTER inst (%u).",
			 htonl(exp->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
    /* not reached */
}

int
ofl_exp_inst_free(struct ofl_instruction_header *i)
{
    struct ofl_instruction_experimenter *exp = 
	(struct ofl_instruction_experimenter*) i;

    if (i->type != OFPIT_EXPERIMENTER) {
	OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown inst (%u).", i->type);
	//free(act);
	return -1;
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_inst_free(i);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to free unknown EXPERIMENTER inst (%u).",
			 exp->experimenter_id);
            free(exp);
            return -1;
        }
    }
    /* not reached */
}

size_t
ofl_exp_inst_ofp_len(struct ofl_instruction_header *i)
{
    struct ofl_instruction_experimenter *exp = 
	(struct ofl_instruction_experimenter*) i;

    if (i->type != OFPIT_EXPERIMENTER) {
	OFL_LOG_WARN(LOG_MODULE, 
		     "Trying to get the length of unknown action (%u).",
		     i->type);
	return sizeof(struct ofp_instruction);
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_inst_ofp_len(i);
        }
        default: {
	    OFL_LOG_WARN(LOG_MODULE, 
			 "Trying to get the length of unknown "
			 "EXPERIMENTER_ID inst (%u).",
			 exp->experimenter_id);
	    return sizeof(struct ofp_instruction_experimenter);
	}
    }
    /* not reached */
}

char*
ofl_exp_inst_to_string(struct ofl_instruction_header *i)
{
    struct ofl_instruction_experimenter *exp = 
	(struct ofl_instruction_experimenter*) i;

    if (i->type != OFPIT_EXPERIMENTER) {
	char *str;
	size_t str_size;
	FILE *stream = open_memstream(&str, &str_size);
	OFL_LOG_WARN(LOG_MODULE, 
		     "Trying to convert to string unknown inst (%u).",
		     i->type);
	fprintf(stream, "inst{id=\"0x%"PRIx32"\"}", i->type);
	fclose(stream);
	return str;
    }

    switch (exp->experimenter_id) {
        case (BME_EXPERIMENTER_ID): {
            return ofl_exp_bme_inst_to_string(i);
        }
        default: {
            char *str;
            size_t str_size;
            FILE *stream = open_memstream(&str, &str_size);
            OFL_LOG_WARN(LOG_MODULE,
			 "Trying to convert to string unknown "
			 "EXPERIMENTER inst (%u).",
			 exp->experimenter_id);
            fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", exp->experimenter_id);
            fclose(stream);
            return str;
        }
    }
    /* not reached */
}

/* *** */

int
ofl_exp_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_pack(msg, buf, buf_len);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_pack(msg, buf, buf_len);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            return -1;
        }
    }
}

ofl_err
ofl_exp_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg) {
    struct ofp_experimenter_header *exp;

    if (*len < sizeof(struct ofp_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message is shorter than ofp_experimenter_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_experimenter_header *)oh;

    switch (htonl(exp->experimenter)) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_unpack(oh, len, msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_unpack(oh, len, msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message (%u).", htonl(exp->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

int
ofl_exp_msg_free(struct ofl_msg_experimenter *msg) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_free(msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

char *
ofl_exp_msg_to_string(struct ofl_msg_experimenter *msg) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_to_string(msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_to_string(msg);
        }
        default: {
            char *str;
            size_t str_size;
            FILE *stream = open_memstream(&str, &str_size);
            OFL_LOG_WARN(LOG_MODULE, "Trying to convert to string unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", msg->experimenter_id);
            fclose(stream);
            return str;
        }
    }
}
