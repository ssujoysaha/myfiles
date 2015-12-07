
#include <netinet/in.h>
#include "packet.h"
#include "openflow/openflow.h"
#include "openflow/bme-ext.h"
#include "pipeline.h"
#include "oflib/ofl-actions.h"
#include "oflib-exp/ofl-exp-bme.h"
#include "dp_exp_bme.h"
#include "dp_actions.h"
#include "list.h"
#include "vlog.h"

#define LOG_MODULE VLM_dp_exp_bme
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

#define XOR_ENCODING_WAIT 20000 /* max. time in ms to wait for packets
			        * of the other flow before seding out a
			        * packet alone */
#define PENDING_MAX_LENGTH 10000  /* max. number of packets in pending lists */

#define SQR(A) ((A) * (A))
#define LIST_POP_FRONT(A) (list_pop_front((struct list*)A))
#define LIST_IS_EMPTY(A) (list_is_empty((struct list*)A))

struct pending_pkt {
    struct list node;
    struct packet *pkt;
    uint32_t seq_no_01;
    uint32_t seq_no_10;
    uint32_t mpls_ttl;
    uint32_t label_a, label_b;
    long long int deadline;  /* in ms */
};
struct pending_flows {
    struct list node;
    uint32_t flow_label;

    struct list enc_10;
    struct list enc_01;
    struct list dec_old;
    struct list seq; /* list for the serializer */
    int length;  /* overall length of the lists above */
    struct list dec_new;

    uint32_t last_seq;
};

static struct pending_flows*
get_pending_flow(struct datapath *dp, uint32_t flow_label)
{
    struct pending_flows *lists, *member;

    if (!dp->exp_bme) {
	lists = xmalloc(sizeof(struct pending_flows));
	dp->exp_bme = (void*)lists;
	list_init((struct list*)lists);
    } else {
	lists = (struct pending_flows *)dp->exp_bme;
    }

    LIST_FOR_EACH (member, struct pending_flows, node, (struct list*)lists) {
	if (member->flow_label == flow_label)
	    return member;
    }

    member = xmalloc(sizeof(struct pending_flows));
    member->flow_label = flow_label;
    list_init(&member->enc_10);
    list_init(&member->enc_01);
    list_init(&member->dec_old);
    list_init(&member->dec_new);
    list_init(&member->seq);
    member->length = 0;
    member->last_seq = 0;

    list_push_back((struct list*)lists, (struct list*)member);
    return member;
}

/* Author: Feng Yuan */
/* taken from:  http://www.codeguru.com/forum/showthread.php?p=283857 */
static void
XOR(char *dst, char *src, int len)
{
    while ( len && ( (unsigned) dst & 3) ) { // move dst to DWORD aligned
	* dst ++ ^= * src ++;
	len --;
    }

    while ( len >= 4 ) { // handle full DWORDs
	* (unsigned long *) dst ^= * (unsigned long *) src;
	dst += 4;
	src += 4;
	len -= 4;
    }

    while ( len ) { // remaining
	* dst ++ ^= * src ++;
	len --;
    }
}

static inline uint32_t
increment_mpls_label(uint32_t seq_no)
{
    static const uint32_t MAX_MPLS_LABEL = ((1 << 20) - 1);

    if (++seq_no > MAX_MPLS_LABEL) {
	return 1;
    } else {
	return seq_no;
    }
}

/* compare sequence numbers stored in 20 bit-long mpls labels
 * taking int account overflow, i.e., 1 follows MAX_MPLS_LABEL */
static inline int
cmp_mpls_seq_numbers(uint32_t a, uint32_t b)
{
    static const uint32_t lower_limit = ((1 << 18) - 1);
    static const uint32_t upper_limit = (3 << 18);

    if (a == b)
	return 0;
    else if (a > upper_limit && b < lower_limit)
	return -1;
    else if (a < lower_limit && b > upper_limit)
	return 1;
    else 
	return a < b? -1: 1;
}

static inline void
set_mpls_label(struct packet *pkt, uint32_t label)
{
    struct ofl_action_mpls_label label_action;

    label_action.header.type = OFPAT_SET_MPLS_LABEL;
    label_action.mpls_label = label;
    dp_execute_action(pkt, (struct ofl_action_header*) &label_action);
}

static void
add_mpls_label(struct packet *pkt, uint32_t label)
{
    struct ofl_action_push push_action;

    push_action.header.type = OFPAT_PUSH_MPLS;
    push_action.ethertype = ETH_TYPE_MPLS;
    dp_execute_action(pkt, (struct ofl_action_header*) &push_action);

    set_mpls_label(pkt, label);
}

static void
set_mpls_ttl(struct packet *pkt, uint32_t ttl)
{
    struct ofl_action_mpls_ttl ttl_action;

    ttl_action.header.type = OFPAT_SET_MPLS_TTL;
    ttl_action.mpls_ttl = (uint8_t)ttl;
    dp_execute_action(pkt, (struct ofl_action_header*) &ttl_action);
}

static inline void
pop_mpls_header(struct packet *pkt, uint16_t ethertype)
{
    struct ofl_action_pop_mpls pop_action;

    pop_action.header.type = OFPAT_POP_MPLS;
    pop_action.ethertype = ethertype;
    dp_execute_action(pkt, (struct ofl_action_header*) &pop_action);
}

/* ================================================================ */

static void
output_by_metadata(struct packet *pkt)
{
    struct ofl_action_output output_action;
    uint64_t metadata = pkt->handle_std->match->metadata;
    uint32_t port = (uint32_t) metadata;
    uint16_t max_len = (uint16_t) (metadata >> 32);

    VLOG_DBG_RL(LOG_MODULE, &rl, "BME_port       =\"0x%08"PRIx32"\"", port);
    VLOG_DBG_RL(LOG_MODULE, &rl, "BME_out_max_len=\"0x%04"PRIx16"\"", max_len);

    output_action.header.type = OFPAT_OUTPUT;
    output_action.port = port;
    output_action.max_len = max_len;

    dp_execute_action(pkt, (struct ofl_action_header*) &output_action);
}

static void
set_metadata_from_packet(struct packet *pkt,
			 struct ofl_bme_set_metadata * act )
{
    uint64_t value = 0;
    uint64_t mask;
    struct ofl_match_standard *match;
    const uint64_t m64 = 0xFFFFFFFFFFFFFFFFULL;
    const uint64_t m48 = 0x0000FFFFFFFFFFFFULL;
    const uint64_t m32 = 0x00000000FFFFFFFFULL;
    const uint64_t m16 = 0x000000000000FFFFULL;
    const uint64_t m8  = 0x00000000000000FFULL;
    packet_handle_std_validate(pkt->handle_std);
    match = pkt->handle_std->match;

    if (act->field & OFPFMF_IN_PORT) { /* Switch input port. */
	value = (uint64_t) match->in_port;
	mask = m32;
    }
    if (act->field & OFPFMF_DL_VLAN) { /* VLAN id. */
	value = (uint64_t) match->dl_vlan;
	mask = m16;
    }
    if (act->field & OFPFMF_DL_VLAN_PCP) { /* VLAN priority. */
	value = (uint64_t) match->dl_vlan_pcp;
	mask = m8;
    }
    if (act->field & OFPFMF_DL_TYPE) { /* Ethernet frame type. */
	value = (uint64_t) match->dl_type;
	mask = m16;
    }
    if (act->field & OFPFMF_NW_TOS) { /* IP ToS (DSCP field, 6 bits). */
	value = match->nw_tos;
	mask = m8; /* would it make more sense to use m6? */
    }
    if (act->field & OFPFMF_NW_PROTO) { /* IP protocol. */
	value = match->nw_proto;
	mask = m8;
    }
    if (act->field & OFPFMF_TP_SRC) { /* TCP/UDP/SCTP source port. */
	value = match->tp_src;
	mask = m16;
    }
    if (act->field & OFPFMF_TP_DST) { /* TCP/UDP/SCTP destination port. */
	value = match->tp_dst;
	mask = m16;
    }
    if (act->field & OFPFMF_MPLS_LABEL) { /* MPLS label. */
	value = match->mpls_label;
	mask = m32;  /* m20 maybe? */
    }
    if (act->field & OFPFMF_MPLS_TC) { /* MPLS TC. */
	value = match->mpls_tc;
	mask = m8;
    }
    if (act->field & OFPFMF_TYPE) { /* Match type. */
	VLOG_WARN_RL(LOG_MODULE, &rl,
		     "BME_set_metadata: OFPFMF_TYPE is not supported");
	value = 0x0ULL;
	mask = 0x0ULL;
    }
    if (act->field & OFPFMF_DL_SRC) { /* Ethernet source address. */
	/* set_meta(mac="11:22:33:44:55:66", offset=0) will be written 
	 * to the metadata register as 0x0000665544332211
	 */
	OFP_ASSERT(sizeof(value) >= ETH_ADDR_LEN);
	memcpy(&value, &match->dl_src, ETH_ADDR_LEN);
	mask = m48;
    }
    if (act->field & OFPFMF_DL_DST) { /* Ethernet destination address. */
	OFP_ASSERT(sizeof(value) >= ETH_ADDR_LEN);
	memcpy(&value, &match->dl_dst, ETH_ADDR_LEN);
	mask = m48;
    }
    if (act->field & OFPFMF_NW_SRC) { /* IP source address. */
	value = match->nw_src;
	mask = m32;
    }
    if (act->field & OFPFMF_NW_DST) { /* IP destination address. */
	value = match->nw_dst;
	mask = m32;
    }
    if (act->field & OFPFMF_METADATA) { /* Metadata passed between tables. */
	value = match->metadata;
	mask = m64;
    }

    value = value << act->offset;
    mask = mask << act->offset;

    match->metadata = (match->metadata & ~mask) | (value & mask);

    VLOG_DBG_RL(LOG_MODULE, &rl, "BME meta=\"0x%016"PRIx64"\"", match->metadata);
}

static void
set_field_from_metadata(struct packet *pkt,
			struct ofl_bme_set_metadata * act)
{
    struct ofl_match_standard *match = pkt->handle_std->match;
    uint64_t metadata = match->metadata;
    uint8_t offset = act->offset;

    /*
	(act->field & OFPFMF_IN_PORT)  // Switch input port.
	(act->field & OFPFMF_DL_VLAN)  // VLAN id. 
	(act->field & OFPFMF_DL_VLAN_PCP) // VLAN priority. 
	(act->field & OFPFMF_DL_TYPE)  // Ethernet frame type.
	(act->field & OFPFMF_NW_TOS)   // IP ToS (DSCP field, 6 bits).
	(act->field & OFPFMF_NW_PROTO) // IP protocol.
	(act->field & OFPFMF_TP_SRC)   // TCP/UDP/SCTP source port.
	(act->field & OFPFMF_TP_DST)   // TCP/UDP/SCTP destination port.
    */

    if (act->field & OFPFMF_MPLS_LABEL) { /* MPLS label. */
	uint32_t label = (uint32_t)(metadata >> offset);
	set_mpls_label(pkt, label);
	return;
    }
    /*
       (act->field & OFPFMF_MPLS_TC)  // MPLS TC. 
       (act->field & OFPFMF_TYPE)     // Match type. 
       (act->field & OFPFMF_DL_SRC)   // Ethernet source address.
       (act->field & OFPFMF_DL_DST)   // Ethernet destination address.
       (act->field & OFPFMF_NW_SRC)   // IP source address.
       (act->field & OFPFMF_NW_DST)   // IP destination address.
       (act->field & OFPFMF_METADATA) // Metadata passed between tables.
    */
    VLOG_ERR_RL(LOG_MODULE, &rl,
		"BME_set_field_from_metadata: field (0x%08"PRIx32
		") is not yet supported", act->field);
}

static void
set_mpls_label_from_counter(struct packet *pkt, 
			    struct ofl_bme_set_mpls_label *act UNUSED)
{
    static uint32_t counter = 1;

    set_mpls_label(pkt, counter);

    counter = increment_mpls_label(counter);
}

static void
set_metadata_from_counter(struct packet *pkt, 
			  struct ofl_bme_set_metadata_from_counter *act)
{
    static uint32_t counter = 1;
    struct ofl_match_standard *m;

    /* following lines are copied from pipeline.c.  It's too hard to
     * call execute_entry() directly. */

    /* NOTE: Hackish solution. If packet had multiple handles, metadata
     *       should be updated in all. */
    packet_handle_std_validate(pkt->handle_std);
    m = (struct ofl_match_standard *)pkt->handle_std->match;

    m->metadata = (uint64_t) counter++;

    if (counter > act->max_num) {
	counter = 1;
    }
}

static struct packet*
remove_from_pending(struct pending_flows *pl, struct pending_pkt* elem)
{
    struct packet *pkt;
    struct pending_pkt *p;

    p = (struct pending_pkt *)list_remove((struct list*)elem);
    pl->length--;
    pkt = elem->pkt;

    return pkt;
}

/* pkt_1 <- pkt_1 XOR pkt_2.  Returns the updated pkt_1, destroys pkt_2. */
static struct packet *
xor_packets(struct packet *pkt_1, struct packet *pkt_2)
{
    int xor_len;
    /* the smaller packet should be padded with 0s. */
    if ( pkt_1->buffer->size < pkt_2->buffer->size ) {
	xor_len = pkt_2->buffer->size;
	ofpbuf_put_zeros( pkt_1->buffer, xor_len - pkt_1->buffer->size );
    } else {
	xor_len = pkt_1->buffer->size;
    }
    XOR( pkt_1->buffer->data, pkt_2->buffer->data, xor_len );
    packet_destroy( pkt_2 );

    return pkt_1;
}

static struct pending_pkt*
find_pkt_in_dec_old(struct pending_flows *pl, struct pending_pkt* p_new)
{
    /* obviously, the efficiency can be improved easily.  One
     * possibility is to use four binary trees. */
    struct pending_pkt *p_old, *pn;

    LIST_FOR_EACH_SAFE (p_old, pn, struct pending_pkt, node, &pl->dec_old) {
	uint32_t n01 = p_new->seq_no_01;
	uint32_t n10 = p_new->seq_no_10;
	uint32_t o01 = p_old->seq_no_01;
	uint32_t o10 = p_old->seq_no_10;
	
	if ((n01 == 0 || o01 == 0 || o01 == n01) &&
	    (n10 == 0 || o10 == 0 || o10 == n10) &&
	    ((n01 && n10) || ((o01 && o10))))
	{
	    return p_old;
	}
    }
    return NULL;
}

static void
process_decoding_queues(struct pending_flows *pl)
{
    struct pending_pkt *p_new, *p_old;
    struct packet *pkt_old, *pkt_new;
    uint32_t seq_no_01, seq_no_10, flow_label;

    while (!LIST_IS_EMPTY(&pl->dec_new)) {
	p_new = (struct pending_pkt*)LIST_POP_FRONT(&pl->dec_new);
	p_old = find_pkt_in_dec_old(pl, p_new);
	if (p_old) {
	    remove_from_pending(pl, p_old);
	    pkt_new = p_new->pkt;
	    pkt_old = p_old->pkt;
	    pkt_new = xor_packets(pkt_new, pkt_old);

	    seq_no_01 = p_old->seq_no_01 ^ p_new->seq_no_01;
	    seq_no_10 = p_old->seq_no_10 ^ p_new->seq_no_10;
	    flow_label = seq_no_10? p_old->label_a: p_old->label_b;
	    add_mpls_label(pkt_new, seq_no_01);
	    add_mpls_label(pkt_new, seq_no_10);
	    add_mpls_label(pkt_new, flow_label);
	    set_mpls_ttl(pkt_new, p_new->mpls_ttl);

	    free(p_new);
	    free(p_old);

	    pipeline_process_packet(pkt_new->dp->pipeline, pkt_new);
	} else {
	    list_push_back(&pl->dec_old, (struct list*)p_new);
	    if (++(pl->length) > PENDING_MAX_LENGTH) {
		p_old = (struct pending_pkt*)LIST_POP_FRONT(&pl->dec_old);
		packet_destroy(p_old->pkt);
		free(p_old);
		pl->length --;
	    }
	}
    }
}

static int
process_encoding_queues(struct pending_flows *pl)
{
    struct pending_pkt *p_01, *pn, *p_10;
    long long int now = time_msec();
    struct packet *pkt_01, *pkt_10, *pkt_11;

    LIST_FOR_EACH_SAFE (p_01, pn, struct pending_pkt, node, &pl->enc_01) {
	if (LIST_IS_EMPTY(&pl->enc_10)) {
	    if ((now > p_01->deadline) ||
		(pl->length > PENDING_MAX_LENGTH))
	    {
		pkt_01 = remove_from_pending(pl, p_01);
		add_mpls_label(pkt_01, p_01->seq_no_01);
		add_mpls_label(pkt_01, 0);
		add_mpls_label(pkt_01, p_01->label_b);
		set_mpls_ttl(pkt_01, p_01->mpls_ttl);
		free(p_01);

		pipeline_process_packet(pkt_01->dp->pipeline, pkt_01);
		continue;
	    } else {
		return (p_01->deadline - now);
	    }
	}
	p_10 = (struct pending_pkt*)list_front(&pl->enc_10);
	pkt_01 = remove_from_pending(pl, p_01);
	pkt_10 = remove_from_pending(pl, p_10);

	pkt_11 = xor_packets(pkt_01, pkt_10);

	add_mpls_label(pkt_11, p_01->seq_no_01);
	add_mpls_label(pkt_11, p_10->seq_no_10);
	add_mpls_label(pkt_11, p_01->label_a);
	set_mpls_ttl(pkt_11, p_01->mpls_ttl);
	free(p_01);
	free(p_10);

	pipeline_process_packet(pkt_11->dp->pipeline, pkt_11);
    }
    LIST_FOR_EACH_SAFE (p_10, pn, struct pending_pkt, node, &pl->enc_10) {
	if ((now > p_10->deadline) ||
	    (pl->length > PENDING_MAX_LENGTH))
	{
	    pkt_10 = remove_from_pending(pl, p_10);
	    add_mpls_label(pkt_10, 0);
	    add_mpls_label(pkt_10, p_10->seq_no_10);
	    add_mpls_label(pkt_10, p_10->label_b);
	    set_mpls_ttl(pkt_10, p_10->mpls_ttl);
	    free(p_10);

	    pipeline_process_packet(pkt_10->dp->pipeline, pkt_10);
	    continue;
	} else {
	    return (p_10->deadline - now);
	}
    }
    return -1;
}

static int
process_seq_queue(struct pending_flows *pl)
{
    struct pending_pkt *p;
    struct packet *pkt;
    long long int now = time_msec();

    while (!LIST_IS_EMPTY(&pl->seq)) {
	p = (struct pending_pkt*)list_front(&pl->seq);

	/* NB.  last_seq is initialized to 0, i.e., we assume the
	 *      first packet's seq.no is 1. */
	if (cmp_mpls_seq_numbers(p->seq_no_10, pl->last_seq) < 0) {
	    p = (struct pending_pkt*)LIST_POP_FRONT(&pl->seq);
	    packet_destroy(p->pkt);
	    free(p);
	    pl->length --;
	    continue;
	} else if ((now > p->deadline) ||
		   (pl->length > PENDING_MAX_LENGTH) ||
		   (p->seq_no_10 == increment_mpls_label(pl->last_seq)))
	{
	    pl->last_seq = p->seq_no_10;

	    pkt = remove_from_pending(pl, p);
	    add_mpls_label(pkt, p->label_a);
	    set_mpls_ttl(pkt, p->mpls_ttl);
	    free(p);

	    pipeline_process_packet(pkt->dp->pipeline, pkt);
	    continue;	    
	} else {
	    return (p->deadline - now);
	}
    }
    return -1;
}

int
dp_exp_bme_process_pending(struct datapath *dp)
{
    struct pending_flows *p, *pn;
    int ret = -1;
    struct list *l = (struct list *)dp->exp_bme;

    if (!l)
	return -1;

    LIST_FOR_EACH_SAFE (p, pn, struct pending_flows, node, l) {
	int r1;

	process_decoding_queues(p);
	r1 = process_encoding_queues(p);
	if (r1>0)
	    ret = MIN(ret, r1);
	r1 = process_seq_queue(p);
	if (r1>0)
	    ret = MIN(ret, r1);
    }

    return ret;
}

/* 
#+begin_ditaa
         +---------------+--------------+--------------+------+
   pkt : |MPLS mpls-label|MPLS seq.no 1 |MPLS seq.no 2 | data |
         +---------------+--------------+--------------+------+
#+end_ditaa
*/
static void
xor_packet_from_queue(struct packet *pkt0, 
		      struct ofl_bme_xor_packet *action,
		      uint32_t type)
{
    struct ofl_bme_xor_packet *bme_act = 
	(struct ofl_bme_xor_packet *)action;
    uint32_t flow_label, flow_ttl, seq_10, seq_01;
    uint32_t mpls_field;
    struct pending_pkt *pending;
    struct pending_flows *pl;
    struct packet *pkt;
    /* We cannot write pkt = packet_clone(pkt0); as it clones the
     * current action_set and metadata too. */
    pkt = packet_create(pkt0->dp, pkt0->in_port, ofpbuf_clone(pkt0->buffer),
			pkt0->packet_out);

    /* process flow-label */
    packet_handle_std_validate(pkt->handle_std);
    mpls_field = ntohl(pkt->handle_std->proto->mpls->fields);
    flow_label = (mpls_field & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
    flow_ttl   = (mpls_field & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
    VLOG_DBG_RL(LOG_MODULE, &rl, "flow_label=\"0x%08"PRIx32"\"", flow_label);
    
    pop_mpls_header(pkt, ETH_TYPE_MPLS);
    packet_handle_std_validate(pkt->handle_std);

    /* process seq_10 */
    mpls_field = ntohl(pkt->handle_std->proto->mpls->fields);
    seq_10 = (mpls_field & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
    VLOG_DBG_RL(LOG_MODULE, &rl, "seq_10    =\"0x%08"PRIx32"\"", seq_10);

    pop_mpls_header(pkt, ETH_TYPE_MPLS);
    packet_handle_std_validate(pkt->handle_std);

    /* process seq_01 */
    mpls_field = ntohl(pkt->handle_std->proto->mpls->fields);
    seq_01 = (mpls_field & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
    VLOG_DBG_RL(LOG_MODULE, &rl, "seq_01    =\"0x%08"PRIx32"\"", seq_01);
  
    pop_mpls_header(pkt, ETH_TYPE_IP);
    packet_handle_std_validate(pkt->handle_std);

    /* enqueue pkt */
    if (type == BME_XOR_ENCODE) {
	if ((seq_10 == 0 && seq_01 == 0) ||
	    (seq_10 != 0 && seq_01 != 0))
	{
	    VLOG_WARN_RL(LOG_MODULE, &rl, "cannot encode pkt (seq_10, seq_01 :"
			 "\"0x%08"PRIx32"\", \"0x%08"PRIx32"\")",
			 seq_10, seq_01);
	    packet_destroy(pkt);
	    return;
	}
    } else { /* type == BME_XOR_DECODE */
    }

    pl = get_pending_flow(pkt->dp, flow_label);
    pending = xmalloc(sizeof(struct pending_pkt));
    pending->pkt = pkt;
    pending->label_a = bme_act->label_a;
    pending->label_b = bme_act->label_b;
    pending->deadline = time_msec() + XOR_ENCODING_WAIT; /* in ms */
    pending->mpls_ttl = flow_ttl;
    pending->seq_no_10 = seq_10;
    pending->seq_no_01 = seq_01;
    if (type == BME_XOR_ENCODE) {
	pl->length++;
	if (seq_10) {
	    list_push_back(&pl->enc_10, (struct list*)pending);
	} else {
	    list_push_back(&pl->enc_01, (struct list*)pending);
	}
    } else { /* type == BME_XOR_DECODE */
	list_push_back(&pl->dec_new, (struct list*)pending);
    }
}

/* 
#+begin_ditaa
         +---------------+------------+------+
   pkt : |MPLS mpls-label|MPLS seq.no | data |
         |   (flow-id)   |            |      |
         +---------------+------------+------+
#+end_ditaa
*/
static void
serialize(struct packet *pkt0, struct ofl_bme_serialize *action)
{
    uint32_t flow_label, flow_ttl, seq_10;
    uint32_t mpls_field;
    struct pending_pkt *pending, *p, *pn;
    struct pending_flows *pl;
    struct packet *pkt;
    /* We cannot write pkt = packet_clone(pkt0); as it clones the
     * current action_set and metadata too. */
    pkt = packet_create(pkt0->dp, pkt0->in_port, ofpbuf_clone(pkt0->buffer),
			pkt0->packet_out);

    /* process flow-label */
    packet_handle_std_validate(pkt->handle_std);
    mpls_field = ntohl(pkt->handle_std->proto->mpls->fields);
    flow_label = (mpls_field & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
    flow_ttl   = (mpls_field & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
    VLOG_DBG_RL(LOG_MODULE, &rl, "flow_label=\"0x%08"PRIx32"\"", flow_label);
    
    pop_mpls_header(pkt, ETH_TYPE_MPLS);
    packet_handle_std_validate(pkt->handle_std);

    /* process seq_10 */
    mpls_field = ntohl(pkt->handle_std->proto->mpls->fields);
    seq_10 = (mpls_field & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
    VLOG_DBG_RL(LOG_MODULE, &rl, "seq_10    =\"0x%08"PRIx32"\"", seq_10);

    pop_mpls_header(pkt, ETH_TYPE_IP);
    packet_handle_std_validate(pkt->handle_std);

    pl = get_pending_flow(pkt->dp, flow_label);
    pending = xmalloc(sizeof(struct pending_pkt));
    pending->pkt = pkt;
    pending->label_a = action->mpls_label;
    pending->deadline = time_msec() + action->timeout; /* in ms */
    pending->mpls_ttl = flow_ttl;
    pending->seq_no_10 = seq_10;
    pending->seq_no_01 = 0;

    /* LIST_FOR_EACH_REVERSE might be more efficient. */ 
    LIST_FOR_EACH_SAFE (p, pn, struct pending_pkt, node, &pl->seq) {
	if (cmp_mpls_seq_numbers(p->seq_no_10, seq_10) > 0) {
	    list_insert((struct list*)p, (struct list*)pending);
	    return;
	}
    }
    list_push_back((struct list*)&pl->seq, (struct list*)pending);
}

static void
get_coordinates(uint64_t addr, int *x, int *y)
{
    static const uint64_t mask = 0x0000000000FFFFFFULL; /* m24 */

#if __BYTE_ORDER == __BIG_ENDIAN
    /* checking for big_endianness does not provide full portability.
     * moreover, __builtin_bswap64 is gcc specific.
     */
    addr = __builtin_bswap64(addr);
#endif

    *x = addr & mask;
    *y = (addr >> (3 * 8)) & mask;
}

static void
update_distance_in_metadata(struct packet *pkt,
			    struct ofl_bme_update_distance *action)
{
    int x1, y1, x2, y2;
    uint64_t addr_dst = 0, addr_act = 0;
    uint64_t dist_old, dist_new;
    struct ofl_match_standard *match = pkt->handle_std->match;

    memcpy(&addr_dst, pkt->handle_std->proto->eth->eth_dst, ETH_ADDR_LEN);
    memcpy(&addr_act, action->hw_addr, ETH_ADDR_LEN);

    get_coordinates(addr_dst, &x1, &y1);
    get_coordinates(addr_act, &x2, &y2);
    VLOG_DBG_RL(LOG_MODULE, &rl, "x1, y1 = %u, %u", x1, y1);
    VLOG_DBG_RL(LOG_MODULE, &rl, "x2, y2 = %u, %u", x2, y2);

    dist_new = SQR(x1 - x2) + SQR(y1 - y2);
    dist_old = match->metadata >> 16;

    if (dist_new < dist_old) {
	static const uint64_t m16 = 0x000000000000FFFFULL;
	uint64_t port_no = action->port & m16;
	struct sw_port *port = dp_ports_lookup(pkt->dp, port_no);
	if (port
	    && port->conf 
	    && (~port->conf->config & OFPPC_PORT_DOWN)
	    && (~port->conf->state & OFPPS_LINK_DOWN))
	{
	    match->metadata = dist_new << 16;
	    match->metadata |= port_no;
	}
    }
}

void
dp_exp_bme_action(struct packet *pkt, struct ofl_action_experimenter *act)
{
    struct ofl_bme_action_header *exp =
	(struct ofl_bme_action_header *)act;

    switch (exp->type) {
    case BME_OUTPUT_BY_METADATA:
	output_by_metadata( pkt );
	break;
    case BME_SET_METADATA_FROM_PACKET:
	set_metadata_from_packet( pkt, (struct ofl_bme_set_metadata *) exp );
	break;
    case BME_SET_MPLS_LABEL_FROM_COUNTER:
	set_mpls_label_from_counter( pkt,
				     (struct ofl_bme_set_mpls_label *) exp );
	break;
    case BME_XOR_DECODE:
    case BME_XOR_ENCODE:
	xor_packet_from_queue( pkt, (struct ofl_bme_xor_packet *)exp,
			       exp->type );
	break;
    case BME_UPDATE_DISTANCE_IN_METADATA:
	update_distance_in_metadata( pkt,
				     (struct ofl_bme_update_distance *)exp );
	break;
    case BME_SET_METADATA_FROM_COUNTER: {
	typedef struct ofl_bme_set_metadata_from_counter ofl_t;
	set_metadata_from_counter( pkt, (ofl_t *)exp );
	break;
    }
    case BME_SET_FIELD_FROM_METADATA: {
	set_field_from_metadata( pkt, (struct ofl_bme_set_metadata *) exp );
	break;
    }
    case BME_SERIALIZE: {
	serialize( pkt, (struct ofl_bme_serialize *) exp );
	break;
    }
    default:
	VLOG_WARN_RL(LOG_MODULE, &rl,
		     "BME dp_exp_action isn't implemented (%u).",
		     exp->type);
	break;
    }
}
