
#include <string.h>
#include <libwebsockets.h>

#include "bacnet/bacdef.h"
#include "bacnet/bactext.h"
#include "bacnet/npdu.h"
#include "bacnet/datalink/sc.h"


struct bsc_message {
  uint8_t *buf;
  uint8_t *payload;
  int pdu_len;
};

struct sc_connection {
  char url[BSC_MAX_WSURL];
  uint8_t vmac[6];
  uint8_t uuid[16];
  uint16_t max_bvlc;
  uint16_t max_npdu;

  struct lws *wsi;
  struct lws_context *context;
  struct lws_client_connect_info info;
  struct lws_ring *outgoing;
  struct bsc_message *incoming;

  uint16_t ident;
  enum connection_state {
    DISCONNECTED,
    AWAITING_REQUEST,
    CONNECTED
  } state;
};

// for now, we only support one connection, but this could be easily
// extended to support more connections.
struct sc_connection primary_hub;


static const lws_retry_bo_t retry = {
        .secs_since_valid_ping = 3,
        .secs_since_valid_hangup = 10,
};

// Websockets protocol.  defined in BACnet/SC \S AB.7.1.
static const char* ws_protocol = "hub.bsc.bacnet.org";

// Our local VMAC
static const char local_vmac[6] = {
  0x01, 0x23, 0x34, 0x56, 0x78, 0x9a};

// Our local UUID
static const char local_uuid[16] = {
  0x01, 0x23, 0x34, 0x56, 
  0x01, 0x23, 0x34, 0x56, 
  0x01, 0x23, 0x34, 0x56, 
  0x01, 0x23, 0x34, 0x56, 
};

static lws_sorted_usec_list_t sul;

bool BSC_Debug = false;

void bsc_bvlc_send_connection_request(struct sc_connection *conn);

static int callback_data_received(struct lws *wsi, enum lws_callback_reasons reason,
				  void *user, void *in, size_t len);
void bsc_bvlc_receive(struct lws *wsi, uint8_t *payload, size_t len);

static const struct lws_protocols protocols [] = {
  {
    "hub.bsc.bacnet.org",
    callback_data_received,
    0, 0, 0, NULL, 0
  },
  { NULL, NULL, 0, 0, 0, NULL, 0 },
};

void free_outgoing(void *p) {
  struct bsc_message **out = p;
  free((*out)->buf);
  free(*out);
}

struct bsc_message *alloc_outgoing(int pdu_len) {
  struct bsc_message *rv = NULL;
  if (pdu_len + BSC_MAX_HEADER > BSC_MPDU_MAX) {
    return rv;
  }

  rv = malloc(sizeof(struct bsc_message));
  rv->pdu_len = pdu_len + BSC_MAX_HEADER;
  /* add overhead for the websockets headers */
  rv->buf = malloc(pdu_len + LWS_PRE + BSC_MAX_HEADER);
  rv->payload = &rv->buf[LWS_PRE];
  return rv;
}
  
void binstr(uint8_t *p, int len) {
  for (int i = 0; i < len; i++) {
    printf("%x ", *p++);
  }
  printf(" ");
}

static void connect_cb(lws_sorted_usec_list_t *_sul) {
  lwsl_notice("%s: connecting\n", __func__);

  if (BSC_Debug) {
    fprintf(stderr, "bsc_init: proto=%s addr=%s port=%d path=%s\n",
	    primary_hub.info.protocol, primary_hub.info.address,
	    primary_hub.info.port, primary_hub.info.path);
  }

  if (!lws_client_connect_via_info(&primary_hub.info)) {
    lwsl_err("connection err\n");
  }

}

static int
callback_data_received(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len) {
  lwsl_user("%s: received %d\n", __func__, reason);
  switch (reason) {
  case LWS_CALLBACK_CLIENT_RECEIVE:
    lwsl_user("%s: received: %lu\n", __func__, len);
    bsc_bvlc_receive(wsi, in, len);
    break;
  case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
    primary_hub.state = DISCONNECTED;
    lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
	     in ? (char *)in : "(null)");
    break;
  case LWS_CALLBACK_CLIENT_CLOSED:
    primary_hub.state = DISCONNECTED;
    primary_hub.wsi = NULL;
    break;
	  
  case LWS_CALLBACK_CLIENT_ESTABLISHED:
    primary_hub.state = AWAITING_REQUEST;
    // after the connection is established, we need to
    // send a connection request.
    lwsl_user("%s: established\n", __func__);
    lws_set_timer_usecs(wsi, 5 * LWS_USEC_PER_SEC);

    lws_callback_on_writable(wsi);
    break;
  case LWS_CALLBACK_CLIENT_WRITEABLE:
    switch (primary_hub.state) {
    case AWAITING_REQUEST:
      bsc_bvlc_send_connection_request(&primary_hub);
      break;
      
    case CONNECTED:
      struct bsc_message **out = (struct bsc_message **)lws_ring_get_element(primary_hub.outgoing, NULL);
      if (out != NULL) {
	if (BSC_Debug)
	  printf("BSC: Sending message len=%d %p\n", (*out)->pdu_len, *out);
	
	lws_write(primary_hub.wsi, (*out)->payload, (*out)->pdu_len, LWS_WRITE_BINARY);
	lws_ring_consume(primary_hub.outgoing, NULL, NULL, 1);

	
	lws_callback_on_writable(primary_hub.wsi);
      }
    }
    break;
  }  
  return lws_callback_http_dummy(wsi, reason, user, in, len);
}


/**
 * Set the virtual Broadcast address for BACnet/SC (0xffffffffffff)
 *
 */
void bsc_get_broadcast_address(BACNET_ADDRESS *dest) {
  if (dest) {
    dest->mac_len = 6;
    memset(dest->mac, 0xff, 6);	/* broadcast VMAC */

    /* no SADR */
    dest->len = 0;
    memset(dest->adr, 0, sizeof(dest->adr));
    dest->net = BACNET_BROADCAST_NETWORK;
  }
}

void bsc_get_my_address(BACNET_ADDRESS *dest) {
  if (dest) {
    dest->mac_len = 6;
    memcpy(dest->mac, local_vmac, 6);

    dest->len = 0;
    memset(dest->adr, 0, sizeof(dest->adr));
    dest->net = 0;
  }
}

/** 
 * Setup the WebSocket connection struct and kickoff the connection
 *
 */
bool bsc_init(char *u) {
  struct lws_context_creation_info info;
  const char *prot, *ads, *path;
  int port;

  if (u == NULL) {
    fprintf(stderr, "BSC: set BACNET_IFACE to primary hub URL\n");
    return false;
  }

  strncpy(primary_hub.url, u, BSC_MAX_WSURL);
  if (lws_parse_uri(primary_hub.url, &prot, &ads, &port, &path) != 0) {
    return false;
  }
  // must be wss;
  if (strcmp(prot, "wss") != 0) {
    return false;
  }

  if (BSC_Debug) {
    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
  } else {
    lws_set_log_level(LLL_ERR, NULL);
  }

  memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
  info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
  info.protocols = protocols;
  info.fd_limit_per_thread = 1 + 1 + 1;

  char *pEnv = getenv("BACNET_SC_CAFILE");
  if (pEnv) {
    if (BSC_Debug) 
      fprintf(stderr, "BSC: setting CA file: %s\n", pEnv);
    info.ssl_ca_filepath = pEnv;
  }

  pEnv = getenv("BACNET_SC_KEYFILE");
  if (pEnv) {
    if (BSC_Debug)
      fprintf(stderr, "BSC: setting key file: %s\n", pEnv);
    info.ssl_private_key_filepath = pEnv;
  }

  pEnv = getenv("BACNET_SC_CERTFILE");
  if (pEnv) {
    if (BSC_Debug)
      fprintf(stderr, "BSC: setting client certificate: %s\n", pEnv);
    info.ssl_cert_filepath = pEnv;
  }
  
  primary_hub.context = lws_create_context(&info);
  if (!primary_hub.context) {
    lwsl_err("lws init failed\n");
    return false;
  }
  /* set up the connection structure */
  memset(&primary_hub.info, 0, sizeof(primary_hub.info));
  primary_hub.info.context = primary_hub.context;
  primary_hub.info.port = port;
  primary_hub.info.protocol = ws_protocol;
  primary_hub.info.local_protocol_name = primary_hub.info.protocol;
  primary_hub.info.path = "/";
  primary_hub.info.address = ads;
  primary_hub.info.origin = primary_hub.info.address;
  primary_hub.info.host = primary_hub.info.address;
  primary_hub.info.alpn = "h2;http/1.1";
  primary_hub.info.retry_and_idle_policy = &retry;
  primary_hub.info.ssl_connection = LCCSCF_USE_SSL  | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
  primary_hub.info.pwsi = &primary_hub.wsi;
  primary_hub.info.context = primary_hub.context;

  primary_hub.outgoing = lws_ring_create(sizeof(struct bsc_message*), 10, free_outgoing);
  primary_hub.incoming = NULL;

  lws_sul_schedule(primary_hub.context, 0, &sul, connect_cb, 100);
  return true;
}

/*
 * Encode the BVLL header for a original broadcast message
 */
uint16_t bsc_bvll_encode_original_broadcast(uint8_t *mtu, int mtu_len, uint8_t *pdu, unsigned pdu_len) {
  mtu[0] = BSC_BVLC_ENCAPSULATED_NPDU;  /* function */
  mtu[1] = BSC_BVLC_CONTROL_DEST_VADDR; /* control flags */
  mtu[2] = (primary_hub.ident >> 8) & 0xff;		/* ident */
  mtu[3] = primary_hub.ident++ & 0xff;
  memset(&mtu[4], 0xff, 6);             /* Dest BVADDR = broadcast MAC */
  memcpy(&mtu[10], pdu, pdu_len);       /* payload */
  return pdu_len + 10;
}

/*
 * Encode an Encapsulated-NPDU packet
 */
int bsc_bvll_encode_original_unicast(BACNET_ADDRESS *dest,
					  uint8_t *mtu, int mtu_len, uint8_t *pdu, unsigned pdu_len) {
  int offset = 4;
  if (mtu_len < 4) {
    return -1;
  }
  mtu[0] = BSC_BVLC_ENCAPSULATED_NPDU;
  mtu[1] = 0;
  mtu[2] = (primary_hub.ident >> 8) & 0xff;		/* ident */
  mtu[3] = primary_hub.ident++ & 0xff;

  if (memcmp(dest->mac, primary_hub.vmac, 6) != 0) {
    /* include the destination VMAC */
    if (mtu_len < 10) {
      return -1;
    }
    
    mtu[1] = BSC_BVLC_CONTROL_DEST_VADDR;
    memcpy(&mtu[offset], &dest->mac[0], 6);
    offset += 6;
  }

  if (pdu_len + offset > mtu_len) {
    return -1;
  }

  memcpy(&mtu[offset], pdu, pdu_len);
  return pdu_len + offset;
}

int bsc_send_pdu(BACNET_ADDRESS *dest, BACNET_NPDU_DATA *data, uint8_t *pdu, unsigned pdu_len) {
  if (BSC_Debug)
    printf("BSC: send len: %d net: %d mac_len: %d\n",
	   dest->len, dest->net, dest->mac_len);
  struct bsc_message *out = alloc_outgoing(pdu_len);
  if (out == NULL) {
    return -1;
  }
  if (dest->net == BACNET_BROADCAST_NETWORK || dest->mac_len == 0) {
    // broadcast message
    out->pdu_len = bsc_bvll_encode_original_broadcast(out->payload, out->pdu_len, pdu, pdu_len);
    if (BSC_Debug)
      printf("BSC: Encoding original broadcast %d %p\n", out->pdu_len, out);
  } else if (dest->mac_len == 6) {
    out->pdu_len = bsc_bvll_encode_original_unicast(dest, out->payload, out->pdu_len,
						    pdu, pdu_len);
    if (BSC_Debug)
      printf("BSC: Encoding original unicast PDU\n");
  }

  if (out->pdu_len <= 0) {
    free_outgoing(out);
    return -1;
  }

  if (lws_ring_insert(primary_hub.outgoing, &out, 1) == 1) {
    if (primary_hub.wsi != NULL) {
      lws_callback_on_writable(primary_hub.wsi);
    }
    return out->pdu_len;
  } else {
    return -1;
  }
}

void bsc_cleanup(void) {
  lws_context_destroy(primary_hub.context);
}


/*
 * After completing a websocket connection, we need to send a
 * connection request with our VMAC and UUID.
 *
 */ 
void bsc_bvlc_send_connection_request(struct sc_connection *conn) {
  uint8_t buf[LWS_PRE + 30];
  uint8_t *mtu = &buf[LWS_PRE];

  *mtu++ = BSC_BVLC_CONNECTION_REQUEST;
  *mtu++ = 0;			/* control, no flags */
  *mtu++ = (conn->ident >> 8) & 0xff;		/* ident */
  *mtu++ = conn->ident++ & 0xff;

  // data fields: VMAC[6], UUID[16], max_bcl
  memcpy(mtu, local_vmac, 6); mtu += 6;
  memcpy(mtu, local_uuid, 16); mtu += 16;


  *mtu++ = (BSC_MPDU_MAX >> 8) & 0xff;
  *mtu++ = (BSC_MPDU_MAX) & 0xff;
  *mtu++ = (BSC_MPDU_MAX >> 8) & 0xff;
  *mtu++ = (BSC_MPDU_MAX) & 0xff;

  if (BSC_Debug)
    printf("BSC: Sending connection request\n");

  lws_write(conn->wsi, &buf[LWS_PRE], 30, LWS_WRITE_BINARY);
}


/*
 * Parse the connection accept function and update the VMAC and UUID
 * fields of the connection structure.
 */
void bsc_bvlc_decode_connection_accept(struct sc_connection *conn, uint8_t *payload, size_t len) {
  if (len < 30 || payload[0] != BSC_BVLC_CONNECTION_ACCEPT) {
    if (BSC_Debug) 
      printf("Short accept %lu\n",    len);
    return;
  }
  if (payload[1] != 0) {
    // what moron put tlv headers here
    return;
  }

  payload += 4;			/* skip fixed header */
  memcpy(&conn->vmac[0],  payload, 6); payload += 6;
  memcpy(&conn->uuid[0], payload, 16); payload += 16;

  conn->max_bvlc = payload[0] << 8 | payload[1]; payload += 2;
  conn->max_npdu = payload[0] << 8 | payload[1]; payload += 2;

  if (BSC_Debug)
    printf("accept control: max_bvlc %d max_npdu %d\n", conn->max_bvlc, conn->max_npdu);
}



/*
 * If the header indicates optional fields are present, 
 * skip over them and return the number of bytes consumed.
 */
int bsc_bvlc_decode_options(uint8_t *pdu, int len) {
  int offset = 0;
  while (offset < len) {
    uint8_t hctl = pdu[offset];
    if (hctl & BSC_BVLC_HEADER_DATA && offset + 2 < len) {
      uint16_t size = (pdu[offset+1] << 8) | pdu[offset+2];
      offset += 3 + size;
    } else {
      offset += 1;
    }
    /* ignore must_understand flag, for now */
    if (!(hctl & BSC_BVLC_HEADER_MORE)) {
      break;
    }
  }
  return offset;
}


/*
 * Decode the BACnet/SC BVLL header and populate the address
 * information with the source address.  Return the number of bytes to
 * skip.
 */
int  bsc_bvlc_decode_header(struct sc_connection *conn, BACNET_ADDRESS *src,
			   uint8_t *pdu, int len) {

  int offset = 4;		/* skip the header */
  
  src->mac_len = 6;
  if (pdu[1] & BSC_BVLC_CONTROL_ORIG_VADDR) {
    /* if an origin VMAC is present, use that */
    memcpy(src->mac, &pdu[offset], 6);
    offset += 6;
  } else {
    /* otherwise it is the VMAC of the peer; */
    memcpy(src->mac, conn->vmac, 6);
  }

  if (pdu[1] & BSC_BVLC_CONTROL_DEST_VADDR) {
    offset += 6;		/* and skip the dest addr */
  }
  
  if (pdu[1] & BSC_BVLC_CONTROL_DATA_OPTIONS) {
    /* consume optional headers */
    offset += bsc_bvlc_decode_options(&pdu[offset], len - offset);
  }

  if (BSC_Debug)
    printf("BSC: header offset: %d\n", offset);
  return offset;
}

/*
 * Called to decode a BVLC-Result frame
 *
 * Currently the only use of this information is to process NAK
 * results of connection attempts, and print the included error
 * message to assist with debugging.
 */
void bsc_bvlc_decode_result(struct sc_connection *conn, uint8_t *payload, size_t len) {
  BACNET_ADDRESS src;
  int offset = bsc_bvlc_decode_header(conn, &src, payload, len);
  uint8_t function = payload[offset];
  uint8_t result = payload[offset+1];
  // skip the Error Header Marker
  if (result == 1 && len >= 6 ) {
    uint16_t error_class = payload[offset+3] << 8 | payload[offset+4];
    uint16_t error_code = payload[offset+5] << 8 | payload[offset+6];
    char message[256];

    memset(message, 0, 256);
    if (len >= 7) 
      memcpy(message, &payload[offset+7], len+offset+7 < len ? len+offset+7: 255);

    printf("BSC: received result NAK: function=%u errorClass=%s errorCode=%s message=\"%s\"\n",
	   function,
	   bactext_error_class_name((int)error_class),
	   bactext_error_code_name((int)error_code),
	   message);
  }
}

/* 
 * Called on a received data frame
 */ 
void bsc_bvlc_receive(struct lws *wsi, uint8_t *payload, size_t len) {
  /* minimum header size */
  if (len < 4) {
    return;
  }
  switch (payload[0]) {
  case BSC_BVLC_CONNECTION_ACCEPT:
    if (BSC_Debug)
      printf("BSC: connection accepted\n");
    primary_hub.state = CONNECTED;
    bsc_bvlc_decode_connection_accept(&primary_hub, payload, len);
    break;
  case BSC_BVLC_ENCAPSULATED_NPDU:
    if (BSC_Debug)
      printf("BSC: data received len: %lu\n", len);
    if (primary_hub.incoming == NULL) {
      primary_hub.incoming = alloc_outgoing(len);
      memcpy(primary_hub.incoming->buf, payload, len);
    } else {
      printf("BSC: no room for incomming; dropping\n");
    }
    break;
  case BSC_BVLC_RESULT:
    bsc_bvlc_decode_result(&primary_hub, payload, len);
    break;
  default:
    break;
  }
}

uint16_t bsc_receive(BACNET_ADDRESS *src,
        uint8_t *pdu,
        uint16_t max_pdu,
        unsigned timeout) {
  int n = 1;
  if (primary_hub.state == CONNECTED) {
    if (lws_ring_get_element(primary_hub.outgoing, NULL) != NULL) {
      lws_callback_on_writable(primary_hub.wsi);
    }
  }

  lws_service(primary_hub.context, timeout);

  if (primary_hub.incoming != NULL) {
    int len = 0, pdu_len = primary_hub.incoming->pdu_len - BSC_MAX_HEADER;

    len = bsc_bvlc_decode_header(&primary_hub, src,
				 primary_hub.incoming->buf, pdu_len);
    if (len < 0) {
      
    } else if (pdu_len - len > max_pdu) {
      /* too big */
      len = -1;
    } else {
      pdu_len -= len;
      memcpy(pdu, primary_hub.incoming->buf + len, pdu_len);
    }

    free_outgoing(&primary_hub.incoming);
    primary_hub.incoming = NULL;

    return pdu_len;
  }
  return 0;
}

void bsc_maintainence_timer(uint16_t seconds) {

}
