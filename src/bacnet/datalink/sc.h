/**************************************************************************
 *
 * Copyright (C) 2022 Stephen Dawson-Haggerty <sdhags@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *********************************************************************/
#ifndef BSC_H
#define BSC_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bacnet/bacnet_stack_exports.h"
#include "bacnet/bacdef.h"
#include "bacnet/npdu.h"
#include "bacnet/datalink/bvlc.h"

#define BSC_MPDU_MAX 1440

/*

 * BACnet/SC BVLC Function Codes
 */
#define BSC_BVLC_RESULT                 0x00
#define BSC_BVLC_ENCAPSULATED_NPDU      0x01
#define BSC_BVLC_CONNECTION_REQUEST     0x06
#define BSC_BVLC_CONNECTION_ACCEPT      0x07
#define BSC_BVLC_HEARTBEAT_REQUEST      0x0a
#define BSC_BVLC_HEARTBEAT_ACK          0x0b

#define BSC_BVLC_CONTROL_DATA_OPTIONS        (1<<0)
#define BSC_BVLC_CONTROL_DEST_OPTIONS        (1<<1)
#define BSC_BVLC_CONTROL_DEST_VADDR          (1<<2)
#define BSC_BVLC_CONTROL_ORIG_VADDR          (1<<3)

#define BSC_BVLC_HEADER_DATA                 (1 << 5)
#define BSC_BVLC_HEADER_MUST_UNDERSTAND      (1 << 6)
#define BSC_BVLC_HEADER_MORE                 (1 << 7)


#define BSC_MAX_WSURL 256
#define BSC_MAX_HEADER 20

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    /* note: define init, set_interface, and cleanup in your port */
    /* on Linux, ifname is eth0, ath0, arc0, and others.
       on Windows, ifname is the dotted ip address of the interface */
    BACNET_STACK_EXPORT
    bool bsc_init(char *wsurl);

    BACNET_STACK_EXPORT
    void bsc_cleanup(void);

    /* common BACnet/IP functions */
    BACNET_STACK_EXPORT
    bool bsc_valid(void);

    BACNET_STACK_EXPORT
    void bsc_get_broadcast_address(BACNET_ADDRESS *dest);

    BACNET_STACK_EXPORT
    void bsc_get_my_address(BACNET_ADDRESS *my_address);

    BACNET_STACK_EXPORT
    int bsc_send_pdu(BACNET_ADDRESS *dest,
        BACNET_NPDU_DATA *npdu_data,
        uint8_t *pdu,
        unsigned pdu_len);

    BACNET_STACK_EXPORT
    uint16_t bsc_receive(BACNET_ADDRESS *src,
        uint8_t *pdu,
        uint16_t max_pdu,
        unsigned timeout);

    BACNET_STACK_EXPORT
    void bsc_maintainence_timer(uint16_t elapsed);

#ifdef __cplusplus
}
#endif /* __cplusplus */
/** @defgroup DLBSC BACnet/SC DataLink Network Layer
 * @ingroup DataLink
 * Implementation of the Network Layer using BACnet/SC as the transport, as
 * described in Annex AB.
 * The functions described here fulfill the roles defined generically at the
 * DataLink level by serving as the implementation of the function templates.
 *
 */
#endif
