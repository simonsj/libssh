/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* counters.h
 * This file includes the public declarations for the libssh counter mechanisms
 */

#ifndef _SSH_COUNTERS_H_
#define _SSH_COUNTERS_H_

#include <libssh/libssh.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup libssh_counters The libssh counters
 * @ingroup libssh
 *
 * Counters which can be used in libssh.
 *
 * @{
 */

struct ssh_bytes_counter_struct {
    uint64_t in_bytes;
    uint64_t out_bytes;
};

typedef struct ssh_bytes_counter_struct *ssh_bytes_counter;

struct ssh_packet_counter_struct {
    uint64_t in_packets;
    uint64_t out_packets;
};

typedef struct ssh_packet_counter_struct *ssh_packet_counter;

 /**
 * @brief Set the session data counters.
 *
 * This functions sets the counter structures to be used to calculate data
 * which come in and go out through the session at various points in time.
 *
 * @code
 * struct ssh_byte_counter_struct scounter = {
 *     .in_bytes = 0,
 *     .out_bytes = 0
 * };
 *
 * struct ssh_byte_counter_struct rcounter = {
 *     .in_bytes = 0,
 *     .out_bytes = 0
 * };
 *
 * struct ssh_packet_counter_struct pcounter = {
 *     .in_packets = 0,
 *     .out_packets = 0
 * };
 *
 * ssh_set_session_counters(session, &scounter, &rcounter, &pcounter);
 * @endcode
 *
 * @param  session      The session to set the counter structures.
 *
 * @param  scounter     The byte counter structure for data passed to sockets.
 *
 * @param  rcounter     The byte counter structure for raw data handled by the
 *                      session, prior compression and SSH overhead.
 *
 * @param  pcounter     The packet counter structure for SSH packets handled by
 *                      the session.
 */
LIBSSH_API void ssh_set_session_counters(ssh_session session,
                                         ssh_bytes_counter scounter,
                                         ssh_bytes_counter rcounter,
                                         ssh_packet_counter pcounter);

/**
 * @brief Set the channel data counters.
 *
 * This functions sets the counter structures to be used to calculate data
 * which come in and go out through the channel at various points in time.
 *
 * @code
 * struct ssh_byte_counter_struct bcounter = {
 *     .in_bytes = 0,
 *     .out_bytes = 0
 * };
 *
 * ssh_set_channel_counters(channel, &bcounter);
 * @endcode
 *
 * @param  channel      The channel to set the counter structures.
 *
 * @param  bcounter     The byte counter structure for raw data passed to the
 *                      channel.
 */
LIBSSH_API void ssh_set_channel_counters(ssh_channel channel,
                                         ssh_bytes_counter bcounter);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _SSH_COUNTERS_H_ */
