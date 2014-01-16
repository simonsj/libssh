/*
 * counters.c - counter functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013  by Andreas Schneider <asn@xxxxxxxxxxxxxx>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "libssh/counters.h"
#include "libssh/session.h"
#include "libssh/channels.h"

void ssh_set_session_counters(ssh_session session, ssh_bytes_counter scounter,
                              ssh_bytes_counter rcounter,
                              ssh_packet_counter pcounter) {
    if (session == NULL)
        return;

    session->socket_byte_counter = scounter;
    session->raw_byte_counter = rcounter;
    session->packet_counter = pcounter;
}

void ssh_set_channel_counters(ssh_channel channel,
                              ssh_bytes_counter bcounter) {
    if (channel == NULL)
        return;

    channel->bytes_counter = bcounter;
}
