/*
 * MpegtTS Basic Parser
 * Copyright (c) jeoliva, All rights reserved.

 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 *License along with this library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "mtrace.h"
#include "bitreader.h"
#include "tsparser.h"

extern FILE*  g_flog;

uint16_t parse_packet(ABitReader *bitReader, uint16_t requested_program, uint16_t search_pmt,
        uint16_t* stream_pids, int* num_streams) {

    uint16_t to_return = 0;

    uint16_t transport_error_indicator;
    uint16_t pid;
    uint16_t payload_unit_start_indicator;
    uint16_t adaptation_field_control;
    /*uint32_t continuity_counter;*/

    uint8_t sync_byte;
    sync_byte = getBits(bitReader, 8); // sync byte
    if (sync_byte != TS_SYNC) {
        TRACE( (void)tmfprintf (g_flog, "Received non-sync byte\n") );
        return 0;
    }

    transport_error_indicator = getBits(bitReader, 1);
    if (transport_error_indicator) {
        TRACE( (void)tmfprintf (g_flog, "Packet with transport error indicator set\n") );
        return 0;
    }

    payload_unit_start_indicator = getBits(bitReader, 1);
    skipBits(bitReader, 1); // transport priority
    pid = getBits(bitReader, 13); // 
    skipBits(bitReader, 2); // transport scrambling control
    adaptation_field_control = getBits(bitReader, 2);
    /*continuity_counter = getBits(bitReader, 4);*/
    skipBits(bitReader, 4); // continuity_counter

    if(adaptation_field_control == 2 || adaptation_field_control == 3)
    {
        parseAdaptationField(bitReader);
    }

    if(adaptation_field_control == 1 || adaptation_field_control == 3)
    {

        if (payload_unit_start_indicator) {
            uint32_t skip = getBits(bitReader, 8);
            skipBits(bitReader, skip * 8);
        }

        if (pid == 0) {
            to_return = getPMTFromPAT(bitReader, requested_program);
        }
        else if (pid == search_pmt) {
            getStreamsFromPMT(bitReader, requested_program, stream_pids, num_streams);
            to_return = pid;
        }
        else if (num_streams != 0 && (*num_streams) > 0) {
            to_return = pid;
        }

    }
    skipBits(bitReader, 32); // CRC
    return to_return;
}

int sendPid(uint16_t pid, uint16_t* stream_pids, int* num_streams) {
    for (int i=0; i < *num_streams; i++) {
        if (stream_pids[i] == pid) {
            return 1;
        }
    }
    return 0;
}


// Parse Program Association table
uint16_t getPMTFromPAT(ABitReader *bitReader, uint16_t requested_program)
{
    size_t i;
    uint16_t pmt_pid = 0;
    skipBits(bitReader, 8); // table_id
    skipBits(bitReader, 1); // section_syntax_indicator
    skipBits(bitReader, 1);
    skipBits(bitReader, 2); // reserved

    uint16_t section_length = getBits(bitReader, 12);

    skipBits(bitReader, 16); // transport_stream_id
    skipBits(bitReader, 2); // reserved
    skipBits(bitReader, 5); // version_number
    skipBits(bitReader, 1); // current_next_indicator
    skipBits(bitReader, 8); // section_number
    skipBits(bitReader, 8); // last_section_number

    size_t numProgramBytes = (section_length - 5 /* header */ - 4 /* crc */);

    for (i = 0; i < numProgramBytes / 4; ++i)	{
        uint16_t program_number = getBits(bitReader, 16);

        skipBits(bitReader, 3); // reserved

        if (program_number == 0) {
            skipBits(bitReader, 13); // network_PID
        } else if (program_number == requested_program) {
            pmt_pid = getBits(bitReader, 13);
        } else {
            skipBits(bitReader, 13);
        }
    }
    skipBits(bitReader, 32); // CRC
    return pmt_pid;
}

int add_stream(uint16_t stream_pid, uint16_t* stream_pids, int* num_streams) {
    int found = 0;
    for (int i=0; i < *num_streams; i++) {
        if (stream_pid == stream_pids[i]) {
            found = 1;
            break;
        }
    }
    if (1 != found) {
        TRACE( (void)tmfprintf( g_flog, "found stream 0x%04x; %d found so far\n",
                                stream_pid, (*num_streams)) );
        stream_pids[*num_streams] = stream_pid;
        (*num_streams)++;
        return 1;
    }
    return 0;
}

// Parse program map
void getStreamsFromPMT(ABitReader *bitReader, uint16_t requested_program,
        uint16_t* stream_pids, int* num_streams)
{
    uint32_t section_length;
    uint32_t program_info_length;
    size_t infoBytesRemaining;
    uint16_t elementaryPID;
    uint32_t ES_info_length;
    uint32_t info_bytes_remaining;

    uint16_t program_number;
    uint16_t pcr_pid;

    skipBits(bitReader, 8); // table_id

    skipBits(bitReader, 1); // section_syntax_indicator
    skipBits(bitReader, 3); // reserved

    section_length = getBits(bitReader, 12);
    program_number = getBits(bitReader, 16);

    skipBits(bitReader, 2); // reserved
    skipBits(bitReader, 5); // version_number
    skipBits(bitReader, 1); // current_next_indicator
    skipBits(bitReader, 8); // section_number
    skipBits(bitReader, 8); // last_section_number
    skipBits(bitReader, 3); // reserved

    pcr_pid = getBits(bitReader, 13); // pcr_pid
    add_stream(pcr_pid, stream_pids, num_streams);

    skipBits(bitReader, 4); // reserved

    program_info_length = getBits(bitReader, 12);

    skipBits(bitReader, program_info_length * 8);  // skip descriptors

    // infoBytesRemaining is the number of bytes that make up the
    // variable length section of ES_infos. It does not include the
    // final CRC.
    infoBytesRemaining = section_length - 9 - program_info_length - 4;

    while (infoBytesRemaining > 0) {
        skipBits(bitReader, 8); // streamType
        skipBits(bitReader, 3); // reserved

        elementaryPID = getBits(bitReader, 13);
        if (program_number == requested_program) {
            add_stream(elementaryPID, stream_pids, num_streams);
        }

        skipBits(bitReader, 4);

        ES_info_length = getBits(bitReader, 12);
        info_bytes_remaining = ES_info_length;

        while (info_bytes_remaining >= 2)
        {
            uint32_t descLength;
            skipBits(bitReader, 8); // tag
            descLength = getBits(bitReader, 8);
            skipBits(bitReader, descLength * 8);
            info_bytes_remaining -= descLength + 2;
        }

        infoBytesRemaining -= 5 + ES_info_length;
    }

    skipBits(bitReader, 32); // CRC
}

// Parse adaptation field
void parseAdaptationField(ABitReader *bitReader)
{
    uint32_t adaptation_field_length = getBits(bitReader, 8);
    if (adaptation_field_length > 0)
    {
        skipBits(bitReader, adaptation_field_length * 8);
    }
}
