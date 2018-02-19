#ifndef __TS_PARSER_H__
#define __TS_PARSER_H__


#define TS_PACKET_SIZE	  188
#define TS_SYNC			  0x47
#define TS_DISCONTINUITY  0x0

#define TS_STREAM_VIDEO	  0x1b
#define TS_STREAM_AUDIO   0x0f

#include "bitreader.h"

uint16_t getPMTFromPAT(ABitReader *bitReader, uint16_t requested_program);
uint16_t parse_packet(ABitReader *bitReader, uint16_t requested_program, uint16_t, uint16_t*, int*);
void getStreamsFromPMT(ABitReader *bitReader, uint16_t requested_program, uint16_t*, int*);
void parseAdaptationField(ABitReader *bitReader);
int sendPid(uint16_t, uint16_t*, int*);
int add_stream(uint16_t, uint16_t*, int*);

#endif
