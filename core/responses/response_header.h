#pragma once

#include "base_response.h"

// access response registry has table and response count
extern int response_count;
extern ke_response *responses[];

// alert response
extern ke_response alert_response;
int alert_execute(struct ke_event_header *event);

// allow response
extern ke_response allow_response;
int allow_execute(struct ke_event_header *event);

// block response
extern ke_response block_response;
int block_execute(struct ke_event_header *event);