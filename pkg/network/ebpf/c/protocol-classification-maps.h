#ifndef __PROTOCOL_CLASSIFICATION_MAPS_H
#define __PROTOCOL_CLASSIFICATION_MAPS_H

#include "protocol-classification-defs.h"
#include "map-defs.h"

// Maps a connection tuple to its classified protocol. Used to reduce redundant classification procedures on the same
// connection. Assumption: each connection has a single protocol.
BPF_HASH_MAP(connection_protocol, conn_tuple_t, protocol_t, 1024)

#endif
