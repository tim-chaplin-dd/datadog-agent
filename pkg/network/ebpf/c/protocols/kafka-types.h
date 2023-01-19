#ifndef __KAFKA_TYPES_H
#define __KAFKA_TYPES_H

typedef enum
{
    KAFKA_PRODUCE = 0,
    KAFKA_FETCH
} kafka_operation_t;

typedef struct {
    int32_t message_size;
    int16_t api_key;
    int16_t api_version;
    int32_t correlation_id;
    int16_t client_id_size;
} kafka_header_t;

typedef struct {
    const char* buffer;
    uint32_t buffer_size;
    uint32_t offset;
    char* offset_as_pointer;
    kafka_header_t header;
} kafka_context_t;

#endif
