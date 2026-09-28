/* SPDX-License-Identifier: Apache-2.0 */
#include "ficc_module.h"
#include <math.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define FICC_MAX_FRAME (1024U * 1024U)

static size_t text_size(const char *value) {
    mbstate_t state = {0};
    size_t remaining = strlen(value), count = 0;
    while (remaining) {
        size_t size = mbrtowc(NULL, value, remaining, &state);
        if (size == (size_t)-1 || size == (size_t)-2 || !size) return SIZE_MAX;
        value += size; remaining -= size; ++count;
    }
    return count;
}

static int read_exact(unsigned char *data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        size_t count = fread(data + offset, 1, size - offset, stdin);
        if (!count) return 0;
        offset += count;
    }
    return 1;
}

static cJSON *read_counted(size_t *total) {
    unsigned char header[4];
    if (!read_exact(header, sizeof(header))) return NULL;
    uint32_t size = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
                    ((uint32_t)header[2] << 8) | header[3];
    if (!size || size > FICC_MAX_FRAME) return NULL;
    if (total && (*total += size + 4) > 2 * (FICC_MAX_FRAME + 4)) return NULL;
    char *data = malloc((size_t)size + 1);
    if (!data) return NULL;
    if (!read_exact((unsigned char *)data, size)) { free(data); return NULL; }
    data[size] = '\0';
    /* cJSON stores text as C strings. Refuse decoded NUL before parsing. */
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == '\\') {
            if (i + 5 < size && data[i + 1] == 'u' && !memcmp(data + i + 2, "0000", 4)) {
                free(data); return NULL;
            }
            ++i;
        }
    }
    const char *end = NULL;
    cJSON *value = cJSON_ParseWithLengthOpts(data, size + 1, &end, 1);
    if (memchr(data, '\0', size)) { cJSON_Delete(value); value = NULL; }
    free(data);
    return value;
}

static cJSON *read_frame(void) { return read_counted(NULL); }

static int bounded(const cJSON *value, unsigned depth) {
    if (!value || depth > 12) return 0;
    if (cJSON_IsNumber(value) && (!isfinite(value->valuedouble) ||
        fabs(value->valuedouble) > 9007199254740991.0)) return 0;
    if (cJSON_IsString(value) && text_size(value->valuestring) > 65536) return 0;
    unsigned count = 0;
    for (const cJSON *item = value->child; item; item = item->next) {
        if (++count > 256 || !bounded(item, depth + 1)) return 0;
        if (cJSON_IsObject(value)) {
            if (!item->string || text_size(item->string) > 240) return 0;
            for (const cJSON *previous = value->child; previous != item; previous = previous->next)
                if (!strcmp(previous->string, item->string)) return 0;
        }
    }
    return 1;
}

static const cJSON *get(const cJSON *value, const char *key) {
    return cJSON_GetObjectItemCaseSensitive(value, key);
}

static int string_is(const cJSON *value, const char *expected) {
    return cJSON_IsString(value) && !strcmp(value->valuestring, expected);
}

static int one(const cJSON *value) {
    return cJSON_IsNumber(value) && value->valuedouble == 1;
}

static int valid(const cJSON *hello, const cJSON *request) {
    if (!bounded(hello, 0) || !bounded(request, 0) || !cJSON_IsObject(hello) ||
        cJSON_GetArraySize(hello) != 3 || !one(get(hello, "version")) ||
        !one(get(hello, "host_api")) || !string_is(get(hello, "type"), "hello") ||
        !cJSON_IsObject(request) || cJSON_GetArraySize(request) != 6 ||
        !one(get(request, "version")) || !string_is(get(request, "type"), "invoke") ||
        !cJSON_IsString(get(request, "id")) || !cJSON_IsString(get(request, "action")) ||
        !cJSON_IsObject(get(request, "parameters"))) return 0;
    size_t id_size = text_size(get(request, "id")->valuestring);
    const cJSON *targets = get(request, "targets");
    if (!id_size || id_size > 128 || !cJSON_IsArray(targets) ||
        cJSON_GetArraySize(targets) < 1 || cJSON_GetArraySize(targets) > 64) return 0;
    for (const cJSON *item = targets->child; item; item = item->next) {
        if (!cJSON_IsString(item) || !*item->valuestring || text_size(item->valuestring) > 128 ||
            strpbrk(item->valuestring, "/\\:")) return 0;
        for (const cJSON *previous = targets->child; previous != item; previous = previous->next)
            if (!strcmp(previous->valuestring, item->valuestring)) return 0;
    }
    return 1;
}

static int write_frame(const char *data) {
    size_t size = strlen(data);
    if (!size || size > FICC_MAX_FRAME) return 0;
    unsigned char header[] = {(unsigned char)(size >> 24), (unsigned char)(size >> 16),
                              (unsigned char)(size >> 8), (unsigned char)size};
    return fwrite(header, 1, 4, stdout) == 4 && fwrite(data, 1, size, stdout) == size;
}

int ficc_serve(ficc_batch_handler handler) {
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
    cJSON *hello = read_frame(), *request = read_frame(), *result = NULL;
    char *encoded = NULL;
    int status = 1;
    if (!valid(hello, request) || fgetc(stdin) != EOF || ferror(stdin)) goto done;
    cJSON *items = handler(request);
    if (!items) goto done;
    result = cJSON_CreateObject();
    if (!result) { cJSON_Delete(items); goto done; }
    if (!cJSON_AddItemToObject(result, "results", items)) { cJSON_Delete(items); goto done; }
    if (!cJSON_AddNumberToObject(result, "version", 1) ||
        !cJSON_AddStringToObject(result, "type", "result") ||
        !cJSON_AddStringToObject(result, "id", get(request, "id")->valuestring)) goto done;
    if (!bounded(result, 0)) goto done;
    encoded = cJSON_PrintUnformatted(result);
    if (!encoded || strlen(encoded) > FICC_MAX_FRAME) goto done;
    if (write_frame("{\"version\":1,\"type\":\"hello\",\"protocol\":1}") &&
        write_frame(encoded) && !fflush(stdout)) status = 0;
done:
    free(encoded);
    cJSON_Delete(result); cJSON_Delete(request); cJSON_Delete(hello);
    if (status) fputs("Invalid module request or result.\n", stderr);
    return status;
}

struct ficc_broker {
    const cJSON *request;
    size_t input, output;
    unsigned calls;
    int failed;
};

static int number_is(const cJSON *value, double expected) {
    return cJSON_IsNumber(value) && value->valuedouble == expected;
}

static int identifier(const char *value) {
    size_t size = strlen(value);
    if (!size || size > 96 || value[0] < 'a' || value[0] > 'z') return 0;
    for (size_t i = 1; i < size; ++i)
        if (!strchr("abcdefghijklmnopqrstuvwxyz0123456789_.-", value[i])) return 0;
    return 1;
}

static int hex_id(const char *value) {
    if (strlen(value) != 32) return 0;
    for (size_t i = 0; i < 32; ++i)
        if (!strchr("0123456789abcdef", value[i])) return 0;
    return 1;
}

static int target_subset(const cJSON *selected, const cJSON *allowed) {
    if (!cJSON_IsArray(selected) || cJSON_GetArraySize(selected) < 1 ||
        cJSON_GetArraySize(selected) > 64) return 0;
    for (const cJSON *item = selected->child; item; item = item->next) {
        int found = 0;
        if (!cJSON_IsString(item)) return 0;
        for (const cJSON *other = allowed->child; other; other = other->next)
            if (string_is(other, item->valuestring)) found = 1;
        if (!found) return 0;
        for (const cJSON *previous = selected->child; previous != item; previous = previous->next)
            if (string_is(previous, item->valuestring)) return 0;
    }
    return 1;
}

static int results_valid(const cJSON *results, const cJSON *targets) {
    if (!cJSON_IsArray(results) || cJSON_GetArraySize(results) != cJSON_GetArraySize(targets)) return 0;
    const cJSON *target = targets->child;
    for (const cJSON *item = results->child; item; item = item->next, target = target->next) {
        const cJSON *error = get(item, "error"), *data = get(item, "data");
        if (!cJSON_IsObject(item) || cJSON_GetArraySize(item) != 2 ||
            !string_is(get(item, "target"), target->valuestring) || (!error == !data)) return 0;
        if (error && (!cJSON_IsObject(error) || cJSON_GetArraySize(error) != 2 ||
            !cJSON_IsString(get(error, "code")) || !identifier(get(error, "code")->valuestring) ||
            !cJSON_IsString(get(error, "message")) || text_size(get(error, "message")->valuestring) > 1024)) return 0;
    }
    return bounded(results, 0);
}

static int send_value(cJSON *value, size_t *total) {
    if (!bounded(value, 0)) return 0;
    char *encoded = cJSON_PrintUnformatted(value);
    if (!encoded) return 0;
    size_t size = strlen(encoded);
    int ok = (*total += size + 4) <= 2 * (FICC_MAX_FRAME + 4) && write_frame(encoded) && !fflush(stdout);
    free(encoded);
    return ok;
}

cJSON *ficc_broker_call(ficc_broker *broker, const char *primitive,
                       const cJSON *targets, const cJSON *parameters) {
    cJSON *request = NULL, *reply = NULL, *result = NULL;
    char identity[33], *encoded = NULL;
    if (broker->failed || ++broker->calls > 16 || !primitive || !identifier(primitive) ||
        !target_subset(targets, get(broker->request, "targets")) || !cJSON_IsObject(parameters) ||
        !bounded(parameters, 0)) goto done;
    encoded = cJSON_PrintUnformatted(parameters);
    if (!encoded || strlen(encoded) > 65536) goto done;
    snprintf(identity, sizeof(identity), "%032x", broker->calls);
    if (string_is(get(broker->request, "id"), identity)) identity[0] = 'f';
    request = cJSON_CreateObject();
    if (!request || !cJSON_AddNumberToObject(request, "version", 2) ||
        !cJSON_AddStringToObject(request, "type", "broker") ||
        !cJSON_AddStringToObject(request, "id", identity) ||
        !cJSON_AddStringToObject(request, "invocation_id", get(broker->request, "id")->valuestring) ||
        !cJSON_AddStringToObject(request, "primitive", primitive) ||
        !cJSON_AddItemToObject(request, "targets", cJSON_Duplicate(targets, 1)) ||
        !cJSON_AddItemToObject(request, "parameters", cJSON_Duplicate(parameters, 1)) ||
        !send_value(request, &broker->output)) goto done;
    reply = read_counted(&broker->input);
    if (!bounded(reply, 0) || !cJSON_IsObject(reply) || cJSON_GetArraySize(reply) != 5 ||
        !number_is(get(reply, "version"), 2) || !string_is(get(reply, "type"), "broker-result") ||
        !string_is(get(reply, "id"), identity) ||
        !string_is(get(reply, "invocation_id"), get(broker->request, "id")->valuestring) ||
        !results_valid(get(reply, "results"), targets)) goto done;
    result = cJSON_Duplicate(get(reply, "results"), 1);
done:
    if (!result) broker->failed = 1;
    free(encoded); cJSON_Delete(request); cJSON_Delete(reply);
    return result;
}

int ficc_serve_broker(ficc_broker_handler handler) {
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
    ficc_broker broker = {0};
    cJSON *hello = read_counted(&broker.input), *request = read_counted(&broker.input);
    cJSON *result = NULL, *ack = NULL;
    int status = 1;
    if (!bounded(hello, 0) || !bounded(request, 0) || !number_is(get(hello, "version"), 2) ||
        !number_is(get(request, "version"), 2) || !cJSON_IsString(get(request, "id")) ||
        !hex_id(get(request, "id")->valuestring)) goto done;
    /* Reuse the complete legacy request shape and target validation. */
    cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(hello, "version"), 1);
    cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(request, "version"), 1);
    if (!valid(hello, request) || !identifier(get(request, "action")->valuestring)) goto done;
    cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(request, "version"), 2);
    broker.request = request;
    ack = cJSON_Parse("{\"version\":2,\"type\":\"hello\",\"protocol\":2}");
    if (!ack || !send_value(ack, &broker.output)) goto done;
    cJSON *items = handler(request, &broker);
    if (!items || broker.failed || !results_valid(items, get(request, "targets"))) {
        cJSON_Delete(items); goto done;
    }
    result = cJSON_CreateObject();
    if (!result || !cJSON_AddItemToObject(result, "results", items)) { cJSON_Delete(items); goto done; }
    if (!cJSON_AddNumberToObject(result, "version", 2) ||
        !cJSON_AddStringToObject(result, "type", "result") ||
        !cJSON_AddStringToObject(result, "id", get(request, "id")->valuestring)) goto done;
    if (send_value(result, &broker.output)) status = 0;
done:
    cJSON_Delete(result); cJSON_Delete(ack); cJSON_Delete(request); cJSON_Delete(hello);
    if (status) fputs("Invalid module request, cancellation or broker result.\n", stderr);
    return status;
}

#include "ficc_adapter.inc"
