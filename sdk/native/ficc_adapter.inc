/* SPDX-License-Identifier: Apache-2.0 */
/* This file shares the bounded JSON codec in ficc_module.c. */
struct ficc_adapter {
    const cJSON *request;
    size_t input, output;
    unsigned calls;
    int failed;
};

static int adapter_text(const cJSON *value, size_t maximum) {
    if (!cJSON_IsString(value) || !*value->valuestring || text_size(value->valuestring) > maximum) return 0;
    for (const unsigned char *p = (const unsigned char *)value->valuestring; *p; ++p)
        if (*p < 32) return 0;
    return 1;
}

static int adapter_hash(const cJSON *value, size_t size) {
    if (!cJSON_IsString(value) || strlen(value->valuestring) != size) return 0;
    for (const char *p = value->valuestring; *p; ++p)
        if (!strchr("0123456789abcdef", *p)) return 0;
    return 1;
}

static int adapter_object(const cJSON *value, int count) {
    return cJSON_IsObject(value) && cJSON_GetArraySize(value) == count;
}

static int adapter_private(const cJSON *value) {
    if (!cJSON_IsObject(value) || !bounded(value, 0)) return 0;
    char *encoded = cJSON_PrintUnformatted(value);
    int valid = encoded && strlen(encoded) <= 65536;
    free(encoded);
    return valid;
}

static int adapter_valid(const cJSON *hello, const cJSON *request) {
    if (!bounded(hello, 0) || !bounded(request, 0) || !adapter_object(hello, 3) ||
        !one(get(hello, "version")) || !one(get(hello, "host_api")) ||
        !string_is(get(hello, "type"), "adapter-hello") || !adapter_object(request, 7) ||
        !one(get(request, "version")) || !string_is(get(request, "type"), "adapter-invoke") ||
        !adapter_hash(get(request, "id"), 32) || !adapter_hash(get(request, "digest"), 64) ||
        !adapter_text(get(request, "phase"), 16)) return 0;
    const char *phase = get(request, "phase")->valuestring;
    int mutation = !strcmp(phase, "prepare") || !strcmp(phase, "apply") || !strcmp(phase, "observe");
    int empty = !strcmp(phase, "probe") || !strcmp(phase, "inventory");
    int intent = !strcmp(phase, "apply") || !strcmp(phase, "observe");
    int observe = !strcmp(phase, "observe");
    if ((!mutation && !empty && strcmp(phase, "status") && strcmp(phase, "console")) ||
        (mutation ? !string_is(get(request, "action"), "start") && !string_is(get(request, "action"), "shutdown") :
                    !string_is(get(request, "action"), phase))) return 0;
    const cJSON *bindings = get(request, "bindings");
    if (!cJSON_IsArray(bindings) || cJSON_GetArraySize(bindings) < 1 || cJSON_GetArraySize(bindings) > 64) return 0;
    unsigned count = 0;
    for (const cJSON *binding = bindings->child; binding; binding = binding->next) {
        if (!adapter_object(binding, 7 + intent + observe) || !adapter_hash(get(binding, "id"), 32) ||
            !adapter_hash(get(binding, "endpoint_id"), 32) || !adapter_hash(get(binding, "machine_identity"), 64) ||
            !cJSON_IsNumber(get(binding, "endpoint_revision")) || get(binding, "endpoint_revision")->valuedouble < 1 ||
            floor(get(binding, "endpoint_revision")->valuedouble) != get(binding, "endpoint_revision")->valuedouble ||
            (!string_is(get(binding, "consistency"), "provider-lock") &&
             !string_is(get(binding, "consistency"), "checked-before-dispatch")) ||
            !adapter_private(get(binding, "parameters")) ||
            (intent && !adapter_private(get(binding, "intent"))) || (observe && !adapter_private(get(binding, "receipt")))) return 0;
        for (const cJSON *prior = bindings->child; prior != binding; prior = prior->next)
            if (string_is(get(prior, "id"), get(binding, "id")->valuestring)) return 0;
        const cJSON *resources = get(binding, "resources");
        if (!cJSON_IsArray(resources) || cJSON_GetArraySize(resources) > 64 ||
            (!empty && cJSON_GetArraySize(resources) < 1)) return 0;
        count += cJSON_GetArraySize(resources);
        for (const cJSON *item = resources->child; item; item = item->next) {
            if (!adapter_object(item, 5) || !adapter_hash(get(item, "id"), 32) ||
                !adapter_hash(get(item, "birth"), 64) || !adapter_hash(get(item, "revision"), 64) ||
                !adapter_text(get(item, "key"), 128) || !adapter_text(get(item, "state"), 16)) return 0;
            const char *state = get(item, "state")->valuestring;
            if (strcmp(state, "unknown") && strcmp(state, "running") && strcmp(state, "blocked") && strcmp(state, "paused") &&
                strcmp(state, "shutting-down") && strcmp(state, "off") && strcmp(state, "crashed") && strcmp(state, "suspended")) return 0;
            for (const cJSON *prior = resources->child; prior != item; prior = prior->next)
                if (string_is(get(prior, "id"), get(item, "id")->valuestring)) return 0;
        }
    }
    return empty ? count == 0 : count > 0 && count <= 64;
}

cJSON *ficc_adapter_call(ficc_adapter *adapter, const char *profile_id, const cJSON *commands) {
    cJSON *request = NULL, *reply = NULL, *result = NULL;
    char identity[33], *encoded = NULL;
    int found = 0;
    if (!adapter || adapter->failed || ++adapter->calls > 16 || !profile_id || !hex_id(profile_id) ||
        !cJSON_IsArray(commands) || cJSON_GetArraySize(commands) < 1 || cJSON_GetArraySize(commands) > 64 || !bounded(commands, 0)) goto done;
    for (const cJSON *binding = get(adapter->request, "bindings")->child; binding; binding = binding->next)
        if (string_is(get(binding, "id"), profile_id)) found = 1;
    if (!found) goto done;
    for (const cJSON *item = commands->child; item; item = item->next)
        if (!adapter_object(item, 2) || !adapter_text(get(item, "command"), 96) || !adapter_private(get(item, "parameters"))) goto done;
    encoded = cJSON_PrintUnformatted(commands);
    if (!encoded || strlen(encoded) > 65536) goto done;
    snprintf(identity, sizeof(identity), "%032x", adapter->calls);
    if (string_is(get(adapter->request, "id"), identity)) identity[0] = 'f';
    request = cJSON_CreateObject();
    if (!request || !cJSON_AddNumberToObject(request, "version", 1) ||
        !cJSON_AddStringToObject(request, "type", "adapter-transport") ||
        !cJSON_AddStringToObject(request, "id", identity) ||
        !cJSON_AddStringToObject(request, "invocation_id", get(adapter->request, "id")->valuestring) ||
        !cJSON_AddStringToObject(request, "profile_id", profile_id) ||
        !cJSON_AddItemToObject(request, "commands", cJSON_Duplicate(commands, 1)) || !send_value(request, &adapter->output)) goto done;
    reply = read_counted(&adapter->input);
    if (!bounded(reply, 0) || !adapter_object(reply, 6) || !one(get(reply, "version")) ||
        !string_is(get(reply, "type"), "adapter-transport-result") || !string_is(get(reply, "id"), identity) ||
        !string_is(get(reply, "invocation_id"), get(adapter->request, "id")->valuestring) ||
        !string_is(get(reply, "profile_id"), profile_id) || !cJSON_IsArray(get(reply, "results")) ||
        cJSON_GetArraySize(get(reply, "results")) != cJSON_GetArraySize(commands)) goto done;
    result = cJSON_Duplicate(get(reply, "results"), 1);
done:
    if (!result && adapter) adapter->failed = 1;
    free(encoded); cJSON_Delete(request); cJSON_Delete(reply);
    return result;
}

static int adapter_results(const cJSON *results, const cJSON *bindings) {
    if (!bounded(results, 0) || !cJSON_IsArray(results) || cJSON_GetArraySize(results) != cJSON_GetArraySize(bindings)) return 0;
    const cJSON *binding = bindings->child;
    for (const cJSON *item = results->child; item; item = item->next, binding = binding->next) {
        const cJSON *error = get(item, "error"), *data = get(item, "data");
        if (!adapter_object(item, 2) || !string_is(get(item, "profile_id"), get(binding, "id")->valuestring) ||
            (!error == !data) || (data && !cJSON_IsObject(data))) return 0;
        if (error && (!adapter_object(error, 2) || !adapter_text(get(error, "code"), 96) ||
            !identifier(get(error, "code")->valuestring) || !adapter_text(get(error, "message"), 1024))) return 0;
    }
    return 1;
}

int ficc_serve_adapter(ficc_adapter_handler handler) {
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
    ficc_adapter adapter = {0};
    cJSON *hello = read_counted(&adapter.input), *request = read_counted(&adapter.input);
    cJSON *frozen = NULL, *result = NULL, *ack = NULL;
    int status = 1;
    if (!adapter_valid(hello, request)) goto done;
    frozen = cJSON_Duplicate(request, 1);
    if (!frozen) goto done;
    adapter.request = frozen;
    ack = cJSON_Parse("{\"version\":1,\"type\":\"adapter-hello\",\"protocol\":1}");
    if (!ack || !send_value(ack, &adapter.output)) goto done;
    cJSON *items = handler(request, &adapter);
    if (adapter.failed || !adapter_results(items, get(frozen, "bindings"))) { cJSON_Delete(items); goto done; }
    result = cJSON_CreateObject();
    if (!result || !cJSON_AddItemToObject(result, "results", items)) { cJSON_Delete(items); goto done; }
    if (!cJSON_AddNumberToObject(result, "version", 1) ||
        !cJSON_AddStringToObject(result, "type", "adapter-result") ||
        !cJSON_AddStringToObject(result, "id", get(frozen, "id")->valuestring)) goto done;
    if (send_value(result, &adapter.output)) status = 0;
done:
    cJSON_Delete(result); cJSON_Delete(ack); cJSON_Delete(frozen); cJSON_Delete(request); cJSON_Delete(hello);
    if (status) fputs("Invalid provider request, cancellation or result.\n", stderr);
    return status;
}
