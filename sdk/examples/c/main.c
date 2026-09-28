/* SPDX-License-Identifier: Apache-2.0 */
#include "ficc_module.h"
#include <string.h>

static cJSON *echo_batch(const cJSON *request) {
    const cJSON *targets = cJSON_GetObjectItemCaseSensitive(request, "targets");
    const cJSON *action = cJSON_GetObjectItemCaseSensitive(request, "action");
    const cJSON *params = cJSON_GetObjectItemCaseSensitive(request, "parameters");
    const cJSON *message = cJSON_GetObjectItemCaseSensitive(params, "message");
    int supported = !strcmp(action->valuestring, "echo") && cJSON_IsString(message);
    cJSON *results = cJSON_CreateArray();
    if (!results) return NULL;
    int index = 0;
    for (const cJSON *target = targets->child; target; target = target->next, ++index) {
        cJSON *item = cJSON_CreateObject(), *value = cJSON_CreateObject();
        if (!item || !value) { cJSON_Delete(item); cJSON_Delete(value); goto fail; }
        if (!cJSON_AddItemToArray(results, item)) {
            cJSON_Delete(item); cJSON_Delete(value); goto fail;
        }
        if (!cJSON_AddItemToObject(item, supported ? "data" : "error", value)) {
            cJSON_Delete(value); goto fail;
        }
        if (!cJSON_AddStringToObject(item, "target", target->valuestring)) goto fail;
        if (supported) {
            if (!cJSON_AddStringToObject(value, "message", message->valuestring) ||
                !cJSON_AddNumberToObject(value, "index", index)) goto fail;
        } else if (!cJSON_AddStringToObject(value, "code", "unsupported_action") ||
                   !cJSON_AddStringToObject(value, "message",
                       "Select the echo action and supply a message.")) goto fail;
    }
    return results;
fail:
    cJSON_Delete(results);
    return NULL;
}

int main(void) { return ficc_serve(echo_batch); }
