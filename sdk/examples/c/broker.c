/* SPDX-License-Identifier: Apache-2.0 */
#include "ficc_module.h"
#include <string.h>

static cJSON *resources(const cJSON *request, ficc_broker *broker) {
    const cJSON *targets = cJSON_GetObjectItemCaseSensitive(request, "targets");
    const char *action = cJSON_GetObjectItemCaseSensitive(request, "action")->valuestring;
    if (strcmp(action, "read")) {
        cJSON *result = cJSON_CreateArray();
        for (const cJSON *target = targets->child; target; target = target->next) {
            cJSON *row = cJSON_CreateObject(), *error = cJSON_CreateObject();
            cJSON_AddStringToObject(row, "target", target->valuestring);
            cJSON_AddStringToObject(error, "code", "unsupported_action");
            cJSON_AddStringToObject(error, "message", "Select the read action.");
            cJSON_AddItemToObject(row, "error", error); cJSON_AddItemToArray(result, row);
        }
        return result;
    }
    cJSON *parameters = cJSON_CreateObject();
    cJSON *result = ficc_broker_call(broker, "system.resources.read", targets, parameters);
    cJSON_Delete(parameters);
    return result;
}

int main(void) { return ficc_serve_broker(resources); }
