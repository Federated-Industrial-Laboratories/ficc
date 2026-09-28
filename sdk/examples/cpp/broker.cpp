// SPDX-License-Identifier: Apache-2.0
#include "ficc_module.h"
#include <cstring>
#include <memory>
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;

static cJSON *resources(const cJSON *request, ficc_broker *broker) {
    const auto *targets = cJSON_GetObjectItemCaseSensitive(request, "targets");
    const auto *action = cJSON_GetObjectItemCaseSensitive(request, "action");
    if (std::strcmp(action->valuestring, "read")) {
        Json result(cJSON_CreateArray(), cJSON_Delete);
        for (const auto *target = targets->child; target; target = target->next) {
            auto *row = cJSON_CreateObject(), *error = cJSON_CreateObject();
            cJSON_AddStringToObject(row, "target", target->valuestring);
            cJSON_AddStringToObject(error, "code", "unsupported_action");
            cJSON_AddStringToObject(error, "message", "Select the read action.");
            cJSON_AddItemToObject(row, "error", error); cJSON_AddItemToArray(result.get(), row);
        }
        return result.release();
    }
    Json parameters(cJSON_CreateObject(), cJSON_Delete);
    return ficc_broker_call(broker, "system.resources.read", targets, parameters.get());
}
int main() { return ficc_serve_broker(resources); }
