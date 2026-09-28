/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FICC_MODULE_H
#define FICC_MODULE_H
#include "cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif
/* The callback receives the complete request and returns an owned result array. */
typedef cJSON *(*ficc_batch_handler)(const cJSON *request);
int ficc_serve(ficc_batch_handler handler);
typedef struct ficc_broker ficc_broker;
typedef cJSON *(*ficc_broker_handler)(const cJSON *request, ficc_broker *broker);
/* The call returns an owned ordered result array, or NULL after any refusal. */
cJSON *ficc_broker_call(ficc_broker *broker, const char *primitive,
                       const cJSON *targets, const cJSON *parameters);
int ficc_serve_broker(ficc_broker_handler handler);
typedef struct ficc_adapter ficc_adapter;
typedef cJSON *(*ficc_adapter_handler)(const cJSON *request, ficc_adapter *adapter);
cJSON *ficc_adapter_call(ficc_adapter *adapter, const char *profile_id, const cJSON *commands);
int ficc_serve_adapter(ficc_adapter_handler handler);
#ifdef __cplusplus
}
#endif
#endif
