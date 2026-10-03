# SPDX-License-Identifier: Apache-2.0
package ficc

import rego.v1

decisions := [decision(request) | some request in input.requests]

decision(request) := {"id": request.id, "allow": true, "reason": "role_permitted"} if {
    permitted(request)
} else := {"id": request.id, "allow": false, "reason": "role_not_permitted"}

permitted(request) if {
    request.authority.local_owner
    request.action in request.authority.scopes
}

permitted(request) if {
    some role in request.authority.roles
    request.action in object.get(data.roles, role, [])
    request.action in request.authority.scopes
}
