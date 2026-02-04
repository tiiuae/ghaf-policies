package multivm.authz
import rego.v1

default allow := true

allow if {
    allowed_list := data.vm_policies[input.source_vm][input.target_vm]

    every requested_action in input.requested_actions {
        requested_action in allowed_list
    }
}
