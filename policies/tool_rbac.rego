package agentguard

# Default deny — all access is denied unless explicitly allowed
default allow = false

# Role-based tool allowlist
role_tool_allowlist := {
    "admin": {
        "search", "calculate", "send_email", "database_query",
        "read_file", "write_file", "execute_command", "list_files",
        "compress", "http_post", "read_env", "modify_prompt",
        "spawn_agent", "write_config", "web_search",
    },
    "analyst": {
        "search", "calculate", "database_query", "read_file",
        "list_files", "web_search",
    },
    "worker": {
        "search", "calculate", "send_email", "web_search",
    },
    "restricted": {
        "search", "calculate",
    },
}

# Allow if the agent's role is in the allowlist and the tool is permitted
allow if {
    role := input.agent_role
    tool := input.tool_name
    role_tool_allowlist[role][tool]
}

# Rate limit configuration per role
rate_limits := {
    "admin": 100,
    "analyst": 50,
    "worker": 20,
    "restricted": 10,
}

# Get rate limit for role
rate_limit = limit if {
    limit := rate_limits[input.agent_role]
}

# Default rate limit for unknown roles
rate_limit = 5 if {
    not rate_limits[input.agent_role]
}
