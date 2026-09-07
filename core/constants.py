"""
core/constants.py - Constantes transversales del MCP.

Centraliza las listas de herramientas destructivas (L1) e irreversibles (L2).
`core/config.py` re-exporta DESTRUCTIVE_TOOLS para compatibilidad con Fase 0.

Niveles (PLAN_DESARROLLO.md §3.1):
    L0 lectura      : list*/get*/check*/test* (sin confirm).
    L1 destructivo  : escritura/destructivo, exige confirm=true.
    L2 irreversible : irreversible o corte-red, exige doble confirmación
                      (confirm + acknowledge + ack_text exacta + eco).
"""

# =============================================================================
# HERRAMIENTAS DESTRUCTIVAS (L1: confirm=true)
# =============================================================================

_DESTRUCTIVE_WINDOWS = frozenset({
    "run_command",
    "run_powershell_script",
    "set_ip_address",
    "set_dns_server",
    "delete_user",
    "kill_process",
    "stop_service",
    "disable_user",
    "delete_scheduled_task",
    "remove_user_from_group",
    "disable_firewall_rule",
    "write_file",
    "create_user",
    "add_user_to_group",
    "set_environment_var",
    "set_password_policy",
    "open_firewall_port",
    "enable_firewall_rule",
    "create_shared_folder",
    "create_scheduled_task",
})

# Equivalentes Linux (sufijo _linux; run_powershell_script -> run_bash_script_linux).
_DESTRUCTIVE_LINUX = frozenset({
    "run_command_linux",
    "run_bash_script_linux",
    "set_ip_address_linux",
    "set_dns_server_linux",
    "delete_user_linux",
    "kill_process_linux",
    "stop_service_linux",
    "disable_user_linux",
    "delete_scheduled_task_linux",
    "remove_user_from_group_linux",
    "disable_firewall_rule_linux",
    "write_file_linux",
    "create_user_linux",
    "add_user_to_group_linux",
    "set_environment_var_linux",
    "set_password_policy_linux",
    "open_firewall_port_linux",
    "enable_firewall_rule_linux",
    "create_shared_folder_linux",
    "create_scheduled_task_linux",
})

DESTRUCTIVE_TOOLS: frozenset = _DESTRUCTIVE_WINDOWS | _DESTRUCTIVE_LINUX


# =============================================================================
# HERRAMIENTAS IRREVERSIBLES / CORTE-RED (L2: doble confirmación)
# =============================================================================

IRREVERSIBLE_TOOLS: frozenset = frozenset({
    # Bosque/dominio y roles (Fase 2).
    "ad_install_forest",
    "ad_install_roles",
    "ad_restart_after_promote",
    # Unión a dominio (Windows + alias).
    "join_domain",
    "ad_join_domain",
    # Red con riesgo de corte SSH (Fase 4).
    "set_ip_address",
    "set_ip_address_linux",
    "set_dns_server",
    "set_dns_server_linux",
    "netplan_set_linux",
    "netplan_apply_linux",
    # Identidad Linux unida a dominio.
    "realm_join_linux",
    "realm_leave_linux",
    # File server (share + NTFS).
    "share_create",
    "ntfs_grant",
    "samba_create_share_linux",
    # AD: crean estado en el directorio.
    "ad_create_ou",
    "ad_create_group",
    "ad_create_user",
    "ad_set_password",
})
