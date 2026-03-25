#!/usr/bin/env bash
# Bash completion for mom(8)
# Install: copy to /usr/share/bash-completion/completions/mom

_mom() {
    local cur prev words cword
    _init_completion || return

    local subcommands="install update refresh"
    local global_opts="-y --yes --check --version --help"

    # Helper: complete from installed packages (for update subcommand)
    _mom_installed_pkgs() {
        if command -v dpkg-query &>/dev/null; then
            mapfile -t COMPREPLY < <(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -F -- "$cur")
        elif command -v rpm &>/dev/null; then
            mapfile -t COMPREPLY < <(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -F -- "$cur")
        fi
    }

    case "$prev" in
        mom)
            COMPREPLY=( $(compgen -W "$subcommands $global_opts" -- "$cur") )
            return
            ;;
        install|update)
            if [[ "$prev" == "update" ]]; then
                _mom_installed_pkgs
            fi
            return
            ;;
        refresh)
            return
            ;;
        --check|--version|--help)
            return
            ;;
    esac

    # Handle subcommand already typed (e.g. "mom install <TAB>")
    local subcmd=""
    local i
    for (( i=1; i < cword; i++ )); do
        case "${words[$i]}" in
            install|update|refresh) subcmd="${words[$i]}"; break ;;
        esac
    done

    if [[ -n "$subcmd" ]]; then
        case "$subcmd" in
            update) _mom_installed_pkgs ;;
        esac
    else
        COMPREPLY=( $(compgen -W "$subcommands $global_opts" -- "$cur") )
    fi
}

complete -F _mom mom
