#!/usr/bin/env bash
# Bash completion for mom(8)
# Install: copy to /usr/share/bash-completion/completions/mom

_mom() {
    local cur prev words cword
    _init_completion || return

    local subcommands="install update refresh"
    local global_opts="-y --yes --check --version --help"

    case "$prev" in
        mom)
            COMPREPLY=( $(compgen -W "$subcommands $global_opts" -- "$cur") )
            return
            ;;
        install|update)
            # Offer installed packages for update, or all available for install
            if [[ "$prev" == "update" ]]; then
                # Complete from installed packages if dpkg/rpm is available
                if command -v dpkg-query &>/dev/null; then
                    local pkgs
                    pkgs=$(dpkg-query -W -f='${Package}\n' 2>/dev/null)
                    COMPREPLY=( $(compgen -W "$pkgs" -- "$cur") )
                elif command -v rpm &>/dev/null; then
                    local pkgs
                    pkgs=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null)
                    COMPREPLY=( $(compgen -W "$pkgs" -- "$cur") )
                fi
            fi
            return
            ;;
        refresh)
            # No further arguments
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
            install|update)
                if [[ "$subcmd" == "update" ]] && command -v dpkg-query &>/dev/null; then
                    local pkgs
                    pkgs=$(dpkg-query -W -f='${Package}\n' 2>/dev/null)
                    COMPREPLY=( $(compgen -W "$pkgs" -- "$cur") )
                elif [[ "$subcmd" == "update" ]] && command -v rpm &>/dev/null; then
                    local pkgs
                    pkgs=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null)
                    COMPREPLY=( $(compgen -W "$pkgs" -- "$cur") )
                fi
                ;;
        esac
    else
        COMPREPLY=( $(compgen -W "$subcommands $global_opts" -- "$cur") )
    fi
}

complete -F _mom mom
