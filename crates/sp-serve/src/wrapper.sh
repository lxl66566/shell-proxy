if [ -n "${SP_CWD:-}" ]; then
  cd -- "$SP_CWD" || { printf 'sp: cannot cd to %s, using HOME\n' "$SP_CWD" >&2; cd; }
fi
unset SP_CWD
__sp_sig=
trap '__sp_sig=130' INT
trap '__sp_sig=143' TERM
trap '__sp_sig=129' HUP
{ eval "$(cat /dev/fd/9)"; } 2>/dev/null
exec 9>&-
__sp_cmd=$(cat /dev/fd/8)
exec 8>&-
eval "$__sp_cmd"
__sp_rc=$?
unset __sp_cmd
[ -n "$__sp_sig" ] && __sp_rc=$__sp_sig
__sp_e=0; [[ $- == *e* ]] && __sp_e=1
set +e
printf '%s\0' "$PWD" >&10
exec 2>/dev/null
( set -- "$__sp_e"; unset __sp_rc __sp_sig __sp_e SP_CWD PWD; declare -p; declare -f; alias; shopt -p; set +o; umask -p; [ "$1" = 1 ] && printf '%s\n' 'set -o errexit'; printf '\0'; ) >&11
exit "$__sp_rc"
