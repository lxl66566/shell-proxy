exec 2>&3
[ -r /etc/bash.bashrc ] && . /etc/bash.bashrc || :
[ -r ~/.bashrc ] && . ~/.bashrc || :
exec 7>&-
