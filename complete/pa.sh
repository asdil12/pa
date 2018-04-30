_pa_complete()
{
    local cur prev opts base
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

	if [[ "${prev}" == "pa" ]] ; then
		opts="ls show clip gen add edit init passwd"
		COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
	elif [[ "${prev}" == "show" ]] || [[ "${prev}" == "edit" ]] || [[ "${prev}" == "clip" ]] ; then
		opts=$(cd ~/.pa/db/;find -type f|sed -e 's/\.\///' -e '/\.$/d')
		COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
	elif [[ "${prev}" == "ls" ]] || [[ "${prev}" == "gen" ]] || [[ "${prev}" == "add" ]] ; then
		opts=$(cd ~/.pa/db/;find -type d|sed -e 's/\.\///' -e '/\.$/d' -e 's/\(.*\)/\1\//')
		COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
		compopt -o nospace
	fi
    return 0
}
complete -F _pa_complete pa
