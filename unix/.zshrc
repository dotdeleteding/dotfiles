[[ -f $HOME/.zsh/aliases.zsh ]] && source $HOME/.zsh/aliases.zsh
[[ -f $HOME/.zsh/starship.zsh ]] && source $HOME/.zsh/starship.zsh
[[ -f $HOME/.zsh/plugin/zsh-autosuggestions/zsh-autosuggestions.zsh ]] && \
    source $HOME/.zsh/plugin/zsh-autosuggestions/zsh-autosuggestions.zsh
[[ -f $HOME/.zsh/plugin/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]] && \
    source $HOME/.zsh/plugin/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
export STARSHIP_CONFIG=$HOME/.zsh/starship.toml
export STARSHIP_CACHE=$HOME/.starship/cache

eval "$(starship init zsh)"
