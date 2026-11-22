use scripting additions

set useRussian to false
try
    set useRussian to (do shell script "/usr/bin/defaults read -g AppleLocale") starts with "ru"
end try
try
    set useRussian to (do shell script "/usr/bin/defaults read com.claudeguard.app MenuLanguage") is "ru"
end try

if useRussian then
    set confirmation to "Удалить ClaudeGuard?"
    set details to "Будут удалены приложение, фоновые службы, профили и настройки. Если в LuLu установлены правила ClaudeGuard, удалите их в LuLu или переключите профиль, чтобы Claude мог подключаться без ClaudeGuard."
    set removeButton to "Удалить"
    set cancelButton to "Отмена"
    set removedTitle to "ClaudeGuard удалён"
    set errorTitle to "Не удалось удалить ClaudeGuard"
else
    set confirmation to "Remove ClaudeGuard?"
    set details to "The application, background services, profiles, and settings will be removed. If you installed ClaudeGuard rules in LuLu, remove them in LuLu or switch profiles to allow Claude to connect without ClaudeGuard."
    set removeButton to "Remove"
    set cancelButton to "Cancel"
    set removedTitle to "ClaudeGuard Removed"
    set errorTitle to "Could Not Remove ClaudeGuard"
end if

try
    display alert confirmation message details as warning buttons {cancelButton, removeButton} default button cancelButton cancel button cancelButton
    do shell script "'/Library/Application Support/ClaudeGuard/python3' -I '/Library/Application Support/ClaudeGuard/remove_desktop.py'" with administrator privileges
    display alert removedTitle
on error problem number errorNumber
    if errorNumber is not -128 then display alert errorTitle message problem as critical
end try
