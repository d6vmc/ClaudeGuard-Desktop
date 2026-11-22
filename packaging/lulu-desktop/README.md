# Claude Desktop с LuLu

[Установка ClaudeGuard Desktop с нуля](../../README.desktop.ru.md)

LuLu фильтрует исходящие соединения Claude Desktop. ClaudeGuard проверяет выходной IPv4 и запускает Desktop с прокси `127.0.0.1:17943`. Для этой сборки не нужен собственный сертификат Developer ID и не устанавливается обёртка Claude Code.

Скачайте `ClaudeGuard-Desktop.pkg` из [релизов](https://github.com/d6vmc/ClaudeGuard-Desktop/releases). В одном пакете находятся приложение, обе архитектуры Python, sing-box, Xray, правила и официальный подписанный образ LuLu. Откройте образ через **Protection → Open LuLu Installer**. Активацию сетевого фильтра LuLu подтверждает пользователь в macOS. Чтобы переключить меню ClaudeGuard на русский, выберите **Language → Русский**.

## Установить LuLu и импортировать правила

В ClaudeGuard 2.3.6 откройте **Protection → Set Up LuLu Rules…**. Для официальной LuLu 4.5.7 приложение запускает штатный импорт через разрешённый macOS «Универсальный доступ». Подробности и порядок первичной настройки описаны в [русском README](../../README.desktop.ru.md#2-установите-lulu-и-настройте-правила-из-claudeguard).

### Ручной импорт

1. Закройте Claude Desktop. Установите LuLu и подтвердите системное расширение и сетевой фильтр в настройках macOS. Для этой схемы проверена структура правил LuLu 4.5.7. [Инструкция LuLu](https://objective-see.org/products/lulu.html)
2. В активном профиле LuLu выключите **Allow Localhost Traffic**, **Allow DNS Traffic** и **Allow Already Installed Programs**. Если нужно разрешать неизвестные соединения остальных приложений без запросов, выберите **Passive Mode → Allow** и отключите автоматическое создание правил. Уберите исключения из **Allow List**, которые разрешили бы Claude выход в обход этих правил.
3. В меню **Rules → Import** выберите [ClaudeGuard-LuLu-rules.json](ClaudeGuard-LuLu-rules.json). Импорт заменяет пользовательские правила текущего профиля. Сохраните их экспортом перед импортом, если профиль уже используется. Не добавляйте для Claude и его помощников общие правила Allow.
4. Убедитесь, что в LuLu видны два правила для `/Applications/Claude.app/*` и два правила **Process + Kids** для `/Applications/Claude.app/Contents/MacOS/Claude`. Точное разрешение `127.0.0.1:17943` применяется прежде общего запрета и позволяет встроенной вкладке Code обращаться к локальному прокси. Правила для дочерних процессов зависят от того, может ли LuLu определить их родителя. [Исходники LuLu 4.5.7](https://github.com/objective-see/LuLu/blob/v4.5.7/LuLu/Extension/Rules.m)

## Прокси и запуск

1. Откройте **Connection → SSH Tunnel…**. Укажите сервер, пользователя, порт, публичный выходной IPv4 и SHA256-отпечаток **ключа сервера**, подтверждённый независимым способом. При необходимости укажите путь к своему локальному SSH-ключу. Сервер должен разрешать TCP forwarding. Для ключа с парольной фразой требуется доступ из агента SSH или связки ключей.
2. В разделе **Connection** команда **Disconnect Proxy** останавливает туннель, а **Connect Proxy** включает его снова. После неожиданного обрыва приложение повторяет подключение с растущими паузами и проверяет выходной IPv4 перед запуском Claude.
3. Для отдельного маршрута VLESS/REALITY выберите **Connection → Import VLESS/REALITY…**. ClaudeGuard запускает встроенный Xray для входов TCP/REALITY. Чтобы привязать соединение к физической сети при работающем Happ, укажите имя Wi-Fi или Ethernet-интерфейса и IPv4 входного сервера.
4. Выберите **Protection → macOS Proxy Routing…**, чтобы настроить PAC для нужных сетевых сервисов macOS. Для Wi-Fi и Happ выберите `Wi-Fi, Happ`. После сохранения может потребоваться переподключить Happ. Системный PAC направляет через прокси домены Claude, Anthropic и hCaptcha, которую Claude использует при входе. Правило действует и в браузерах, которые используют настройки macOS. [Требования Anthropic к сети](https://support.claude.com/en/articles/18426225-move-from-claude-enterprise-to-claude-desktop-on-a-cloud-provider)

Если PAC уже был настроен в версии 2.3.1, сохраните его через **Protection → macOS Proxy Routing…** ещё раз, чтобы добавить hCaptcha.

Когда ClaudeGuard работает, LuLu включён, системный PAC активен, а выходной IPv4 подтверждён, открывайте Claude обычной иконкой в Dock или Finder. Карточка в меню ClaudeGuard показывает состояние защиты, тип прокси и подтверждённый IP. Под ней находятся **Open Claude** и **Check Connection**. При обнаружении остановки LuLu или утраты требуемых правил ClaudeGuard закрывает Claude Desktop. Проверка выполняется раз в три секунды с небольшим допуском, пока Claude открыт.

## Обновления ClaudeGuard

Начиная с 2.3.5, приложение проверяет релизы Desktop на GitHub раз в сутки. Для ручной проверки выберите **Проверить обновления…** (**Check for Updates…**). Когда новая версия найдена, выберите **Обновить до …**. Приложение сверит SHA-256 скачанного пакета с GitHub и откроет установщик macOS для подтверждения. Установка сохраняет профиль прокси, маршрутизацию macOS и язык меню.

### Ручной режим SSH

Для отдельного теста используйте VPS с постоянным IPv4 и IPv4-выходом. Для SSH нужен разрешённый TCP forwarding. Команда на Mac открывает локальный порт, а сеть до Claude использует VPS.

```bash
ssh -4 -NT -D 127.0.0.1:1081 -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 USER@VPS_IPV4
```

В другом окне проверьте выходной адрес командой `curl --proxy socks5h://127.0.0.1:1081 --noproxy '' https://api.ipify.org`. В ClaudeGuard выберите **Connection → External Proxy…**, укажите `socks5://127.0.0.1:1081` и этот внешний IPv4. Параметр SSH `-4` выбирает IPv4 при подключении к VPS. Для двухстекового VPS отдельно настройте выход SOCKS по IPv4.

Если Happ переключает серверы, настройте для ClaudeGuard отдельное подключение. В **Connection → External Proxy…** вставьте клиентский sing-box outbound JSON для своего прокси. Для VLESS/REALITY перенесите параметры входа из клиентского профиля, включая UUID, TLS server name, открытый ключ REALITY, short ID и flow, если он указан. Задайте IP входного сервера в `server` и добавьте `"bind_interface": "en0"`, если `en0` — активный интерфейс Wi-Fi или Ethernet. В поле ожидаемого IPv4 укажите публичный IPv4 **выходного** сервера. При смене физического интерфейса обновите `bind_interface`. Если физическая сеть теряет доступ к входному серверу, проверка прокси блокирует запуск Claude. [Параметры подключения sing-box](https://sing-box.sagernet.org/configuration/shared/dial/#bind_interface)

Для сборки из исходников используйте `CLAUDEGUARD_LULU_DESKTOP=1 bash build.sh 2.3.6`. ClaudeGuard сохраняет правила PF для известных адресов, включая адреса общих CDN. DNS, приложения-помощники вне пакета и поведение после перезагрузки следует проверять отдельно.

Сторонние компоненты поставляются со своими лицензиями и соответствующими исходниками. [LuLu 4.5.7](https://github.com/objective-see/LuLu/tree/v4.5.7), [Xray 26.11.9](https://github.com/XTLS/Xray-core/tree/v26.11.9), [Python 3.13.18](https://github.com/python/cpython/tree/v3.13.18), [сборка Python для macOS](https://github.com/astral-sh/python-build-standalone/tree/20261110).
