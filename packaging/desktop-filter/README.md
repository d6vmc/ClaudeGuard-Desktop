# Сетевой фильтр Claude Desktop

Вариант сборки для macOS 15+. Фильтр привязан к подписи Anthropic `Q6L2SF6YDW` и идентификатору `com.anthropic.claudefordesktop`. Он проверяет идентичность приложения и процесса сокета, включая подписанные вспомогательные процессы в `Claude.app`. Для совпавших потоков разрешён только исходящий TCP к `127.0.0.1:17943`. Меню **Launch Isolated Claude Desktop** запускает Electron с явным HTTP-прокси, запрещает локальное разрешение имён через Chromium и требует свежего подтверждения выходного IPv4. Claude Code и проверки VPN-режима работают как раньше.

## Сборка и активация

Для обычной сборки остаётся команда `bash build.sh`. Для сборки с сетевым фильтром нужны сертификат Developer ID Application в связке ключей и два профиля от одной команды Apple Developer. Профиль `com.claudeguard.app` разрешает активацию системного расширения и Network Extension, а профиль `com.claudeguard.app.desktop-filter` разрешает `content-filter-provider-systemextension`. Убедитесь, что распространяемый пакет проходит обычную проверку Gatekeeper и нотарификацию. [Требования Apple к Network Extension](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)

```bash
CLAUDEGUARD_DESKTOP_FILTER=1 \
CLAUDEGUARD_APP_SIGN_IDENTITY='Developer ID Application: …' \
CLAUDEGUARD_APP_PROVISION_PROFILE=/path/to/claudeguard.provisionprofile \
CLAUDEGUARD_FILTER_PROVISION_PROFILE=/path/to/desktop-filter.provisionprofile \
bash build.sh 2.2.0
```

Закройте Claude Desktop перед активацией. После установки тестового пакета в ClaudeGuard выберите режим Proxy, задайте профиль и ожидаемый публичный IPv4, затем выберите **Enable Desktop Network Filter…**. Подтвердите активацию и разрешение на фильтрацию в системных настройках macOS. Откройте Claude через **Launch Isolated Claude Desktop**. Перед удалением тестовой версии закройте Claude и снимите настройку через **Disable Desktop Network Filter…**.

## Приёмка с Happ

| Проверка | Ожидаемый результат |
| --- | --- |
| Happ выключен, включён и меняет сервер | Desktop работает через один IPv4 либо теряет связь. Обычное контрольное приложение сохраняет свой маршрут. |
| Прокси недоступен или возвращает другой IPv4 | Desktop теряет связь. Пакеты Desktop к внешним адресам отсутствуют. |
| Неизвестное назначение, IPv6, DNS и QUIC | В системном захвате нет прямых потоков Desktop. Запросы, которые Electron отправил через прокси, видны на локальном входе. |
| Перезагрузка и запуск из Finder | До готовности фильтра и прокси Desktop не оказывает сетевой активности. |
| Вспомогательные процессы и обновление Claude | Новые идентичности процессов попадают под фильтр. Сценарии входа, чат и загрузки проверяются отдельно. |

Сверяйте трафик на loopback, физических интерфейсах и интерфейсах Happ, а также внешний IPv4 на прокси. Сообщение `Claude Desktop socket policy loaded` в системном журнале подтверждает загрузку правил провайдером. Статус в меню и запись о разрешении от macOS подтверждают конфигурацию. Системное разрешение DNS, процессы с отдельной идентичностью, браузер авторизации и порядок запуска расширения проверяются отдельно. Пока нет этой проверки, сборка считается экспериментальной.
