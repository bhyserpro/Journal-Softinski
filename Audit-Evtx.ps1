#requires -Version 5.1
<#
Offline EVTX triage. Windows PowerShell 5.1, built-in .NET only.
Reads supplied files; never changes logs, accounts, audit policy or execution policy.
See README.md for semantics, limitations and validation status.
#>
[CmdletBinding()]
param(
    [string]$InputPath,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Evtx-Audit'),
    [ValidateRange(2,100000)][int]$FailureThreshold = 10,
    [ValidateRange(1,1440)][int]$WindowMinutes = 10,
    [ValidateRange(2,10000)][int]$SprayUserThreshold = 5,
    [ValidateRange(1000,1000000)][int]$RowsPerCsv = 500000,
    [ValidateRange(1,720)][int]$MaxRdpHours = 24,
    [char]$Delimiter = ';',
    [switch]$IncludeMessages,
    [switch]$IncludeNoise,
    [switch]$IncludeAllErrors,
    [ValidateRange(1,65535)][int]$MaxEventId = 10000,
    [datetime]$StartTime,
    [datetime]$EndTime,
    [switch]$SkipMessages,
    [switch]$IncludeNetworkLogons,
    [switch]$DeepScriptScan,
    [switch]$IncludeProcessCreation,
    [switch]$HashFiles,
    [switch]$SkipCorrelation,
    [switch]$SkipTriage,
    [ValidateRange(1,1440)][int]$TriageWindowMinutes = 30,
    [switch]$NoExcel,
    [switch]$KeepTechnicalFiles,
    [switch]$IncludeAllAntivirusEvents,
    [string]$ExtraAvFilePattern = '(?i)(doctor[ ._-]*web|dr[ ._-]*web|kaspersky|eset|symantec|sophos|mcafee|trend.?micro)',
    [switch]$SelfTest
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Version = '9.0.0'
$script:Utf8 = New-Object System.Text.UTF8Encoding($true)
$script:Invariant = [Globalization.CultureInfo]::InvariantCulture
$script:FastCellInvalid=New-Object Text.RegularExpressions.Regex('[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]')
$script:FastCellFormula=New-Object Text.RegularExpressions.Regex('^\s*[=+@-]')
$script:CellReplacement=[Text.RegularExpressions.MatchEvaluator]{param($m) return ('[U+{0:X4}]' -f [int][char]$m.Value[0])}
$script:HashEngine=[Security.Cryptography.SHA256]::Create()
$script:QueryCache=@{}
$script:ReaderSettings=New-Object Xml.XmlReaderSettings
$script:ReaderSettings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
$script:ReaderSettings.XmlResolver=$null
$script:Writers = New-Object 'System.Collections.Generic.List[System.IO.StreamWriter]'
$script:Rules = @{}
$script:RuleTable = @'
Provider	Id	Category	Severity	Title	Note
Microsoft-Windows-Security-Auditing	4616	Время	Medium	Изменено системное время	Проверить старое/новое время, инициатора и процесс; синхронизация времени может быть штатной.
Microsoft-Windows-Security-Auditing	4720	Учетные записи	Medium	Создана учетная запись	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4726	Учетные записи	Medium	Удалена учетная запись	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4722	Учетные записи	Medium	Учетная запись включена	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4725	Учетные записи	Medium	Учетная запись отключена	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4738	Учетные записи	Medium	Изменена учетная запись	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4781	Учетные записи	Medium	Учетная запись переименована	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4741	Учетные записи компьютеров	Medium	Создана учетная запись компьютера	Событие формируется на контроллере домена; проверить инициатора, имя компьютера и обоснование создания.
Microsoft-Windows-Security-Auditing	4742	Учетные записи компьютеров	Medium	Изменена учетная запись компьютера	Событие формируется на контроллере домена; проверить измененные атрибуты, делегирование и инициатора.
Microsoft-Windows-Security-Auditing	4743	Учетные записи компьютеров	High	Удалена учетная запись компьютера	Событие формируется на контроллере домена; для критичных серверов и админских рабочих станций проверить согласование удаления.
Microsoft-Windows-Security-Auditing	4767	Учетные записи	Medium	Учетная запись разблокирована	Сопоставить с заявками, владельцем УЗ и субъектом операции.
Microsoft-Windows-Security-Auditing	4723	Учетные записи	Medium	Попытка изменения пароля	Успех/отказ определяется AuditOutcome; проверить полномочия инициатора.
Microsoft-Windows-Security-Auditing	4724	Учетные записи	Medium	Попытка сброса пароля	Успех/отказ определяется AuditOutcome; проверить полномочия инициатора.
Microsoft-Windows-Security-Auditing	4728	Привилегии	Medium	Участник добавлен в глобальную группу	Проверить SID группы и участника; членство в произвольной группе не доказывает повышение прав.
Microsoft-Windows-Security-Auditing	4732	Привилегии	Medium	Участник добавлен в локальную группу	Проверить SID группы и участника; членство в произвольной группе не доказывает повышение прав.
Microsoft-Windows-Security-Auditing	4756	Привилегии	Medium	Участник добавлен в универсальную группу	Проверить SID группы и участника; членство в произвольной группе не доказывает повышение прав.
Microsoft-Windows-Security-Auditing	4729	Привилегии	Medium	Участник удален из глобальной группы	Проверить SID группы и участника; членство в произвольной группе не доказывает повышение прав.
Microsoft-Windows-Security-Auditing	4733	Привилегии	Medium	Участник удален из локальной группы	Проверить SID группы и участника; членство в произвольной группе не доказывает повышение прав.
Microsoft-Windows-Security-Auditing	4757	Привилегии	Medium	Участник удален из универсальной группы	Проверить SID группы и участника; членство в произвольной группе не доказывает повышение прав.
Microsoft-Windows-Security-Auditing	4704	Привилегии	High	Назначено право пользователя	Проверить назначенные права/SID и согласование изменения.
Microsoft-Windows-Security-Auditing	4705	Привилегии	High	Удалено право пользователя	Проверить назначенные права/SID и согласование изменения.
Microsoft-Windows-Security-Auditing	4670	Права доступа	Medium	Изменены разрешения объекта	Проверить ObjectType/ObjectName, процесс и старый/новый дескриптор безопасности; событие может быть шумным при широком Object Access audit.
Microsoft-Windows-Security-Auditing	4911	Права доступа	Medium	Изменены атрибуты ресурса объекта	Проверить объект, процесс и старый/новый дескриптор; актуально для Dynamic Access Control и классификации данных.
Microsoft-Windows-Security-Auditing	4913	Права доступа	Medium	Изменена Central Access Policy объекта	Проверить объект, процесс и старую/новую Central Access Policy; событие относится к централизованной политике доступа.
Microsoft-Windows-Security-Auditing	4717	Привилегии / удаленный доступ	High	Учетной записи предоставлено право входа	Проверить TargetSid и AccessGranted; особенно SeRemoteInteractiveLogonRight, SeNetworkLogonRight и SeServiceLogonRight.
Microsoft-Windows-Security-Auditing	4718	Привилегии / удаленный доступ	Medium	У учетной записи отозвано право входа	Проверить TargetSid и AccessRemoved; изменение прав входа должно быть согласовано.
Microsoft-Windows-Security-Auditing	4765	Привилегии	High	SID History добавлен к УЗ	Проверить назначенные права/SID и согласование изменения.
Microsoft-Windows-Security-Auditing	4672	Привилегии	Low	Специальные привилегии назначены при входе	Контекст привилегированного входа; это не доказательство повышения привилегий.
Microsoft-Windows-Security-Auditing	4625	Аутентификация	Low	Неудачный вход	Проверить Status/SubStatus; повторные отказы могут быть вызваны сохраненным старым паролем.
Microsoft-Windows-Security-Auditing	4771	Аутентификация	Low	Ошибка предварительной аутентификации Kerberos	Проверить Status/SubStatus; повторные отказы могут быть вызваны сохраненным старым паролем.
Microsoft-Windows-Security-Auditing	4776	Аутентификация	Low	Проверка учетных данных NTLM	Проверить Status/SubStatus; повторные отказы могут быть вызваны сохраненным старым паролем.
Microsoft-Windows-Security-Auditing	4740	Аутентификация	Medium	Учетная запись заблокирована	Проверить источник и контекст; само событие не доказывает атаку или успешный вход.
Microsoft-Windows-Security-Auditing	4624	Удаленный доступ	Info	Успешный вход	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4634	Удаленный доступ	Info	Сеанс входа завершен	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4778	Удаленный доступ	Info	Повторное подключение к сеансу Window Station	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4779	Удаленный доступ	Info	Отключение от сеанса Window Station	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4719	Политики защиты	High	Изменена политика аудита	Проверить значения и согласованное администрирование.
Microsoft-Windows-Security-Auditing	4902	Политики защиты	Medium	Создана таблица политики аудита для пользователя	Проверить, кто и зачем изменял per-user audit policy; само событие не означает очистку журнала.
Microsoft-Windows-Security-Auditing	4904	Политики защиты	High	Попытка зарегистрировать источник событий безопасности	Нетипичная регистрация источника Security требует проверки инициатора и легитимности ПО.
Microsoft-Windows-Security-Auditing	4905	Политики защиты	High	Попытка отменить регистрацию источника событий безопасности	Может повлиять на журналирование; проверить инициатора, источник и согласование.
Microsoft-Windows-Security-Auditing	4906	Политики защиты	High	Изменено значение CrashOnAuditFail	Изменение поведения системы при невозможности записывать аудит; проверить новое значение и инициатора.
Microsoft-Windows-Security-Auditing	4907	Политики защиты	High	Изменены параметры аудита объекта	Проверить значения и согласованное администрирование.
Microsoft-Windows-Security-Auditing	4739	Политики защиты	High	Изменена политика домена	Проверить значения и согласованное администрирование.
Microsoft-Windows-Security-Auditing	4697	Закрепление / запуск	Medium	Установлена служба	Проверить автора, исполняемый файл/команду, учетную запись запуска и заявку.
Microsoft-Windows-Security-Auditing	4698	Закрепление / запуск	Medium	Создано задание планировщика	Проверить автора, исполняемый файл/команду, учетную запись запуска и заявку.
Microsoft-Windows-Security-Auditing	4702	Закрепление / запуск	Medium	Обновлено задание планировщика	Проверить автора, исполняемый файл/команду, учетную запись запуска и заявку.
Microsoft-Windows-Security-Auditing	4699	Закрепление / запуск	Medium	Удалено задание планировщика	Проверить автора, исполняемый файл/команду, учетную запись запуска и заявку.
Microsoft-Windows-Security-Auditing	4700	Закрепление / запуск	Medium	Задание включено	Проверить автора, исполняемый файл/команду, учетную запись запуска и заявку.
Microsoft-Windows-Security-Auditing	4701	Закрепление / запуск	Medium	Задание отключено	Проверить автора, исполняемый файл/команду, учетную запись запуска и заявку.
Microsoft-Windows-Security-Auditing	4946	Политики защиты	Medium	Добавлено правило Windows Firewall	Проверить направление, адреса, порты, действие и основание изменения.
Microsoft-Windows-Security-Auditing	4947	Политики защиты	Medium	Изменено правило Windows Firewall	Проверить направление, адреса, порты, действие и основание изменения.
Microsoft-Windows-Security-Auditing	4948	Политики защиты	Medium	Удалено правило Windows Firewall	Проверить направление, адреса, порты, действие и основание изменения.
Microsoft-Windows-Security-Auditing	4950	Политики защиты	Medium	Изменен параметр Windows Firewall	Проверить направление, адреса, порты, действие и основание изменения.
Microsoft-Windows-Security-Auditing	4954	Политики защиты	Medium	Изменены параметры Firewall через групповую политику	Проверить направление, адреса, порты, действие и основание изменения.
Microsoft-Windows-Security-Auditing	4608	Контекст	Info	Запуск Windows	Граница загрузки; используется для разрыва корреляции сеансов.
Microsoft-Windows-Eventlog	1102	Журналы	High	Очищен журнал Security	Очистка/потеря/остановка журналирования требует проверки; остановка возможна при штатном выключении.
Microsoft-Windows-Eventlog	104	Журналы	High	Очищен журнал событий	Очистка/потеря/остановка журналирования требует проверки; остановка возможна при штатном выключении.
Microsoft-Windows-Eventlog	1100	Журналы	High	Служба журналирования завершена	Очистка/потеря/остановка журналирования требует проверки; остановка возможна при штатном выключении.
Microsoft-Windows-Eventlog	1101	Журналы	High	Потеряны события аудита	Очистка/потеря/остановка журналирования требует проверки; остановка возможна при штатном выключении.
Microsoft-Windows-Eventlog	1104	Журналы	High	Журнал Security заполнен	Очистка/потеря/остановка журналирования требует проверки; остановка возможна при штатном выключении.
Microsoft-Windows-Eventlog	1108	Журналы	High	Ошибка обработки входящего события журналирования	Очистка/потеря/остановка журналирования требует проверки; остановка возможна при штатном выключении.
Microsoft-Windows-Kernel-General	1	Время	Medium	Изменено системное время	Проверить OldTime/NewTime и причину; возможна штатная коррекция.
Microsoft-Windows-Kernel-General	12	Контекст	Info	Запуск операционной системы	Контекст загрузки/выключения.
Microsoft-Windows-Kernel-General	13	Контекст	Info	Остановка операционной системы	Контекст загрузки/выключения.
Microsoft-Windows-Kernel-Power	41	Сбои	High	Перезапуск после некорректного завершения	Не определяет причину сбоя; проверить питание, дампы и соседние события.
EventLog	6008	Сбои	High	Предыдущее завершение системы было неожиданным	Время записи события может отличаться от времени самого сбоя; подробности в XML.
EventLog	6005	Контекст	Info	Запущена служба журнала событий	Контекст доступности журнала.
EventLog	6006	Контекст	Info	Остановлена служба журнала событий	Контекст доступности журнала.
User32	1074	Контекст	Low	Процесс инициировал выключение/перезапуск	Проверить инициатора и причину.
Service Control Manager	7045	Закрепление / запуск	Medium	Установлена служба	Проверить службу, путь, учетную запись и заявку.
Service Control Manager	7040	Закрепление / запуск	Medium	Изменен тип запуска службы	Проверить службу, путь, учетную запись и заявку.
Service Control Manager	7031	Сбои	Medium	Неожиданно завершена служба	Может быть штатной неисправностью; проверить роль службы и повторяемость.
Service Control Manager	7034	Сбои	Medium	Неожиданно завершена служба	Может быть штатной неисправностью; проверить роль службы и повторяемость.
Service Control Manager	7000	Сбои	Medium	Не удалось запустить службу	Проверить имя службы, код ошибки, путь и соседние события; повторяемость может указывать на неисправность или вмешательство.
Service Control Manager	7001	Сбои	Medium	Служба не запущена из-за зависимости	Проверить зависимую службу/драйвер и первичную причину отказа.
Service Control Manager	7011	Сбои	Medium	Тайм-аут ожидания ответа службы	Проверить зависание службы, нагрузку и соседние ошибки; единичное событие не является ИБ-инцидентом.
Service Control Manager	7023	Сбои	Medium	Служба завершилась с ошибкой	Проверить службу, код завершения и соседние события.
Service Control Manager	7024	Сбои	Medium	Служба завершилась с сервисной ошибкой	Проверить службу, специфичный код ошибки и соседние события.
Application Error	1000	Сбои	Medium	Сбой приложения	Проверить аварийно завершившийся процесс/модуль, исключение и повторяемость; связь с ИБ требует контекста.
Windows Error Reporting	1001	Сбои	Low	Отчет Windows Error Reporting	Может содержать сведения о сбое приложения, LiveKernelEvent или иной проблеме; проверить EventName и ReportId, поскольку событие часто информационное.
Microsoft-Windows-WER-SystemErrorReporting	1001	Сбои	High	Системный BugCheck / отчет об аварии	Проверить код BugCheck, путь к дампу и соседние события Kernel-Power/EventLog.
Microsoft-Windows-Windows Defender	1006	Антивирус	High	Defender обнаружил угрозу (старый формат)	Проверить угрозу, ресурс, действие и результат; обнаружение не доказывает запуск/заражение.
Microsoft-Windows-Windows Defender	1116	Антивирус	High	Defender обнаружил вредоносное или нежелательное ПО	Проверить угрозу, ресурс, действие и результат; обнаружение не доказывает запуск/заражение.
Microsoft-Windows-Windows Defender	1015	Антивирус	High	Defender обнаружил подозрительное поведение	Проверить угрозу, ресурс, действие и результат; обнаружение не доказывает запуск/заражение.
Microsoft-Windows-Windows Defender	1008	Антивирус	High	Ошибка действия Defender (старый формат)	Проверить угрозу, ресурс, действие и результат; обнаружение не доказывает запуск/заражение.
Microsoft-Windows-Windows Defender	1118	Антивирус	High	Ошибка действия Defender	Проверить угрозу, ресурс, действие и результат; обнаружение не доказывает запуск/заражение.
Microsoft-Windows-Windows Defender	1119	Антивирус	High	Критическая ошибка действия Defender	Проверить угрозу, ресурс, действие и результат; обнаружение не доказывает запуск/заражение.
Microsoft-Windows-Windows Defender	1007	Антивирус	Medium	Defender выполнил действие (старый формат)	Для 1117/1007 проверить конкретное действие: Allow не означает удаление угрозы.
Microsoft-Windows-Windows Defender	1117	Антивирус	Medium	Defender выполнил действие над угрозой	Для 1117/1007 проверить конкретное действие: Allow не означает удаление угрозы.
Microsoft-Windows-Windows Defender	1013	Антивирус	Medium	Удалена история обнаружений Defender	Для 1117/1007 проверить конкретное действие: Allow не означает удаление угрозы.
Microsoft-Windows-Windows Defender	5007	Антивирус	Medium	Изменены настройки Defender	Для 1117/1007 проверить конкретное действие: Allow не означает удаление угрозы.
Microsoft-Windows-Windows Defender	5013	Антивирус	Medium	Защита от изменений заблокировала изменение	Для 1117/1007 проверить конкретное действие: Allow не означает удаление угрозы.
Microsoft-Windows-Windows Defender	5001	Антивирус	High	Отключена защита Defender в реальном времени	Проверить длительность и причину; Defender может быть отключен при наличии другого антивируса.
Microsoft-Windows-Windows Defender	5010	Антивирус	High	Отключено сканирование нежелательного ПО	Проверить длительность и причину; Defender может быть отключен при наличии другого антивируса.
Microsoft-Windows-Windows Defender	5012	Антивирус	High	Отключено антивирусное сканирование	Проверить длительность и причину; Defender может быть отключен при наличии другого антивируса.
Microsoft-Windows-Windows Defender	5008	Антивирус	High	Сбой антивирусного движка	Проверить длительность и причину; Defender может быть отключен при наличии другого антивируса.
Microsoft-Windows-Windows Defender	3002	Антивирус	High	Сбой компонента защиты в реальном времени	Проверить длительность и причину; Defender может быть отключен при наличии другого антивируса.
Microsoft-Windows-TerminalServices-RemoteConnectionManager	1149	Удаленный доступ	Info	Terminal Services: успешная аутентификация	Не доказывает создание рабочего стола и не задает длительность RDP.
Microsoft-Windows-TerminalServices-LocalSessionManager	21	Удаленный доступ	Info	Terminal Services: вход в сеанс	Дополнительная временная линия; проверить Address/User/SessionID, возможен локальный сеанс.
Microsoft-Windows-TerminalServices-LocalSessionManager	22	Удаленный доступ	Info	Terminal Services: запуск оболочки	Дополнительная временная линия; проверить Address/User/SessionID, возможен локальный сеанс.
Microsoft-Windows-TerminalServices-LocalSessionManager	23	Удаленный доступ	Info	Terminal Services: выход из сеанса	Дополнительная временная линия; проверить Address/User/SessionID, возможен локальный сеанс.
Microsoft-Windows-TerminalServices-LocalSessionManager	24	Удаленный доступ	Info	Terminal Services: отключение сеанса	Дополнительная временная линия; проверить Address/User/SessionID, возможен локальный сеанс.
Microsoft-Windows-TerminalServices-LocalSessionManager	25	Удаленный доступ	Info	Terminal Services: повторное подключение	Дополнительная временная линия; проверить Address/User/SessionID, возможен локальный сеанс.
Microsoft-Windows-Sysmon	4	Дополнительные признаки	Medium	Изменилось состояние службы Sysmon	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-Sysmon	6	Дополнительные признаки	Medium	Загружен драйвер	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-Sysmon	16	Дополнительные признаки	Medium	Изменена конфигурация Sysmon	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-Sysmon	19	Дополнительные признаки	Medium	Зарегистрирован WMI-фильтр	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-Sysmon	20	Дополнительные признаки	Medium	Зарегистрирован WMI-consumer	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-Sysmon	21	Дополнительные признаки	Medium	Связан WMI-filter и consumer	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-Sysmon	25	Дополнительные признаки	Medium	Sysmon: вмешательство в процесс	Если Sysmon установлен: проверить подпись, пути и назначение. Событие не всегда означает атаку.
Microsoft-Windows-TaskScheduler	106	Закрепление / запуск	Medium	Зарегистрировано задание планировщика	Дополнительный источник к Security 4698/4702/4699; проверить задание.
Microsoft-Windows-TaskScheduler	140	Закрепление / запуск	Medium	Обновлено задание планировщика	Дополнительный источник к Security 4698/4702/4699; проверить задание.
Microsoft-Windows-TaskScheduler	141	Закрепление / запуск	Medium	Удалено задание планировщика	Дополнительный источник к Security 4698/4702/4699; проверить задание.
'@ | ConvertFrom-Csv -Delimiter "`t"
# v9: default rule set keeps only security-relevant, low/medium-volume events.
# The rules below are high-volume or purely operational; -IncludeNoise returns them.
$script:NoiseRules = [System.Collections.Generic.HashSet[string]]::new([string[]]@(
    'Microsoft-Windows-Security-Auditing|4670',  # object permissions: very noisy with Object Access audit
    'Microsoft-Windows-Security-Auditing|4672',  # special privileges at logon: context only, one per admin/service logon
    'Microsoft-Windows-Security-Auditing|4700',
    'Microsoft-Windows-Security-Auditing|4701',
    'Microsoft-Windows-Security-Auditing|4705',
    'Microsoft-Windows-Security-Auditing|4718',
    'Microsoft-Windows-Security-Auditing|4742',  # computer account changed: machine password rotation on DCs
    'Microsoft-Windows-Security-Auditing|4767',
    'Microsoft-Windows-Security-Auditing|4902',
    'Microsoft-Windows-Security-Auditing|4911',
    'Microsoft-Windows-Security-Auditing|4913',
    'Microsoft-Windows-Security-Auditing|4950',
    'Microsoft-Windows-Security-Auditing|4954',  # firewall GPO refresh
    'Microsoft-Windows-Kernel-General|1',         # time sync; Security 4616 is the security signal
    'Microsoft-Windows-Kernel-General|12',
    'Microsoft-Windows-Kernel-General|13',
    'EventLog|6005',
    'EventLog|6006',
    'Service Control Manager|7000',
    'Service Control Manager|7001',
    'Service Control Manager|7011',
    'Service Control Manager|7023',
    'Service Control Manager|7024',
    'Service Control Manager|7031',
    'Service Control Manager|7034',
    'Application Error|1000',
    'Windows Error Reporting|1001',
    'Microsoft-Windows-Windows Defender|1013',
    'Microsoft-Windows-TerminalServices-LocalSessionManager|22',
    'Microsoft-Windows-Sysmon|6',
    'Microsoft-Windows-TaskScheduler|140'
))
# Generic "any Critical/Error event" rule: opt-in, it dominates System/Application volume.
$script:GenericErrors = [bool]($IncludeNoise -or $IncludeAllErrors)
$script:RuleTable=@($script:RuleTable | Where-Object {
    [int]$_.Id -le $MaxEventId -and ($IncludeNoise -or -not $script:NoiseRules.Contains($_.Provider + '|' + $_.Id))
})
foreach ($r in $script:RuleTable) { $script:Rules[($r.Provider + '|' + $r.Id)] = $r }
# Events that can influence RDP pairing / failure correlation; other events skip those calls.
$script:RdpRelevant = [System.Collections.Generic.HashSet[string]]::new([string[]]@(
    'Microsoft-Windows-Security-Auditing|4608','Microsoft-Windows-Security-Auditing|4616',
    'Microsoft-Windows-Security-Auditing|4624','Microsoft-Windows-Security-Auditing|4634',
    'Microsoft-Windows-Security-Auditing|4778','Microsoft-Windows-Security-Auditing|4779',
    'Microsoft-Windows-Eventlog|1102'))
$script:FailureIds=@(4625,4771,4776)
$script:HasStart=$PSBoundParameters.ContainsKey('StartTime')
$script:HasEnd=$PSBoundParameters.ContainsKey('EndTime')
$script:StartTicks=[long]0; $script:EndTicks=[DateTime]::MaxValue.Ticks
if ($script:HasStart) { $script:StartTicks=$StartTime.ToUniversalTime().Ticks }
if ($script:HasEnd) { $script:EndTicks=$EndTime.ToUniversalTime().Ticks }

function New-Writer([string]$Path, [bool]$Append = $false) {
    $w = New-Object System.IO.StreamWriter($Path, $Append, $script:Utf8, 65536)
    $script:Writers.Add($w)
    return $w
}
function Close-Writer($Writer) {
    if ($Writer) { $Writer.Dispose(); [void]$script:Writers.Remove($Writer) }
}
function Cell([object]$Value, [bool]$Safe = $true) {
    $s = [string]$Value
    $s = [regex]::Replace($s,'[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]',[Text.RegularExpressions.MatchEvaluator]{ param($m) return ('[U+{0:X4}]' -f [int][char]$m.Value[0]) })
    # One physical line per CSV row. Exact source values remain in the original EVTX;
    # optional Evidence JSONL is kept only with -KeepTechnicalFiles.
    $s = $s.Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    if ($Safe -and $s.Length -gt 30000) { $s=$s.Substring(0,30000)+' [обрезано; см. исходный EVTX или Technical Evidence]' }
    if ($Safe -and $s -match '^\s*[=+@-]') { $s = "'" + $s }
    return '"' + $s.Replace('"', '""') + '"'
}
function Write-Row($Writer, [object[]]$Values, [bool]$Safe = $true) {
    # Same transformations as Cell; avoid 46 function invocations per finding.
    $cells=New-Object 'string[]' $Values.Length
    for ($i=0; $i -lt $Values.Length; $i++) {
        $s=[string]$Values[$i]
        if ($script:FastCellInvalid.IsMatch($s)) { $s=$script:FastCellInvalid.Replace($s,$script:CellReplacement) }
        $s=$s.Replace("`r",'\r').Replace("`n",'\n').Replace("`t",'\t')
        if ($Safe -and $s.Length -gt 30000) { $s=$s.Substring(0,30000)+' [обрезано; см. исходный EVTX или Technical Evidence]' }
        if ($Safe -and $script:FastCellFormula.IsMatch($s)) { $s="'"+$s }
        $cells[$i]='"'+$s.Replace('"','""')+'"'
    }
    $Writer.WriteLine([string]::Join([string]$Delimiter,$cells))
}
function Hash-Text([string]$Text) {
    # Single-threaded run; ComputeHash resets the algorithm after each hash.
    return ([BitConverter]::ToString($script:HashEngine.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
}
function Field($Data, [string[]]$Names) {
    foreach ($n in $Names) {
        if ($Data.Contains($n) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$n]) -and [string]$Data[$n] -ne '-') { return [string]$Data[$n] }
    }
    return ''
}
function Account([string]$Domain, [string]$Name) {
    if (-not $Name -or $Name -eq '-') { return '' }
    if ($Domain -and $Domain -ne '-') { return $Domain + '\' + $Name }
    return $Name
}
function Ru-Severity([string]$Value) {
    switch ($Value) {
        'High' { return 'Высокий' }
        'Medium' { return 'Средний' }
        'Low' { return 'Низкий' }
        'Info' { return 'Инфо' }
        default { return $Value }
    }
}
function Ru-AuditOutcome([string]$Value) {
    switch ($Value) {
        'Success' { return 'Успех' }
        'Failure' { return 'Отказ' }
        default { return $Value }
    }
}
function Ru-MessageStatus([string]$Value) {
    switch ($Value) {
        'Available' { return 'Доступно' }
        'Unavailable' { return 'Недоступно' }
        'NotRequested' { return 'Не запрашивалось' }
        default { return $Value }
    }
}
function Ru-FileStatus([string]$Value) {
    switch ($Value) {
        'OK' { return 'OK' }
        'Warning' { return 'Завершено с предупреждениями' }
        'Partial' { return 'Частично' }
        'Failed' { return 'Ошибка' }
        'NoCandidates' { return 'Нет совпадений' }
        default { return $Value }
    }
}
function Ru-RunStatus([string]$Value) {
    switch ($Value) {
        'Running' { return 'Выполняется' }
        'Completed' { return 'Завершено' }
        'CompletedWithWarnings' { return 'Завершено с предупреждениями' }
        'CompletedWithErrors' { return 'Завершено с ошибками' }
        'Failed' { return 'Ошибка' }
        default { return $Value }
    }
}
function Ru-RdpStatus([string]$Value) {
    switch ($Value) {
        'Paired' { return 'Пара найдена' }
        'MissingStart' { return 'Не найдено начало' }
        'MissingEnd' { return 'Не найден конец' }
        'UncertainDuration' { return 'Длительность сомнительна' }
        default { return $Value }
    }
}
function Ru-Stage([string]$Value) {
    if ($Value -eq 'XmlRecovered') { return 'Восстановление XML' }
    if ($Value -eq 'Triage') { return 'Приоритизация' }
    switch ($Value) {
        'Discovery' { return 'Поиск файлов' }
        'Hash' { return 'Хеширование' }
        'BoundaryRead' { return 'Чтение границ файла' }
        'OpenQuery' { return 'Открытие запроса EVTX' }
        'ReadEvent' { return 'Чтение события' }
        'ParseOrRule' { return 'Разбор события / правило' }
        'ClockOrder' { return 'Порядок времени' }
        'InputChanged' { return 'Файл изменился во время чтения' }
        'Correlation' { return 'Корреляция' }
        'TriageRow' { return 'Приоритизация: строка' }
        'TriageChain' { return 'Приоритизация: связка' }
        'Fatal' { return 'Критическая ошибка скрипта' }
        default { return $Value }
    }
}
function Read-SafeXml([string]$Text) {
    $sr = New-Object IO.StringReader($Text)
    $xr = $null
    try {
        $xr = [Xml.XmlReader]::Create($sr,$script:ReaderSettings)
        $doc = New-Object Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($xr)
        return ,$doc
    } finally { if ($xr) { $xr.Dispose() }; $sr.Dispose() }
}
function Repair-XmlCharacters([string]$Text) {
    # Preserve valid surrogate pairs; replace only XML 1.0 forbidden characters.
    $pattern = '[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]'
    $fixed = [regex]::Replace($Text,$pattern,[Text.RegularExpressions.MatchEvaluator]{
        param($m)
        return ('[U+{0:X4}]' -f [int][char]$m.Value[0])
    })
    # Numeric references to forbidden characters are invalid too. Do not decode other entities.
    return [regex]::Replace($fixed,'&#(x[0-9a-fA-F]+|[0-9]+);',[Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $s=$m.Groups[1].Value
        try {
            if ($s.StartsWith('x')) { $n=[Convert]::ToInt64($s.Substring(1),16) }
            else { $n=[Convert]::ToInt64($s,10) }
        } catch { return $m.Value }
        if ($n -in @(9,10,13) -or ($n -ge 32 -and $n -le 55295) -or ($n -ge 57344 -and $n -le 65533) -or ($n -ge 65536 -and $n -le 1114111)) { return $m.Value }
        return ('[U+{0:X4}]' -f $n)
    })
}

function Parse-Event([string]$XmlText) {
    $recovery=''
    try { $xml=Read-SafeXml $XmlText }
    catch {
        $fixed=Repair-XmlCharacters $XmlText
        if ($fixed -ceq $XmlText) { throw }
        $xml=Read-SafeXml $fixed
        $recovery='Недопустимые XML-символы заменены маркерами [U+XXXX] только при разборе. Исходный EVTX не изменен.'
    }
    $ns = New-Object Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $sys = $xml.SelectSingleNode('/e:Event/e:System', $ns)
    if ($null -eq $sys) { throw 'Missing Event/System in event XML.' }
    $data = [ordered]@{}
    $i = 0
    foreach ($n in $xml.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $name = $n.GetAttribute('Name')
        if (-not $name) { $name = 'Data' + $i }
        if ($data.Contains($name)) { $name = $name + '#' + $i }
        $data[$name] = $n.InnerText
        $i++
    }
    foreach ($n in $xml.SelectNodes('/e:Event/e:UserData//*[not(*)]', $ns)) {
        $name = $n.LocalName
        if ($data.Contains($name)) { $name = 'UserData.' + $name + '#' + $i }
        $data[$name] = $n.InnerText
        $i++
    }
    $time = [DateTimeOffset]::Parse($sys.TimeCreated.GetAttribute('SystemTime'), $script:Invariant)
    $keywords = [string]$sys.Keywords
    $audit = ''
    if ($keywords) {
        $kw = [Convert]::ToUInt64(($keywords -replace '^0x',''),16)
        if (($kw -band [UInt64]4503599627370496) -ne 0) { $audit = 'Failure' }
        elseif (($kw -band [UInt64]9007199254740992) -ne 0) { $audit = 'Success' }
    }
    $levelNode = $sys.SelectSingleNode('e:Level',$ns)
    $ridNode = $sys.SelectSingleNode('e:EventRecordID',$ns)
    $channelNode = $sys.SelectSingleNode('e:Channel',$ns)
    $computerNode = $sys.SelectSingleNode('e:Computer',$ns)
    $level = 0; if ($levelNode) { $level = [int]$levelNode.InnerText }
    $rid = ''; if ($ridNode) { $rid = $ridNode.InnerText }
    $channel = ''; if ($channelNode) { $channel = $channelNode.InnerText }
    $computer = ''; if ($computerNode) { $computer = $computerNode.InnerText }
    return [pscustomobject]@{
        Provider=$sys.Provider.GetAttribute('Name'); Id=[int]$sys.SelectSingleNode('e:EventID',$ns).InnerText
        Channel=$channel; Computer=$computer; RecordId=$rid; Level=$level
        TimeUtc=$time.UtcDateTime.ToString('o',$script:Invariant); Ticks=$time.UtcDateTime.Ticks
        Data=$data; AuditOutcome=$audit; Xml=$XmlText; XmlRecovery=$recovery
        Subject=(Account (Field $data @('SubjectDomainName')) (Field $data @('SubjectUserName')))
        Target=(Account (Field $data @('TargetDomainName','AccountDomain')) (Field $data @('TargetUserName','AccountName')))
        SourceIP=(Field $data @('IpAddress','ClientAddress','Address','Param3'))
        LogonType=(Field $data @('LogonType'))
        LogonId=(Field $data @('TargetLogonId','LogonID','LogonId'))
        SessionName=(Field $data @('SessionName'))
        Message=''; MessageStatus='NotRequested'; Fingerprint=''
    }
}
function Match-Event($e, [bool]$VendorFile) {
    # v9: Event ID above -MaxEventId (default 10000) is never a finding, including
    # the full-scan fallback and third-party AV logs.
    if ($e.Id -gt $MaxEventId) { return }
    $key = $e.Provider + '|' + $e.Id
    $r = $null
    if ($script:Rules.ContainsKey($key)) {
        $orig = $script:Rules[$key]
        $r = [pscustomobject]@{Category=$orig.Category; Severity=$orig.Severity; Title=$orig.Title; Note=$orig.Note; RuleId=$key}
    }
    $d = $e.Data
    if ($e.Provider -eq 'Microsoft-Windows-Security-Auditing') {
        if ($e.Id -eq 4776) {
            $status = Field $d @('Status')
            if ($status -match '^(0x)?0+$') { return }
            if (-not $status -and $r) { $r.Note += ' Код результата отсутствует; исход неизвестен.' }
        }
        if ($e.Id -in @(4624,4634)) {
            if ($e.LogonType -eq '10') { $r.Title += ' (RemoteInteractive, тип 10)' }
            elseif ($IncludeNetworkLogons -and $e.Id -eq 4624 -and $e.LogonType -in @('3','8')) {
                $r.Title = 'Сетевой вход, тип ' + $e.LogonType
                $r.Note = 'Сетевой доступ: возможны SMB, WinRM, службы и другие механизмы; не доказательство RDP.'
            } else { return }
        }
        if ($r -and $e.Id -eq 4672 -and (Field $d @('SubjectUserSid')) -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
            if (-not $IncludeNoise) { return }
            $r.Severity = 'Info'; $r.Note += ' Встроенная служебная учетная запись.'
        }
        if ($e.Id -in @(4728,4732,4756)) {
            $sid = Field $d @('TargetSid')
            if ($sid -match '^S-1-5-32-(544|548|549|550|551)$|^S-1-5-21-\d+-\d+-\d+-(512|518|519)$') {
                $r.Severity = 'High'; $r.Title += ': привилегированная группа по SID'
                $r.Note = 'Зафиксировано добавление в известную привилегированную группу; проверить MemberSid и согласование. Проверка не вычисляет все эффективные права.'
            } elseif ($sid -eq 'S-1-5-32-555') { $r.Note += ' Группа Remote Desktop Users: предоставление возможности RDP.' }
            elseif ($sid -eq 'S-1-5-32-580') { $r.Note += ' Группа Remote Management Users: возможен удаленный доступ через средства управления/WinRM в зависимости от конфигурации.' }
        }
    }
    $scriptCandidate=($DeepScriptScan -and $e.Provider -eq 'Microsoft-Windows-PowerShell' -and $e.Id -eq 4104)
    $processCandidate=($IncludeProcessCreation -and (($e.Provider -eq 'Microsoft-Windows-Security-Auditing' -and $e.Id -eq 4688) -or
        ($e.Provider -eq 'Microsoft-Windows-Sysmon' -and $e.Id -eq 1)))
    if ($scriptCandidate -or $processCandidate) {
        $text = Field $d @('CommandLine','ScriptBlockText')
        if ($text -match '(?i)(-(enc|encodedcommand)\s|FromBase64String|DownloadString|Invoke-Expression|\biex\s|wevtutil\s+(cl|clear-log)\b|Clear-EventLog|vssadmin\s+delete\s+shadows|Set-MpPreference.+Disable|Add-MpPreference.+Exclusion)') {
            $r = [pscustomobject]@{Category='Подозрительные команды';Severity='Medium';Title='Эвристика: команда требует проверки';Note='Возможны штатные скрипты и цитирование кода. 4104 может быть разбит на части: восстановление и декодирование не выполняются.';RuleId='HEURISTIC-COMMAND'}
        }
    }
    if ($VendorFile -and $null -eq $r) {
        $vendorText = $e.Xml + ' ' + $e.Message
        $negative = $vendorText -match '(?i)(no\s+threats?\s+(were\s+)?found|no\s+malware\s+(was\s+)?found|угроз\s+не\s+обнаружено|вредоносн\w*\s+не\s+обнаружено|заражени\w*\s+не\s+обнаружено)'
        $threat = $vendorText -match '(?i)(infected|infection|malware|trojan|ransomware|virus|threat\s+(was\s+)?detected|quarantin|угроз|заражен|вредонос|троян|вирус|обнаружен\w*\s+угроз|карантин)'
        if ($threat -and -not $negative) {
            $r = [pscustomobject]@{Category='Антивирус';Severity='High';Title='Сторонний антивирус: возможное обнаружение угрозы';Note='Эвристика по XML/описанию. Проверить точное действие, объект, результат лечения и контекст в исходном EVTX.';RuleId='AV-VENDOR-THREAT'}
        } elseif ($e.Level -in @(1,2)) {
            $sev='Medium'; if ($e.Level -eq 1) { $sev='High' }
            $r = [pscustomobject]@{Category='Антивирус';Severity=$sev;Title='Сторонний антивирус: Critical/Error';Note='Ошибка/критическое событие продукта защиты. Проверить описание и XML в исходном EVTX.';RuleId='AV-VENDOR-ERROR'}
        } elseif ($IncludeAllAntivirusEvents) {
            $r = [pscustomobject]@{Category='Антивирус: ручная проверка';Severity='Info';Title='Событие стороннего антивируса';Note='Включен -IncludeAllAntivirusEvents. Точное значение Event ID зависит от продукта/версии.';RuleId='AV-VENDOR-REVIEW'}
        }
    }
    if ($null -eq $r -and $script:GenericErrors -and $e.Level -in @(1,2)) {
        $severity='Medium'; if ($e.Level -eq 1) { $severity='High' }
        $r=[pscustomobject]@{Category='Сбои';Severity=$severity;Title='Событие уровня Critical/Error';Note='Операционная неисправность; связь с ИБ требует отдельной проверки.';RuleId='GENERIC-LEVEL-'+$e.Level}
    }
    return $r
}
function Build-Query([string]$Path, [bool]$VendorFile) {
    $queryKey=([string]$VendorFile)+'|'+$IncludeNoise+'|'+$IncludeNetworkLogons+'|'+$DeepScriptScan+'|'+$IncludeProcessCreation+'|'+$script:GenericErrors+'|'+$MaxEventId+'|'+$script:StartTicks+'|'+$script:EndTicks
    if ($script:QueryCache.ContainsKey($queryKey)) { return $script:QueryCache[$queryKey] }
    # v9: the optional time window is applied inside System[], so Windows skips those
    # records before ToXml/PowerShell. Rule selectors list explicit IDs (already
    # <= MaxEventId); only the wildcard selectors need an explicit EventID limit.
    # Terms are kept few: a rejected query falls back to a much slower full scan.
    $common='EventID<='+$MaxEventId
    $time=''
    if ($script:HasStart) { $time+=" and TimeCreated[@SystemTime>='"+([DateTime]::new($script:StartTicks,[DateTimeKind]::Utc).ToString('yyyy-MM-ddTHH:mm:ss.fffZ',$script:Invariant))+"']" }
    if ($script:HasEnd) { $time+=" and TimeCreated[@SystemTime<='"+([DateTime]::new($script:EndTicks,[DateTimeKind]::Utc).ToString('yyyy-MM-ddTHH:mm:ss.fffZ',$script:Invariant))+"']" }
    $common+=$time
    $selectors = New-Object 'System.Collections.Generic.List[string]'
    if ($VendorFile) {
        # For named AV exports inspect every record. A structured QueryList is
        # retained so the same reader path can be used for all rule selectors.
        $selectors.Add("*[System[$common]]")
    } else {
    if ($script:GenericErrors) { $selectors.Add("*[System[(Level=1 or Level=2) and $common]]") }
    $groups = $script:RuleTable | Group-Object Provider
    foreach ($g in $groups) {
        # 4624/4634 need LogonType, 4776 needs Status: dedicated selectors below.
        $excludedSecurityIds=@(4624,4634,4776)
        $ids = @($g.Group | Where-Object { $_.Provider -ne 'Microsoft-Windows-Security-Auditing' -or [int]$_.Id -notin $excludedSecurityIds } | ForEach-Object { [int]$_.Id })
        # Short selectors keep each XPath below Windows Event Log complexity limits.
        for ($i=0; $i -lt $ids.Count; $i+=8) {
            $last = [Math]::Min($i+7,$ids.Count-1)
            $parts = @($ids[$i..$last] | ForEach-Object { 'EventID=' + $_ })
            $selectors.Add("*[System[Provider[@Name='$($g.Name)'] and ($($parts -join ' or '))$time]]")
        }
    }
    $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4634)$time] and EventData[Data[@Name='LogonType']='10']]")
    if ($script:Rules.ContainsKey('Microsoft-Windows-Security-Auditing|4776')) {
        # Successful NTLM validations (Status 0x0) are the bulk of 4776 on DCs and are never findings.
        $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4776$time] and EventData[Data[@Name='Status']!='0x0']]")
    }
    if ($IncludeNetworkLogons) {
        $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4624$time] and EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='8')]]")
    }
    if ($DeepScriptScan) {
        $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-PowerShell'] and EventID=4104$time]]")
    }
    if ($IncludeProcessCreation) {
        $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4688$time]]")
        $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and EventID=1$time]]")
    }
    }
    # The source file is supplied through EventLogQuery.Path with PathType=FilePath.
    # Do not duplicate the file name in QueryList. Microsoft documents that when a
    # structured query omits paths, the path supplied to EvtQuery/EventLogQuery is used.
    # This also avoids malformed file:// URIs for paths containing spaces, Cyrillic or %4.
    $xml=New-Object Text.StringBuilder
    [void]$xml.Append('<QueryList><Query Id="0">')
    foreach ($s in $selectors) { [void]$xml.Append('<Select>'+[Security.SecurityElement]::Escape($s)+'</Select>') }
    [void]$xml.Append('</Query></QueryList>')
    $script:QueryCache[$queryKey]=$xml.ToString()
    return $script:QueryCache[$queryKey]
}
function Log-Issue([string]$Stage,[string]$Path,[string]$RecordId,[string]$Text) {
    $script:IssueCount++
    if ($Stage -in @('XmlRecovered','ClockOrder')) { $script:WarningCount++ }
    Write-Row $script:ErrorWriter @([DateTime]::UtcNow.ToString('o'),(Ru-Stage $Stage),$Path,$RecordId,$Text)
}
function New-FindingFile {
    if ($script:FindingWriter) { Close-Writer $script:FindingWriter }
    $script:Part++
    $script:PartRows=0
    $script:FindingWriter=New-Writer (Join-Path $script:RunPath ('Findings-{0:D4}.csv' -f $script:Part))
    Write-Row $script:FindingWriter $script:FindingHeaders
}
function Save-Finding($e,$r,$file,[string]$EvidencePath) {
    if ($script:PartRows -ge $RowsPerCsv) { New-FindingFile }
    $script:FindingCount++; $script:PartRows++
    $id=$script:FindingCount
    $d=$e.Data
    $details=(@(foreach ($name in $d.Keys) { $name+'='+[string]$d[$name] }) -join ' | ')
    if ($details.Length -gt 4000) { $details=$details.Substring(0,4000)+' [обрезано; полный текст смотрите в исходном EVTX или техническом Evidence при -KeepTechnicalFiles]' }
    $message=$e.Message
    if ($message.Length -gt 8000) { $message=$message.Substring(0,8000)+' [обрезано; полный текст смотрите в исходном EVTX или техническом Evidence при -KeepTechnicalFiles]' }
    $delta=''
    $old=Field $d @('PreviousTime','OldTime'); $new=Field $d @('NewTime')
    if ($old -and $new) {
        try { $delta=([DateTimeOffset]::Parse($new,$script:Invariant)-[DateTimeOffset]::Parse($old,$script:Invariant)).TotalSeconds.ToString('0.#######',$script:Invariant) } catch { $delta='Unparsed' }
    }
    Write-Row $script:FindingWriter @($id,$e.Id,$e.RecordId,(Ru-Severity $r.Severity),$r.Category,$r.Title,$r.Note,$e.TimeUtc,$e.Computer,
        $file.DirectoryName,$file.Name,$file.FullName,$e.Channel,$e.Provider,$e.Level,(Ru-AuditOutcome $e.AuditOutcome),
        $e.Subject,(Field $d @('SubjectUserSid')),$e.Target,(Field $d @('TargetUserSid','TargetSid')),
        (Field $d @('MemberName')),(Field $d @('MemberSid')),$e.SourceIP,(Field $d @('IpPort','ClientPort')),
        (Field $d @('WorkstationName','Workstation','ClientName')),$e.LogonType,$e.LogonId,
        (Field $d @('SubjectLogonId')),(Field $d @('SessionID','SessionId')),$e.SessionName,
        (Field $d @('Status')),(Field $d @('SubStatus')),(Field $d @('ProcessName','NewProcessName','Image')),
        (Field $d @('CommandLine')),(Field $d @('PrivilegeList','AccessGranted','AccessRemoved','AccessList')),
        (Field $d @('Threat Name','ThreatName')),(Field $d @('Path','Resource Path')),
        $old,$new,$delta,$details,$message,(Ru-MessageStatus $e.MessageStatus),$r.RuleId,$e.Fingerprint,$e.XmlRecovery)
    if ($script:EvidenceWriter) {
        $script:EvidenceWriter.WriteLine(([ordered]@{FindingId=$id;SourceFile=$file.FullName;RuleId=$r.RuleId;
            Fingerprint=$e.Fingerprint;Xml=$e.Xml;Message=$e.Message;MessageStatus=$e.MessageStatus} | ConvertTo-Json -Depth 6 -Compress))
    }
    $key=$r.Severity+'|'+$r.Category+'|'+$e.Computer
    if (-not $script:Summary.ContainsKey($key)) { $script:Summary[$key]=[pscustomobject]@{Severity=$r.Severity;Category=$r.Category;Computer=$e.Computer;Count=0} }
    $script:Summary[$key].Count++
    return $id
}

# RDP intervals: conservative pairing inside ONE file, by computer + logon ID.
function Rdp-Key($e) { return $e.Computer.ToLowerInvariant()+'|'+$e.LogonId.ToLowerInvariant() }
function Save-Rdp($start,$end,[string]$Status,[string]$Reason) {
    $script:RdpCount++
    $duration=''; $endTime=''; $endRecord=''; $endId=''; $endEvent=''
    if ($end) { $endTime=$end.TimeUtc; $endRecord=$end.RecordId; $endId=$end.FindingId; $endEvent=$end.Id }
    if ($start -and $end -and $Status -eq 'Paired') {
        $seconds=($end.Ticks-$start.Ticks)/[TimeSpan]::TicksPerSecond
        if ($seconds -lt 0 -or $seconds -gt $MaxRdpHours*3600) { $Status='UncertainDuration'; $Reason='Отрицательная или слишком большая длительность; проверить часы/границы загрузки.' }
        else { $duration=$seconds.ToString('0.###',$script:Invariant) }
    }
    $anchor=$end; if ($start) { $anchor=$start }
    $startTime=''; $startRecord=''; $startId=''; $startEvent=''
    if ($start) { $startTime=$start.TimeUtc; $startRecord=$start.RecordId; $startId=$start.FindingId; $startEvent=$start.Id }
    Write-Row $script:RdpWriter @($startEvent,$endEvent,$anchor.File,$anchor.Computer,$anchor.Target,$anchor.LogonId,$anchor.SourceIP,
        $startTime,$endTime,$duration,(Ru-RdpStatus $Status),$Reason,$startRecord,$endRecord,$startId,$endId)
}
function Reset-Rdp($state,[string]$Computer,[string]$Reason) {
    foreach ($key in @($state.Keys)) {
        if (-not $Computer -or $state[$key].Computer -eq $Computer) {
            Save-Rdp $state[$key] $null 'MissingEnd' $Reason
            $state.Remove($key)
        }
    }
}
function Handle-Rdp($e,$state,[string]$File,[long]$FindingId) {
    if (($e.Provider -eq 'Microsoft-Windows-Security-Auditing' -and $e.Id -in @(4608,4616)) -or
        ($e.Provider -eq 'Microsoft-Windows-Eventlog' -and $e.Id -eq 1102)) {
        Reset-Rdp $state $e.Computer 'Запуск ОС, изменение часов или очистка журнала: пара не строится через эту границу.'
        return
    }
    if ($e.Provider -ne 'Microsoft-Windows-Security-Auditing' -or -not $e.Computer -or -not $e.LogonId -or $e.LogonId -eq '0x0') { return }
    $key=Rdp-Key $e
    $isRdpName=$e.SessionName -match '^RDP-'
    $isStart=($e.Id -eq 4624 -and $e.LogonType -eq '10') -or ($e.Id -eq 4778 -and $isRdpName)
    $isEnd=($e.Id -eq 4634 -and ($e.LogonType -eq '10' -or $state.ContainsKey($key))) -or ($e.Id -eq 4779 -and ($isRdpName -or $state.ContainsKey($key)))
    if (-not $isStart -and -not $isEnd) { return }
    $point=[pscustomobject]@{File=$File;Computer=$e.Computer;Target=$e.Target;LogonId=$e.LogonId;SourceIP=$e.SourceIP;
        TimeUtc=$e.TimeUtc;Ticks=$e.Ticks;RecordId=$e.RecordId;FindingId=$FindingId;Id=$e.Id}
    if ($isStart) {
        if ($state.ContainsKey($key)) { Save-Rdp $state[$key] $null 'MissingEnd' 'Новый вход/переподключение до найденного конца; прежний интервал не закрывается предположением.' }
        $state[$key]=$point
    } elseif ($state.ContainsKey($key)) {
        $start=$state[$key]
        if ($start.Target -and $e.Target -and $start.Target -ne $e.Target) {
            Save-Rdp $start $null 'MissingEnd' 'Разные учетные записи при одинаковом LogonId.'
            Save-Rdp $null $point 'MissingStart' 'Начало с подходящей учетной записью не найдено.'
        } else { Save-Rdp $start $point 'Paired' 'Интервал по Security; время между подключением и отключением/выходом, не активность пользователя.' }
        $state.Remove($key)
    } else { Save-Rdp $null $point 'MissingStart' 'Начало в этом файле не найдено; выход после ранее зафиксированного отключения также возможен.' }
}

# Failure spool partitions: directory + computer + EventID. This avoids combining
# 4625 and 4771/4776 as though each were an independent password attempt.
function Save-Failure($e,$file,[long]$FindingId,$spoolWriters) {
    if ($SkipCorrelation -or $e.Provider -ne 'Microsoft-Windows-Security-Auditing' -or $e.Id -notin @(4625,4771,4776)) { return }
    if ($e.Id -eq 4776 -and ((Field $e.Data @('Status')) -match '^(0x)?0+$' -or -not (Field $e.Data @('Status')))) { return }
    $scope=$file.DirectoryName
    # Unknown computer stays file-scoped to prevent mixing unrelated exports.
    $partition=$scope.ToLowerInvariant()+'|'+$e.Computer.ToLowerInvariant()+'|'+$e.Id
    if (-not $e.Computer) { $partition+='|'+$file.Name }
    if (-not $spoolWriters.ContainsKey($partition)) {
        $hash=Hash-Text $partition
        $path=Join-Path $script:SpoolPath ($hash+'.jsonl')
        $w=New-Writer $path $true
        $spoolWriters[$partition]=$w
    }
    $source=$e.SourceIP
    if ($source -match '^::ffff:') { $source=$source.Substring(7) }
    if (-not $source -or $source -eq '-') { $source=Field $e.Data @('WorkstationName','Workstation','ClientName') }
    if (-not $source) { $source='[unknown]' }
    $account=$e.Target; if (-not $account) { $account='[unknown]' }
    $spoolWriters[$partition].WriteLine(([ordered]@{Ticks=$e.Ticks;TimeUtc=$e.TimeUtc;Computer=$e.Computer;Scope=$scope;
        EventId=$e.Id;Account=$account;Source=$source;Fingerprint=$e.Fingerprint;FindingId=$FindingId;
        File=$file.FullName;RecordId=$e.RecordId;Status=(Field $e.Data @('Status'));SubStatus=(Field $e.Data @('SubStatus'))} | ConvertTo-Json -Compress))
}
function Save-Burst($queue,[string]$Mode) {
    $items=@($queue.ToArray())
    $first=$items[0]; $last=$items[$items.Count-1]
    $users=@($items | Select-Object -ExpandProperty Account -Unique)
    $sample=@($items | Select-Object -First 20)
    $kind='Повторные отказы для УЗ и источника'; $severity='Medium'
    if ($Mode -eq 'Source') { $kind='Отказы для нескольких УЗ с одного источника: возможный password spraying'; $severity='High' }
    $script:BurstCount++
    Write-Row $script:BurstWriter @((Ru-Severity $severity),$first.EventId,$kind,$first.Scope,$first.Computer,$first.Source,
        $first.TimeUtc,$last.TimeUtc,$items.Count,$users.Count,($users -join ' | '),
        (($sample | ForEach-Object {$_.FindingId}) -join ' | '),
        (($sample | ForEach-Object {$_.File+'#'+$_.RecordId}) -join ' | '),
        (($items | ForEach-Object {$_.Status+'/'+$_.SubStatus} | Select-Object -Unique) -join ' | '),
        'Скользящее окно; число событий, не доказанное число попыток пароля. Проверить причины отказа и сохраненные пароли. Ссылки: первые 20 событий окна.')
}
function Correlate-Failures([string]$Path) {
    # Only one compact partition in memory, never the complete XML/findings corpus.
    $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    $rows=@([IO.File]::ReadLines($Path) | ForEach-Object { ConvertFrom-Json -InputObject $_ } | Where-Object { $seen.Add($_.Fingerprint) } | Sort-Object @{Expression={[long]$_.Ticks}})
    $groups=@{}; $iteration=0
    $windowTicks=[long]$WindowMinutes*[TimeSpan]::TicksPerMinute
    foreach ($row in $rows) {
        $now=[long]$row.Ticks
        foreach ($mode in @('Account','Source')) {
            # Do not infer one network source or distinct accounts from missing fields.
            if ($mode -eq 'Source' -and ($row.Source -eq '[unknown]' -or $row.Account -eq '[unknown]')) { continue }
            $key=$mode+'|'+$row.Source.ToLowerInvariant()
            if ($mode -eq 'Account') { $key+='|'+$row.Account.ToLowerInvariant() }
            if (-not $groups.ContainsKey($key)) { $groups[$key]=[pscustomobject]@{Queue=(New-Object 'System.Collections.Generic.Queue[object]'); LastAlert=[long]0; UserCounts=@{}} }
            $g=$groups[$key]; $q=$g.Queue
            while ($q.Count -gt 0 -and [long]$q.Peek().Ticks -lt ($now-$windowTicks)) {
                $removed=$q.Dequeue()
                if ($mode -eq 'Source') {
                    $userKey=$removed.Account.ToLowerInvariant()
                    $g.UserCounts[$userKey]--
                    if ($g.UserCounts[$userKey] -eq 0) { $g.UserCounts.Remove($userKey) }
                }
            }
            $q.Enqueue($row)
            if ($mode -eq 'Source') {
                $userKey=$row.Account.ToLowerInvariant()
                if (-not $g.UserCounts.ContainsKey($userKey)) { $g.UserCounts[$userKey]=0 }
                $g.UserCounts[$userKey]++
            }
            $crossed=$q.Count -ge $FailureThreshold
            if ($crossed -and $mode -eq 'Source') { $crossed=$g.UserCounts.Count -ge $SprayUserThreshold }
            if ($crossed -and ($g.LastAlert -eq 0 -or ($now-$g.LastAlert) -ge $windowTicks)) { Save-Burst $q $mode; $g.LastAlert=$now }
        }
        $iteration++
        if ($iteration % 512 -eq 0) {
            foreach ($key in @($groups.Keys)) {
                $entry=$groups[$key]; $q=$entry.Queue
                while ($q.Count -gt 0 -and [long]$q.Peek().Ticks -lt ($now-$windowTicks)) {
                    $removed=$q.Dequeue()
                    if ($key.StartsWith('Source|')) {
                        $userKey=$removed.Account.ToLowerInvariant()
                        $entry.UserCounts[$userKey]--
                        if ($entry.UserCounts[$userKey] -eq 0) { $entry.UserCounts.Remove($userKey) }
                    }
                }
                if ($q.Count -eq 0) { $groups.Remove($key) }
            }
        }
    }
}
# Reference implementation from v8. Used only by equivalence SelfTest.
function Correlate-FailuresReference([string]$Path) {
    # Only one compact partition in memory, never the complete XML/findings corpus.
    $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    $rows=@([IO.File]::ReadLines($Path) | ForEach-Object { ConvertFrom-Json -InputObject $_ } | Where-Object { $seen.Add($_.Fingerprint) } | Sort-Object @{Expression={[long]$_.Ticks}})
    $groups=@{}; $iteration=0
    $windowTicks=[long]$WindowMinutes*[TimeSpan]::TicksPerMinute
    foreach ($row in $rows) {
        $now=[long]$row.Ticks
        foreach ($mode in @('Account','Source')) {
            # Do not infer one network source or distinct accounts from missing fields.
            if ($mode -eq 'Source' -and ($row.Source -eq '[unknown]' -or $row.Account -eq '[unknown]')) { continue }
            $key=$mode+'|'+$row.Source.ToLowerInvariant()
            if ($mode -eq 'Account') { $key+='|'+$row.Account.ToLowerInvariant() }
            if (-not $groups.ContainsKey($key)) { $groups[$key]=[pscustomobject]@{Queue=(New-Object 'System.Collections.Generic.Queue[object]'); LastAlert=[long]0} }
            $g=$groups[$key]; $q=$g.Queue
            while ($q.Count -gt 0 -and [long]$q.Peek().Ticks -lt ($now-$windowTicks)) { [void]$q.Dequeue() }
            $q.Enqueue($row)
            $crossed=$q.Count -ge $FailureThreshold
            if ($crossed -and $mode -eq 'Source') { $crossed=@($q.ToArray() | ForEach-Object {$_.Account.ToLowerInvariant()} | Select-Object -Unique).Count -ge $SprayUserThreshold }
            if ($crossed -and ($g.LastAlert -eq 0 -or ($now-$g.LastAlert) -ge $windowTicks)) { Save-Burst $q $mode; $g.LastAlert=$now }
        }
        $iteration++
        if ($iteration % 512 -eq 0) {
            foreach ($key in @($groups.Keys)) {
                $q=$groups[$key].Queue
                while ($q.Count -gt 0 -and [long]$q.Peek().Ticks -lt ($now-$windowTicks)) { [void]$q.Dequeue() }
                if ($q.Count -eq 0) { $groups.Remove($key) }
            }
        }
    }
}
function Assert-True([bool]$Condition,[string]$Name) {
    if (-not $Condition) { throw ('SelfTest FAILED: '+$Name) }
    Write-Host ('PASS: '+$Name)
}
function Test-Xml([int]$Id,[string]$Provider,[string]$Payload,[string]$Keywords='0x8020000000000000') {
    return '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="'+$Provider+'"/><EventID>'+$Id+'</EventID><Level>0</Level><Keywords>'+$Keywords+'</Keywords><TimeCreated SystemTime="2026-01-01T10:00:00.0000000Z"/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>PC01</Computer></System>'+$Payload+'</Event>'
}
function Run-SelfTest {
    $security='Microsoft-Windows-Security-Auditing'
    $e=Parse-Event (Test-Xml 1102 'Microsoft-Windows-Eventlog' '<UserData><LogFileCleared xmlns="urn:test"><SubjectUserName>alice</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName></LogFileCleared></UserData>')
    Assert-True ($e.Subject -eq 'LAB\alice') '1102 UserData and XML namespace'
    Assert-True ((Match-Event $e $false).Severity -eq 'High') '1102 provider-aware rule'
    $e.Provider='Unrelated-Provider'; Assert-True ($null -eq (Match-Event $e $false)) 'same ID with unrelated provider; Level 0 is not Critical'
    $e=Parse-Event (Test-Xml 4776 $security '<EventData><Data Name="Status">0x0</Data></EventData>')
    Assert-True ($null -eq (Match-Event $e $false)) 'successful NTLM validation excluded'
    $e=Parse-Event (Test-Xml 4625 $security '<EventData><Data Name="TargetUserName">alice</Data></EventData>' '0x8010000000000000')
    Assert-True ($e.AuditOutcome -eq 'Failure') 'Audit Failure keyword'
    $e=Parse-Event (Test-Xml 4732 $security '<EventData><Data Name="TargetSid">S-1-5-32-544</Data></EventData>')
    Assert-True ((Match-Event $e $false).Severity -eq 'High') 'administrators identified by SID'
    $e.Data['TargetSid']='S-1-5-32-545'
    Assert-True ((Match-Event $e $false).Severity -eq 'Medium') 'ordinary group not labeled privilege escalation'
    Assert-True ((Cell '=HYPERLINK("x")') -eq '"''=HYPERLINK(""x"")"') 'CSV formula neutralization'
    $query=Build-Query 'C:\Logs & audit\Security.evtx' $false
    $doc=New-Object Xml.XmlDocument; $doc.LoadXml($query)
    Assert-True (-not $doc.QueryList.Query.HasAttribute('Path')) 'structured query uses EventLogQuery file path'
    Assert-True ($doc.QueryList.Query.Select.Count -gt 0) 'structured query contains selectors'
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-SelfTest-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tmp)
    try {
        $script:RdpCount=0; $script:BurstCount=0
        $script:RdpWriter=New-Writer (Join-Path $tmp 'rdp.csv')
        Write-Row $script:RdpWriter @('StartEvent','EndEvent','File','Computer','Account','LogonId','Source','Start','End','Seconds','Status','Reason','StartRecord','EndRecord','StartFinding','EndFinding')
        $state=@{}
        $e=Parse-Event (Test-Xml 4624 $security '<EventData><Data Name="LogonType">10</Data><Data Name="TargetLogonId">0xabc</Data><Data Name="TargetUserName">alice</Data></EventData>')
        Handle-Rdp $e $state 'sample.evtx' 1
        $e.Id=4779; $e.SessionName='RDP-Tcp#1'; $e.Ticks+=[TimeSpan]::TicksPerMinute*5; $e.TimeUtc='2026-01-01T10:05:00.0000000Z'
        Handle-Rdp $e $state 'sample.evtx' 2
        Assert-True ($state.Count -eq 0 -and $script:RdpCount -eq 1) 'RDP disconnect closes connected interval'
        $e.Id=4778; Handle-Rdp $e $state 'sample.evtx' 3
        $e.Id=4616; Handle-Rdp $e $state 'sample.evtx' 4
        Assert-True ($state.Count -eq 0 -and $script:RdpCount -eq 2) 'clock-change barrier invalidates pending interval'
        Close-Writer $script:RdpWriter
        $rdp=@(Import-Csv -LiteralPath (Join-Path $tmp 'rdp.csv') -Delimiter $Delimiter)
        Assert-True ($rdp[0].Seconds -eq '300' -and $rdp[1].Status -eq 'Не найден конец') 'RDP duration and partial status'
        $script:BurstWriter=New-Writer (Join-Path $tmp 'bursts.csv')
        Write-Row $script:BurstWriter @('Severity','EventId','Kind','Scope','Computer','Source','Start','End','Count','Users','Accounts','Findings','Files','Codes','Note')
        $spool=Join-Path $tmp 'failures.jsonl'; $w=New-Writer $spool
        $base=[datetime]::Parse('2026-01-01T10:09:58Z').ToUniversalTime()
        for ($i=0;$i -lt $FailureThreshold;$i++) {
            $t=$base.AddMilliseconds($i)
            $row=[ordered]@{Ticks=$t.Ticks;TimeUtc=$t.ToString('o');Computer='PC01';Scope='scope';EventId=4625;Account='alice';Source='10.0.0.1';Fingerprint=('hash'+$i);FindingId=($i+1);File='a.evtx';RecordId=($i+1);Status='0xc000006d';SubStatus='0xc000006a'}
            $w.WriteLine(($row | ConvertTo-Json -Compress))
            $w.WriteLine(($row | ConvertTo-Json -Compress)) # overlapping exports must not double the count
        }
        Close-Writer $w; Correlate-Failures $spool; Close-Writer $script:BurstWriter
        $bursts=@(Import-Csv -LiteralPath (Join-Path $tmp 'bursts.csv') -Delimiter $Delimiter)
        Assert-True ($script:BurstCount -eq 1 -and [int]$bursts[0].Count -eq $FailureThreshold) 'failure threshold and duplicate evidence removal'
        Write-Host 'Basic tests passed; correlation tests follow.'
    } finally {
        foreach ($w in $script:Writers) { $w.Dispose() }
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}

function Combine-CsvParts([object[]]$Parts,[string]$Destination) {
    $writer=New-Writer $Destination
    try {
        $firstPart=$true
        foreach ($part in $Parts) {
            $reader=New-Object System.IO.StreamReader($part.FullName,[Text.Encoding]::UTF8,$true,65536)
            try {
                $lineNumber=0
                while (-not $reader.EndOfStream) {
                    $line=$reader.ReadLine()
                    if ($lineNumber -eq 0 -and -not $firstPart) { $lineNumber++; continue }
                    $writer.WriteLine($line)
                    $lineNumber++
                }
            } finally { $reader.Dispose() }
            $firstPart=$false
        }
    } finally { Close-Writer $writer }
}
function New-RunSummaryCsv([string]$WorkPath) {
    $jsonPath=Join-Path $WorkPath 'Run.json'
    if (-not (Test-Path -LiteralPath $jsonPath)) { return $null }
    $run=Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $path=Join-Path $WorkPath 'RunSummary.csv'
    $w=New-Writer $path
    try {
        Write-Row $w @('Параметр','Значение')
        $pairs=@(
            [pscustomobject]@{Label='Статус';Value=(Ru-RunStatus $run.Status)},
            [pscustomobject]@{Label='Версия скрипта';Value=$run.ScriptVersion},
            [pscustomobject]@{Label='Начало UTC';Value=$run.StartedUtc},
            [pscustomobject]@{Label='Завершение UTC';Value=$run.FinishedUtc},
            [pscustomobject]@{Label='Входной путь';Value=$run.InputPath},
            [pscustomobject]@{Label='PowerShell';Value=$run.PowerShell},
            [pscustomobject]@{Label='Файлов обнаружено';Value=$run.FilesDiscovered},
            [pscustomobject]@{Label='Файлов обработано';Value=$run.FilesProcessed},
            [pscustomobject]@{Label='Файлов с предупреждениями';Value=$run.WarningFiles},
            [pscustomobject]@{Label='Файлов Partial/Failed';Value=$run.FailedOrPartialFiles},
            [pscustomobject]@{Label='Находок';Value=$run.Findings},
            [pscustomobject]@{Label='RDP-интервалов';Value=$run.RdpRows},
            [pscustomobject]@{Label='Серий отказов аутентификации';Value=$run.AuthBursts},
            [pscustomobject]@{Label='Замечаний обработки';Value=$run.Issues},
            [pscustomobject]@{Label='Предупреждений обработки';Value=$run.ProcessingWarnings},
            [pscustomobject]@{Label='Ошибок корреляции';Value=$run.CorrelationErrors},
            [pscustomobject]@{Label='Порог отказов';Value=$run.Parameters.FailureThreshold},
            [pscustomobject]@{Label='Окно отказов, мин';Value=$run.Parameters.WindowMinutes},
            [pscustomobject]@{Label='Порог разных УЗ для spraying';Value=$run.Parameters.SprayUserThreshold},
            [pscustomobject]@{Label='Максимальный Event ID';Value=$run.Parameters.MaxEventId},
            [pscustomobject]@{Label='Период: начало UTC';Value=$run.Parameters.StartTimeUtc},
            [pscustomobject]@{Label='Период: конец UTC';Value=$run.Parameters.EndTimeUtc},
            [pscustomobject]@{Label='IncludeNoise';Value=$run.Parameters.IncludeNoise},
            [pscustomobject]@{Label='IncludeAllErrors';Value=$run.Parameters.IncludeAllErrors},
            [pscustomobject]@{Label='DeepScriptScan';Value=$run.Parameters.DeepScriptScan},
            [pscustomobject]@{Label='IncludeProcessCreation';Value=$run.Parameters.IncludeProcessCreation},
            [pscustomobject]@{Label='IncludeNetworkLogons';Value=$run.Parameters.IncludeNetworkLogons},
            [pscustomobject]@{Label='IncludeMessages';Value=$run.Parameters.IncludeMessages},
            [pscustomobject]@{Label='HashFiles';Value=$run.Parameters.HashFiles}
        )
        foreach ($pair in $pairs) { Write-Row $w @($pair.Label,$pair.Value) }
    } finally { Close-Writer $w }
    return $path
}
function Export-ReportsToExcel([string]$WorkPath,[string]$XlsxPath) {
    $reports=New-Object 'System.Collections.Generic.List[object]'
    $triagePath=Join-Path $WorkPath 'Triage.csv'
    if (Test-Path -LiteralPath $triagePath) { $reports.Add([pscustomobject]@{Name='Приоритетные';Path=$triagePath}) }
    $parts=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'Findings-*.csv' -File | Sort-Object Name)
    for ($i=0; $i -lt $parts.Count; $i++) {
        $name='Находки'
        if ($parts.Count -gt 1) { $name='Находки_'+($i+1) }
        $reports.Add([pscustomobject]@{Name=$name;Path=$parts[$i].FullName})
    }
    $extraReports=@(
        [pscustomobject]@{Name='Сводка';File='Summary.csv'},
        [pscustomobject]@{Name='Подбор_пароля';File='AuthBursts.csv'},
        [pscustomobject]@{Name='RDP_сеансы';File='RdpIntervals.csv'},
        [pscustomobject]@{Name='Файлы';File='Files.csv'},
        [pscustomobject]@{Name='Качество_выгрузки';File='Coverage.csv'},
        [pscustomobject]@{Name='Ошибки';File='Errors.csv'}
    )
    foreach ($item in $extraReports) {
        $path=Join-Path $WorkPath $item.File
        if (Test-Path -LiteralPath $path) { $reports.Add([pscustomobject]@{Name=$item.Name;Path=$path}) }
    }
    $runSummary=New-RunSummaryCsv $WorkPath
    if ($runSummary) { $reports.Add([pscustomobject]@{Name='Запуск';Path=$runSummary}) }
    if ($reports.Count -eq 0) { throw 'Нет CSV-отчетов для упаковки в Excel.' }

    $excel=$null; $book=$null
    try {
        $excel=New-Object -ComObject Excel.Application -ErrorAction Stop
        $excel.Visible=$false
        $excel.DisplayAlerts=$false
        try { $excel.ScreenUpdating=$false } catch { }
        try { $excel.EnableEvents=$false } catch { }
        try { $excel.Calculation=-4135 } catch { } # xlCalculationManual
        try { $excel.SheetsInNewWorkbook=1 } catch { }
        $book=$excel.Workbooks.Add()
        while ($book.Worksheets.Count -lt $reports.Count) { [void]$book.Worksheets.Add() }
        while ($book.Worksheets.Count -gt $reports.Count) { $book.Worksheets.Item($book.Worksheets.Count).Delete() }
        for ($i=0; $i -lt $reports.Count; $i++) {
            $sheet=$null; $cell=$null; $qt=$null; $used=$null
            try {
                $sheet=$book.Worksheets.Item($i+1)
                $sheet.Name=[string]$reports[$i].Name
                $cell=$sheet.Range('A1')
                $qt=$sheet.QueryTables.Add(('TEXT;'+[string]$reports[$i].Path),$cell)
                $qt.BackgroundQuery=$false
                $qt.TextFilePromptOnRefresh=$false
                $qt.TextFilePlatform=65001
                $qt.TextFileStartRow=1
                $qt.TextFileParseType=1
                $qt.TextFileTextQualifier=1
                $qt.TextFileConsecutiveDelimiter=$false
                $qt.TextFileTabDelimiter=($Delimiter -eq "`t")
                $qt.TextFileSemicolonDelimiter=($Delimiter -eq ';')
                $qt.TextFileCommaDelimiter=($Delimiter -eq ',')
                $qt.TextFileSpaceDelimiter=$false
                if ($Delimiter -ne ';' -and $Delimiter -ne ',' -and $Delimiter -ne "`t") { $qt.TextFileOtherDelimiter=[string]$Delimiter }
                $qt.TextFileColumnDataTypes=@(1..100 | ForEach-Object { 2 })
                [void]$qt.Refresh($false)
                $qt.Delete()
                $qt=$null
                $sheet.Rows.Item(1).Font.Bold=$true
                $used=$sheet.UsedRange
                if ($used.Rows.Count -gt 0 -and $used.Columns.Count -gt 0) {
                    try { [void]$used.AutoFilter() } catch { }
                    $rowCount=[int]($used.Rows.Count)
                    if ($rowCount -le 1000) {
                        try { [void]$used.Columns.AutoFit() } catch { }
                        $maxCols=[Math]::Min([int]($used.Columns.Count),100)
                        for ($c=1; $c -le $maxCols; $c++) {
                            try { if ($sheet.Columns.Item($c).ColumnWidth -gt 60) { $sheet.Columns.Item($c).ColumnWidth=60 } } catch { }
                        }
                    } else {
                        # AutoFit scans every cell and can take many minutes on a
                        # wide findings sheet. Fixed width keeps export predictable;
                        # the full value remains in the cell and formula bar.
                        try { $used.Columns.ColumnWidth=18 } catch { }
                    }
                }
                try {
                    $sheet.Activate()
                    $excel.ActiveWindow.SplitColumn=0
                    $excel.ActiveWindow.SplitRow=1
                    $excel.ActiveWindow.FreezePanes=$true
                } catch { }
            } finally {
                if ($used) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($used) }
                if ($qt) { try { $qt.Delete() } catch { }; [void][Runtime.InteropServices.Marshal]::ReleaseComObject($qt) }
                if ($cell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($cell) }
                if ($sheet) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sheet) }
            }
        }
        if (Test-Path -LiteralPath $XlsxPath) { Remove-Item -LiteralPath $XlsxPath -Force }
        $firstSheet=$book.Worksheets.Item(1)
        try { $firstSheet.Activate() } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($firstSheet) }
        $book.SaveAs($XlsxPath,51)
        $book.Close($false)
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($book); $book=$null
        $excel.Quit()
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($excel); $excel=$null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        if (-not (Test-Path -LiteralPath $XlsxPath)) { throw 'Excel не создал итоговый XLSX.' }
    } catch {
        if ($book) { try { $book.Close($false) } catch { }; try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($book) } catch { } }
        if ($excel) { try { $excel.Quit() } catch { }; try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($excel) } catch { } }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        throw
    }
}
function New-FallbackOverview([string]$WorkPath,[string]$Destination) {
    $w=New-Writer $Destination
    try {
        Write-Row $w @('Тип строки','Event ID','Приоритет','Категория / событие','Компьютер','Начало UTC','Конец UTC','Учетная запись','Источник / IP','Record ID','Количество','Статус','Файл','Комментарий')
        $triagePath=Join-Path $WorkPath 'Triage.csv'
        if (Test-Path -LiteralPath $triagePath) {
            Import-Csv -LiteralPath $triagePath -Delimiter $Delimiter -Encoding UTF8 | ForEach-Object {
                $r=$_
                Write-Row $w @('Приоритетная находка',$r.'Event ID',$r.'Приоритет',$r.'Сценарий',$r.'Компьютер',$r.'Первое время UTC',$r.'Последнее время UTC',$r.'УЗ / объект / IP','','',$r.'Связанных уникальных событий','Кандидат',$r.'Папка источника',($r.'Основание связи'+' '+$r.'Почему выделено'+' '+$r.'Что проверить'+' '+$r.'Ссылки на находки и EVTX (до 10)'+' '+$r.'Ограничения'))
            }
        }
        $runPath=Join-Path $WorkPath 'Run.json'
        if (Test-Path -LiteralPath $runPath) {
            $run=Get-Content -LiteralPath $runPath -Raw -Encoding UTF8 | ConvertFrom-Json
            Write-Row $w @('Запуск','','','Итог',$null,$run.StartedUtc,$run.FinishedUtc,'','','',$run.Findings,(Ru-RunStatus $run.Status),$run.InputPath,('Обработано файлов: '+$run.FilesProcessed+'; с предупреждениями: '+$run.WarningFiles+'; Partial/Failed: '+$run.FailedOrPartialFiles+'; замечаний: '+$run.Issues))
        }
        $path=Join-Path $WorkPath 'Summary.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Сводка','',$row.'Приоритет',$row.'Категория',$row.'Компьютер','','','','','',$row.'Количество','','','')
            }
        }
        $path=Join-Path $WorkPath 'AuthBursts.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Подбор пароля',$row.'Event ID',$row.'Приоритет',$row.'Событие',$row.'Компьютер',$row.'Окно: начало UTC',$row.'Окно: конец UTC',$row.'Учетные записи',$row.'Источник','',$row.'Событий в окне','',$row.'Папка источника',($row.'Комментарий'+' Коды: '+$row.'Коды статуса'))
            }
        }
        $path=Join-Path $WorkPath 'RdpIntervals.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('RDP',($row.'Event ID начала'+' -> '+$row.'Event ID конца'),'Инфо','RDP-сеанс',$row.'Компьютер',$row.'Начало UTC',$row.'Окончание UTC',$row.'Учетная запись',$row.'IP источника',($row.'Record ID начала'+' -> '+$row.'Record ID конца'),$row.'Длительность, сек',$row.'Статус',$row.'Файл источника',$row.'Комментарий')
            }
        }
        $path=Join-Path $WorkPath 'Files.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Файл','','','Проверка обработки',$row.'Компьютеры',$row.'Время первой записи UTC',$row.'Время последней записи UTC','','','',$row.'Находок',$row.'Статус обработки',$row.'Полный путь',$row.'Комментарий')
            }
        }
        $path=Join-Path $WorkPath 'Coverage.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Качество выгрузки','','','Контроль полноты',$row.'Компьютеры','','','','','',$null,'Инфо',$row.'Папка источника',($row.'Что это означает / что запросить'))
            }
        }
        $path=Join-Path $WorkPath 'Errors.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Ошибка обработки','','Высокий',$row.'Этап','',$row.'Время UTC','','','',$row.'Record ID','',$row.'Этап',$row.'Файл источника',$row.'Ошибка')
            }
        }
    } finally { Close-Writer $w }
}

function Publish-FinalReports([string]$WorkPath,[string]$OutputRoot,[string]$BaseName) {
    $result=New-Object 'System.Collections.Generic.List[string]'
    $xlsx=Join-Path $OutputRoot ($BaseName+'.xlsx')
    if (-not $NoExcel) {
        try {
            Export-ReportsToExcel $WorkPath $xlsx
            $result.Add($xlsx)
            return @($result)
        } catch {
            if (Test-Path -LiteralPath $xlsx) { try { Remove-Item -LiteralPath $xlsx -Force } catch { } }
            Write-Warning ('Не удалось создать XLSX через установленный Excel: '+$_.Exception.Message+' Будут созданы 2 Excel-совместимых CSV.')
        }
    }
    $parts=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'Findings-*.csv' -File | Sort-Object Name)
    $findingsOut=Join-Path $OutputRoot ($BaseName+'_Findings.csv')
    if ($parts.Count -gt 0) { Combine-CsvParts $parts $findingsOut }
    else {
        $w=New-Writer $findingsOut; Write-Row $w $script:FindingHeaders; Close-Writer $w
    }
    $overviewOut=Join-Path $OutputRoot ($BaseName+'_Overview.csv')
    New-FallbackOverview $WorkPath $overviewOut
    $result.Add($findingsOut); $result.Add($overviewOut)
    return @($result)
}

# Priority layer v7: every P1/P2 row has an explicit evidence relationship.
function Triage-Value($r,[string]$Name) {
    $p=$r.PSObject.Properties[$Name]
    if ($null -eq $p) { return '' }
    return [string]$p.Value
}
function Triage-DataValue($r,[string[]]$Names) {
    $text=Triage-Value $r 'Данные события'
    if (-not $text) { return '' }
    foreach ($name in $Names) {
        $pattern='(?s)(?:^|\s\|\s)'+[regex]::Escape($name)+'=([^|]*)'
        $m=[regex]::Match($text,$pattern)
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
    }
    return ''
}
function Triage-Scope($r) {
    return ((Triage-Value $r 'Папка источника')+'|'+(Triage-Value $r 'Компьютер')).ToLowerInvariant()
}
function Triage-Key($r) {
    $hash=Triage-Value $r 'SHA256 XML события'
    if (-not $hash) { $hash=(Triage-Value $r 'Полный путь')+'|'+(Triage-Value $r 'Record ID')+'|'+(Triage-Value $r 'Время UTC') }
    return (Triage-Scope $r)+'|'+$hash
}
function Triage-IsServiceSid([string]$Sid) {
    return $Sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')
}
function Triage-ValidSid([string]$Sid) {
    return $Sid -match '^S-1-\d+(?:-\d+)+$' -and $Sid -ne 'S-1-0-0'
}
function Triage-LogonId($r,[string]$Name) {
    $value=(Triage-Value $r $Name).Trim().ToLowerInvariant()
    if ($value -match '^0x[0-9a-f]+$' -and $value -notmatch '^0x0+$') {
        try { return '0x'+([Convert]::ToUInt64($value.Substring(2),16)).ToString('x') } catch { return '' }
    }
    return ''
}
function Triage-NormalIp([string]$Ip) {
    if ($null -eq $Ip) { return '' }
    $value=$Ip.Trim().ToLowerInvariant()
    if ($value.StartsWith('::ffff:')) { $value=$value.Substring(7) }
    return $value
}
function Triage-IsRemoteIp([string]$Ip) {
    $value=Triage-NormalIp $Ip
    return $value -and $value -notin @('-','localhost','127.0.0.1','::1','0.0.0.0')
}
function Triage-TargetIdentity($r) {
    $account=(Triage-Value $r 'Целевая УЗ').Trim()
    if ($account -match '^[^\\]+\\[^\\]+$' -or $account -match '^[^@]+@[^@]+$') {
        return 'account:'+$account.ToLowerInvariant()
    }
    $sid=Triage-Value $r 'SID целевой УЗ'
    if (Triage-ValidSid $sid) { return 'sid:'+$sid.ToLowerInvariant() }
    return ''
}
function Is-PrivilegedGroup([string]$Sid) {
    return $Sid -match '^S-1-5-32-(544|548|549|550|551)$|^S-1-5-21-\d+-\d+-\d+-(512|518|519)$'
}
function Triage-ActorKey($r) {
    $sid=Triage-Value $r 'SID инициатора'
    $logon=Triage-LogonId $r 'Logon ID инициатора'
    if ((Triage-ValidSid $sid) -and -not (Triage-IsServiceSid $sid) -and $logon) { return $sid.ToLowerInvariant()+'|'+$logon }
    return ''
}
function Triage-Contains([string]$Text,[string]$Value) {
    if (-not $Text -or -not $Value) { return $false }
    return $Text.IndexOf($Value,[StringComparison]::OrdinalIgnoreCase) -ge 0
}
function Get-TriageErrorText($ErrorRecord) {
    # The priority layer must leave an actionable diagnostic, even when an
    # unusual CSV value or a future Windows event shape is encountered.
    $text=''
    try { $text=[string]($ErrorRecord.Exception.Message) } catch { $text=[string]$ErrorRecord }
    try {
        $line=[int]($ErrorRecord.InvocationInfo.ScriptLineNumber)
        if ($line -gt 0) { $text+=' | строка скрипта: '+$line }
    } catch { }
    try {
        $command=([string]($ErrorRecord.InvocationInfo.Line)).Trim()
        if ($command) {
            if ($command.Length -gt 300) { $command=$command.Substring(0,300)+' [обрезано]' }
            $text+=' | команда: '+$command
        }
    } catch { }
    return $text
}
function Get-ServiceRisk($r) {
    $path=Triage-DataValue $r @('ServiceFileName','ImagePath','BinaryPathName')
    $type=Triage-DataValue $r @('ServiceType')
    $start=Triage-DataValue $r @('ServiceStartType','StartType')
    $account=Triage-DataValue $r @('ServiceAccount','AccountName')
    $name=Triage-DataValue $r @('ServiceName')
    $flags=New-Object 'System.Collections.Generic.List[string]'
    if ($path) {
        $trimmed=$path.Trim().Trim('"')
        if ($trimmed -notmatch '(?i)^(%windir%|%systemroot%|[a-z]:\\windows|[a-z]:\\program files(?: \(x86\))?|\\systemroot)\\') { [void]$flags.Add('исполняемый файл вне Windows/Program Files') }
    }
    if ($type -match '(?i)^(0x)?(1|2|8)$') { [void]$flags.Add('тип драйвера ранней загрузки '+$type) }
    if ($start -match '(?i)^(0x)?(0|1)$') { [void]$flags.Add('тип запуска драйвера '+$start) }
    if ($start -match '(?i)^(0x)?4$') { [void]$flags.Add('служба установлена Disabled') }
    if ($account -and $account -notmatch '(?i)^(local.?system|nt authority\\system|local.?service|network.?service|nt authority\\local service|nt authority\\network service)$') { [void]$flags.Add('учетная запись запуска '+$account) }
    # Do not expose a one-element array as a property.  Under StrictMode in
    # Windows PowerShell 5.1 such a value can be treated as a scalar and
    # `Flags.Count` then throws.  A Boolean and pre-rendered text are stable.
    return [pscustomobject]@{HasRisk=[bool]($flags.Count -gt 0);Evidence=($flags.ToArray() -join '; ');Object=(($name+' | '+$path).Trim(' | '))}
}
function Get-TaskRisk($r) {
    $data=(Triage-Value $r 'Данные события')+' '+(Triage-Value $r 'Командная строка')
    $task=Triage-DataValue $r @('TaskName','TaskContent')
    $flags=New-Object 'System.Collections.Generic.List[string]'
    $encoded=$data -match '(?i)(-(enc|encodedcommand)\s|frombase64string|downloadstring|invoke-expression|\biex\s)'
    $tool=$data -match '(?i)\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)\b'
    $writable=$data -match '(?i)(\\users\\public\\|\\appdata\\(?:local|roaming)?\\|\\windows\\temp\\|\\temp\\|%temp%|%appdata%)'
    if ($encoded) { [void]$flags.Add('признак кодированной/загружающей команды') }
    elseif ($tool -and $writable) { [void]$flags.Add('интерпретатор/LOLBIN из доступного пользователю пути') }
    if ($task.Length -gt 512) { $task=$task.Substring(0,512)+' [обрезано]' }
    return [pscustomobject]@{HasRisk=[bool]($flags.Count -gt 0);Evidence=($flags.ToArray() -join '; ');Object=$task}
}
function Add-Triage {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][hashtable]$Groups,
        [Parameter(Mandatory=$true)][string]$Priority,
        [Parameter(Mandatory=$true)][string]$Scenario,
        [Parameter(Mandatory=$true)][string]$Evidence,
        [Parameter(Mandatory=$true)][string]$Why,
        [Parameter(Mandatory=$true)][string]$Check,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Object,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][object[]]$Rows
    )
    $firstRow=$Rows[0]
    foreach ($row in $Rows) {
        if ($null -eq $row -or -not (Triage-Value $row 'Event ID') -or -not (Triage-Value $row 'Время UTC')) {
            throw 'Add-Triage: отсутствуют обязательные поля доказательства (Event ID / Время UTC).'
        }
        if ((Triage-Scope $row) -ne (Triage-Scope $firstRow)) {
            throw 'Add-Triage: попытка связать разные компьютеры или папки.'
        }
    }
    $scope=Triage-Scope $firstRow
    $key=$Scenario+'|'+$scope+'|'+$Object
    if (-not $Groups.ContainsKey($key)) {
        $Groups[$key]=[pscustomobject]@{
            Priority=$Priority; Scenario=$Scenario; Evidence=$Evidence; Why=$Why; Check=$Check; Object=$Object
            Computer=(Triage-Value $firstRow 'Компьютер'); Scope=(Triage-Value $firstRow 'Папка источника')
            First=''; Last=''; Seen=(New-Object 'System.Collections.Generic.HashSet[string]')
            Ids=(New-Object 'System.Collections.Generic.HashSet[string]'); Refs=(New-Object 'System.Collections.Generic.List[string]')
            Recovered=$false
        }
    }
    $g=$Groups[$key]
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if (-not $g.Seen.Add((Triage-Key $r))) { continue }
        $time=Triage-Value $r 'Время UTC'
        if (-not $g.First -or [string]::CompareOrdinal($time,$g.First) -lt 0) { $g.First=$time }
        if (-not $g.Last -or [string]::CompareOrdinal($time,$g.Last) -gt 0) { $g.Last=$time }
        [void]$g.Ids.Add((Triage-Value $r 'Event ID'))
        if ($g.Refs.Count -lt 10) { [void]$g.Refs.Add(('Находка '+(Triage-Value $r 'Номер')+'; '+(Triage-Value $r 'Полный путь')+'; Record ID='+(Triage-Value $r 'Record ID'))) }
        if (Triage-Value $r 'Восстановление XML') { $g.Recovered=$true }
    }
}
function Add-SingleTriage($Groups,$r) {
    $id=[int](Triage-Value $r 'Event ID'); $provider=Triage-Value $r 'Провайдер'
    $security=$provider -eq 'Microsoft-Windows-Security-Auditing'
    if ($security -and (Triage-Value $r 'Результат аудита') -eq (Ru-AuditOutcome 'Failure')) { return }
    $target=Triage-Value $r 'Целевая УЗ'; $data=Triage-Value $r 'Данные события'
    if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(1102,104)) {
        Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Очистка журнала' -Evidence 'Факт: EventLog зафиксировал очистку.' -Why 'Очистка скрывает предшествующий контекст, но может быть штатной операцией.' -Check 'Установить инициатора, очищенный журнал, основание, соседние операции и полноту выгрузки.' -Object ((Triage-Value $r 'Инициатор')+' | '+$data) -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(1101,1104,1108)) {
        Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Потеря или переполнение журналирования' -Evidence 'Факт: EventLog сообщил о потере, заполнении или ошибке приема событий.' -Why 'Факт: EventLog сообщил о потере, заполнении или ошибке приема событий.' -Check 'Определить интервал неполноты, причину, размер журналов и наличие централизованной копии.' -Object ((Triage-Value $r 'Событие')+' | '+$data) -Rows @($r)
    }
    if ($security -and $id -in @(4728,4732,4756) -and (Is-PrivilegedGroup (Triage-Value $r 'SID целевой УЗ'))) {
        Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Добавление в привилегированную группу' -Evidence 'Факт: SID группы относится к известной административной группе.' -Why 'Факт: SID группы относится к известной административной группе.' -Check 'Проверить заявку, инициатора, SID участника и последующие действия этой УЗ.' -Object ((Triage-Value $r 'SID участника')+' -> '+(Triage-Value $r 'SID целевой УЗ')) -Rows @($r)
    }
    if ($security -and $id -in @(4904,4905,4906,4907,4739)) {
        Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Изменение механизма аудита или политики безопасности' -Evidence 'Факт: зарегистрировано изменение источника Security, CrashOnAuditFail, параметров аудита объекта или доменной политики.' -Why 'Факт: зарегистрировано изменение источника Security, CrashOnAuditFail, параметров аудита объекта или доменной политики.' -Check 'Проверить инициатора, точное старое/новое значение, заявку и последующие потери журналов.' -Object ((Triage-Value $r 'Инициатор')+' | '+$data) -Rows @($r)
    }
    if ($security -and $id -eq 4719) {
        Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Изменение политики аудита' -Evidence 'Факт: Windows сообщает об изменении политики аудита; сам по себе оно может быть плановым.' -Why 'Факт: Windows сообщает об изменении политики аудита; сам по себе оно может быть плановым.' -Check 'Проверить категорию/подкатегорию, Success/Failure, инициатора, Logon ID и основание изменения.' -Object ((Triage-Value $r 'Инициатор')+' | '+$data) -Rows @($r)
    }
    if ($security -and $id -eq 4946) {
        Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Локально добавлено правило Firewall' -Evidence 'Факт: это локальное добавление правила; событие 4946 не возникает при добавлении через GPO.' -Why 'Факт: это локальное добавление правила; событие 4946 не возникает при добавлении через GPO.' -Check 'Проверить имя правила, профиль, направление, адреса/порты и согласование.' -Object (Triage-DataValue $r @('RuleName','RuleId')) -Rows @($r)
    }
    if ((($security -and $id -eq 4697) -or ($provider -eq 'Service Control Manager' -and $id -eq 7045))) {
        $risk=Get-ServiceRisk $r
        if ($risk.HasRisk) {
            Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Служба с нетипичными параметрами' -Evidence ('Эвристика по полям службы: '+$risk.Evidence+'.') -Why ('Эвристика по полям службы: '+$risk.Evidence+'.') -Check 'Проверить путь, подпись, тип и запуск службы, учетную запись, владельца ПО и заявку.' -Object $risk.Object -Rows @($r)
        }
    }
    if ((($security -and $id -in @(4698,4702)) -or ($provider -eq 'Microsoft-Windows-TaskScheduler' -and $id -in @(106,140)))) {
        $risk=Get-TaskRisk $r
        if ($risk.HasRisk) {
            Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Задание с рискованной командой' -Evidence ('Эвристика по содержимому задания: '+$risk.Evidence+'.') -Why ('Эвристика по содержимому задания: '+$risk.Evidence+'.') -Check 'Открыть полное XML задания, проверить команду, триггер, учетную запись выполнения, путь и заявку.' -Object $risk.Object -Rows @($r)
        }
    }
    if ($security -and $id -in @(4704,4765)) {
        Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Изменение прав или SID History' -Evidence 'Факт: назначено право пользователя либо добавлен SID History.' -Why 'Факт: назначено право пользователя либо добавлен SID History.' -Check 'Проверить выданное право, целевую УЗ и основание изменения.' -Object ($target+' | '+(Triage-Value $r 'Привилегии')) -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Windows Defender' -and $id -in @(1006,1015,1116,1008,1118,1119,5001,5010,5012)) {
        $scenario='Обнаружение угрозы Defender'; $priority='P2 — проверить'
        if ($id -in @(1008,1118,1119)) { $scenario='Ошибка устранения угрозы Defender'; $priority='P1 — сначала' }
        if ($id -in @(5001,5010,5012)) { $scenario='Отключение компонентов защиты Defender' }
        Add-Triage -Groups $Groups -Priority $priority -Scenario $scenario -Evidence 'Факт: событие Defender требует сверки результата обработки и состояния защиты.' -Why 'Факт: событие Defender требует сверки результата обработки и состояния защиты.' -Check 'Сопоставить обнаружение с действием, проверить объект, исключения, состояние защиты и согласованные изменения.' -Object ((Triage-Value $r 'Имя угрозы')+' | '+(Triage-Value $r 'Ресурс / путь')) -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Sysmon' -and $id -eq 25) {
        Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Sysmon: вмешательство в процесс' -Evidence 'Факт: Sysmon сообщил о ProcessTampering; событие ориентировано на техники скрытия/изменения процесса.' -Why 'Факт: Sysmon сообщил о ProcessTampering; событие ориентировано на техники скрытия/изменения процесса.' -Check 'Проверить исходный и целевой процессы, подписи, хеши, родителя и контекст EDR.' -Object ((Triage-DataValue $r @('Image','SourceImage'))+' -> '+(Triage-DataValue $r @('TargetImage'))) -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Sysmon' -and $id -eq 16) {
        Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Изменение конфигурации Sysmon' -Evidence 'Факт: Sysmon сообщил об изменении собственной конфигурации.' -Why 'Факт: Sysmon сообщил об изменении собственной конфигурации.' -Check 'Сверить конфигурацию, инициатора и изменения фильтров с эталоном и заявкой.' -Object (Triage-DataValue $r @('Configuration','ConfigurationFileHash')) -Rows @($r)
    }
    if ((Triage-Value $r 'Правило') -eq 'AV-VENDOR-THREAT') {
        Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Сторонний антивирус: признаки угрозы' -Evidence 'Эвристика v3 нашла признаки угрозы в XML/описании; это не подтверждение заражения.' -Why 'Эвристика v3 нашла признаки угрозы в XML/описании; это не подтверждение заражения.' -Check 'Проверить точный смысл события продукта, объект и результат лечения в полном описании.' -Object ((Triage-Value $r 'Провайдер')+' | '+(Triage-Value $r 'Имя угрозы')+' | '+(Triage-Value $r 'Ресурс / путь')) -Rows @($r)
    }
    if ($security -and $id -eq 4616) {
        $delta=0.0; $sid=Triage-Value $r 'SID инициатора'
        if ($sid -and -not (Triage-IsServiceSid $sid) -and [double]::TryParse((Triage-Value $r 'Сдвиг времени, сек'),[Globalization.NumberStyles]::Float,$script:Invariant,[ref]$delta) -and [Math]::Abs($delta) -ge 300) {
            Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Значительное изменение времени пользователем' -Evidence 'Факт: сдвиг не менее 5 минут; инициатор не служебная УЗ.' -Why 'Факт: сдвиг не менее 5 минут; инициатор не служебная УЗ.' -Check 'Проверить старое и новое время, процесс и согласованную корректировку часов.' -Object (Triage-Value $r 'Инициатор') -Rows @($r)
        }
    }
    if ((Triage-Value $r 'Правило') -eq 'HEURISTIC-COMMAND') {
        $command=(Triage-Value $r 'Командная строка')+' '+$data
        if ($command -match '(?i)(wevtutil\s+(cl|clear-log)\b|Clear-EventLog\b|vssadmin\s+delete\s+shadows|Set-MpPreference\b.{0,120}-Disable\w+\s+\$true|Add-MpPreference\b.{0,120}-Exclusion)' -or ($command -match '(?i)DownloadString' -and $command -match '(?i)\b(IEX|Invoke-Expression)\b')) {
            Add-Triage -Groups $Groups -Priority 'P2 — проверить' -Scenario 'Потенциально опасная команда' -Evidence 'Эвристика: признаки удаления следов, ослабления защиты либо загрузки и исполнения кода. Текст мог быть цитатой.' -Why 'Эвристика: признаки удаления следов, ослабления защиты либо загрузки и исполнения кода. Текст мог быть цитатой.' -Check 'Прочитать команду и полный ScriptBlock в EVTX; установить родительский процесс, автора и результат исполнения.' -Object ((Triage-Value $r 'Инициатор')+' | '+(Triage-Value $r 'Процесс')) -Rows @($r)
        }
    }
}
function Add-PasswordSuccessTriage($Groups,[object[]]$Rows) {
    $queues=@{}; $windowTicks=[long]$WindowMinutes*[TimeSpan]::TicksPerMinute
    # Core supplies chronologically sorted, scope-isolated, deduplicated rows.
    foreach ($r in $Rows) {
        $id=[int]$r.'Event ID'; $provider=$r.'Провайдер'; $time=[DateTimeOffset]::Parse($r.'Время UTC',$script:Invariant)
        if (($provider -eq 'Microsoft-Windows-Security-Auditing' -and $id -in @(4608,4616)) -or ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1102))) { $queues.Clear(); continue }
        if ($provider -ne 'Microsoft-Windows-Security-Auditing') { continue }
        $identity=Triage-TargetIdentity $r; $ip=Triage-NormalIp $r.'IP источника'
        if (-not $identity -or -not (Triage-IsRemoteIp $ip) -or $r.'Тип входа' -ne '10') { continue }
        $key=$identity+'|'+$ip
        if ($id -eq 4625) {
            $bad=($r.'SubStatus' -match '(?i)^(0x)?c000006a$') -or ($r.'Status' -match '(?i)^(0x)?c000006a$')
            if (-not $bad) { continue }
            if (-not $queues.ContainsKey($key)) { $queues[$key]=New-Object 'System.Collections.Generic.Queue[object]' }
            $q=$queues[$key]
            while ($q.Count -gt 0 -and ([DateTimeOffset]::Parse($q.Peek().'Время UTC',$script:Invariant).UtcDateTime.Ticks -lt ($time.UtcDateTime.Ticks-$windowTicks))) { [void]$q.Dequeue() }
            $q.Enqueue($r)
            continue
        }
        if ($id -eq 4624 -and $r.'Результат аудита' -eq (Ru-AuditOutcome 'Success') -and $queues.ContainsKey($key)) {
            $q=$queues[$key]
            while ($q.Count -gt 0 -and ([DateTimeOffset]::Parse($q.Peek().'Время UTC',$script:Invariant).UtcDateTime.Ticks -lt ($time.UtcDateTime.Ticks-$windowTicks))) { [void]$q.Dequeue() }
            if ($q.Count -ge $FailureThreshold) {
                $successSid=Triage-Value $r 'SID целевой УЗ'
                $items=@($q.ToArray() | Where-Object {
                    $failureSid=Triage-Value $_ 'SID целевой УЗ'
                    -not ((Triage-ValidSid $failureSid) -and (Triage-ValidSid $successSid)) -or $failureSid -eq $successSid
                })
                if ($items.Count -lt $FailureThreshold) { continue }
                $last=$items[$items.Count-1]
                $wait=($time-[DateTimeOffset]::Parse($last.'Время UTC',$script:Invariant)).TotalMinutes
                if ($wait -ge 0 -and $wait -le $TriageWindowMinutes) {
                    Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Отказы RDP с неверным паролем → успешный вход' -Evidence ('Связь: '+$items.Count+' уникальных отказов 4625 (неверный пароль), затем 4624 типа 10. Совпали IP и полное имя УЗ либо SID; при двух известных SID они проверены. Это кандидат, не доказанный подбор.') -Why ('Связь: '+$items.Count+' уникальных отказов 4625 (неверный пароль), затем 4624 типа 10. Совпали IP и полное имя УЗ либо SID; при двух известных SID они проверены. Это кандидат, не доказанный подбор.') -Check 'Проверить владельца IP, назначение УЗ, журнал RDP, смену пароля, блокировки и последующие действия в сеансе.' -Object ($identity+' | '+$ip+' | '+$last.'Record ID') -Rows ($items + @($r))
                }
            }
            $queues.Remove($key)
        }
    }
}
function Add-ChainTriage($Groups,[object[]]$Rows) {
    $parts=@{}; $unique=New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($row in $Rows) {
        if (-not (Triage-Value $row 'Компьютер')) { continue }
        $scope=Triage-Scope $row
        if (-not $parts.ContainsKey($scope)) { $parts[$scope]=New-Object 'System.Collections.Generic.List[object]' }
        if ($unique.Add((Triage-Key $row))) { [void]$parts[$scope].Add($row) }
    }
    foreach ($part in $parts.GetEnumerator()) {
        Add-ChainTriageCore $Groups $part.Value.ToArray()
    }
}
function Add-ChainTriageCore($Groups,[object[]]$Rows) {
    $created=@{}; $opened=@{}; $rdp=@{}; $audit=@{}
    $orderedRows=@($Rows | Sort-Object @{Expression={[DateTimeOffset]::Parse($_.'Время UTC',$script:Invariant).UtcDateTime.Ticks}},@{Expression={$_.'Полный путь'}},@{Expression={[long]$_.'Record ID'}})
    Add-PasswordSuccessTriage $Groups $orderedRows
    foreach ($r in $orderedRows) {
        $id=[int]$r.'Event ID'; $provider=$r.'Провайдер'; $time=[DateTimeOffset]::Parse($r.'Время UTC',$script:Invariant)
        if ($provider -eq 'Microsoft-Windows-Security-Auditing' -and $id -in @(4608,4616)) { $created.Clear(); $opened.Clear(); $rdp.Clear(); $audit.Clear(); continue }
        # WMI correlation remains disabled as previously agreed. Raw Sysmon
        # 19/20/21 findings are retained for manual review.
        if ($provider -eq 'Microsoft-Windows-Sysmon') { continue }
        if ($provider -eq 'Microsoft-Windows-Security-Auditing' -and $r.'Результат аудита' -ne (Ru-AuditOutcome 'Success')) { continue }
        if ($provider -eq 'Microsoft-Windows-Security-Auditing') {
            if ($id -eq 4720 -and (Triage-ValidSid $r.'SID целевой УЗ')) { $created[$r.'SID целевой УЗ']=$r }
            if ($id -in @(4722,4724) -and (Triage-ValidSid $r.'SID целевой УЗ')) { $opened[$r.'SID целевой УЗ']=$r }
            if ($id -in @(4728,4732,4756) -and (Is-PrivilegedGroup $r.'SID целевой УЗ') -and $r.'SID участника' -and $created.ContainsKey($r.'SID участника')) {
                $start=$created[$r.'SID участника']; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -gt 0 -and $delta -le $TriageWindowMinutes) {
                    Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Новая УЗ получила привилегии' -Evidence ('Строго: SID созданной УЗ совпал с SID участника группы; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: SID созданной УЗ совпал с SID участника группы; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить, согласованы ли создание и выдача прав. Это цепочка действий, не доказательство атаки.' -Object ($r.'SID участника'+' | '+$start.'Record ID') -Rows @($start,$r)
                }
            }
            if ($id -eq 4634) {
                $ended=Triage-LogonId $r 'Logon ID цели'
                if ($ended) { $rdp.Remove($ended) }
                continue
            }
            $logon=Triage-LogonId $r 'Logon ID цели'
            if ($id -eq 4624 -and $r.'Тип входа' -eq '10' -and $logon) {
                $rdp[$logon]=$r
                if ((Triage-ValidSid $r.'SID целевой УЗ') -and $opened.ContainsKey($r.'SID целевой УЗ')) {
                    $start=$opened[$r.'SID целевой УЗ']; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                    if ($delta -ge 0 -and $delta -le $TriageWindowMinutes) {
                        Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Включение/сброс УЗ → RDP-вход' -Evidence ('Строго: SID УЗ совпал; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: SID УЗ совпал; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить законность включения/сброса, владельца УЗ, источник RDP и последующие действия.' -Object ($r.'SID целевой УЗ'+' | '+$start.'Record ID') -Rows @($start,$r)
                    }
                }
            }
            $impact=@{4697='создание службы';4698='создание задания';4702='изменение задания';4719='изменение политики аудита';4904='регистрация источника Security';4905='отмена источника Security';4906='изменение CrashOnAuditFail';4907='изменение параметров аудита объекта';4739='изменение доменной политики';4946='добавление правила Firewall';4947='изменение правила Firewall';4948='удаление правила Firewall';4950='изменение параметра Firewall';4954='изменение Firewall через GPO';4720='создание УЗ';4722='включение УЗ';4723='изменение пароля';4724='сброс пароля';4728='добавление в глобальную группу';4732='добавление в локальную группу';4756='добавление в универсальную группу';4704='назначение права';4765='добавление SID History';4616='изменение времени'}
            $actorLogon=Triage-LogonId $r 'Logon ID инициатора'
            if ($impact.ContainsKey($id) -and $actorLogon -and $rdp.ContainsKey($actorLogon)) {
                $start=$rdp[$actorLogon]; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -gt 0 -and $delta -le $TriageWindowMinutes -and (Triage-ValidSid $start.'SID целевой УЗ') -and $start.'SID целевой УЗ' -eq $r.'SID инициатора') {
                    Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario ('RDP-сеанс: '+$impact[$id]) -Evidence ('Строго: успешный RDP типа 10 связан с действием по одному Logon ID и SID; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: успешный RDP типа 10 связан с действием по одному Logon ID и SID; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить источник RDP, владельца УЗ, объект изменения, заявку и полную временную линию сеанса.' -Object ($actorLogon+' | '+$id) -Rows @($start,$r)
                }
            }
            if ($id -in @(4719,4904,4905,4906,4907,4739)) {
                $actor=Triage-ActorKey $r
                if ($actor) { $audit[$actor]=$r }
            }
        }
        if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1101,1102,1104,1108)) {
            $actor=Triage-ActorKey $r
            if ($actor -and $audit.ContainsKey($actor)) {
                $start=$audit[$actor]; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -ge 0 -and $delta -le $TriageWindowMinutes) {
                    Add-Triage -Groups $Groups -Priority 'P1 — сначала' -Scenario 'Изменение аудита → потеря/очистка журналирования' -Evidence ('Строго: одинаковые SID и Logon ID; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: одинаковые SID и Logon ID; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить точные параметры аудита, очищенный/переполненный журнал, инициатора, причину и внешнюю копию логов.' -Object ($actor+' | '+$start.'Record ID') -Rows @($start,$r)
                }
            }
        }
        if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1102)) { $created.Clear(); $opened.Clear(); $rdp.Clear(); $audit.Clear() }
    }
}
function Test-TriageCandidate($r) {
    $id=[int]$r.'Event ID'; $provider=$r.'Провайдер'
    if ($provider -eq 'Microsoft-Windows-Security-Auditing' -and $id -in @(4608,4616,4624,4625,4634,4697,4698,4702,4704,4719,4720,4722,4723,4724,4728,4732,4739,4756,4765,4904,4905,4906,4907,4946,4947,4948,4950,4954)) { return $true }
    if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1101,1102,1104,1108)) { return $true }
    return $false
}
function Build-LogCoverage([string]$WorkPath) {
    $groups=@{}
    foreach ($row in (Import-Csv -LiteralPath (Join-Path $WorkPath 'Files.csv') -Delimiter $Delimiter -Encoding UTF8)) {
        $path=$row.'Полный путь'; if (-not $path) { continue }
        $folder=[IO.Path]::GetDirectoryName($path)
        if (-not $groups.ContainsKey($folder)) {
            $groups[$folder]=[pscustomobject]@{Files=(New-Object 'System.Collections.Generic.List[object]');Computers=(New-Object 'System.Collections.Generic.HashSet[string]');Bad=(New-Object 'System.Collections.Generic.List[string]')}
        }
        $g=$groups[$folder]; $g.Files.Add($row)
        foreach ($computer in (($row.'Компьютеры' -split ' \| ') | Where-Object { $_ })) { [void]$g.Computers.Add($computer) }
        if ($row.'Статус обработки' -in @('Частично','Ошибка')) { $g.Bad.Add(([IO.Path]::GetFileName($path)+' — '+$row.'Статус обработки')) }
    }
    $w=New-Writer (Join-Path $WorkPath 'Coverage.csv')
    try {
        Write-Row $w @('Папка источника','Компьютеры','Security','System','PowerShell Operational','Defender Operational','RDP Operational','Sysmon Operational','Файлы с неполной обработкой','Что это означает / что запросить')
        foreach ($folder in ($groups.Keys | Sort-Object)) {
            $g=$groups[$folder]; $names=@($g.Files | ForEach-Object { [IO.Path]::GetFileName($_.'Полный путь').ToLowerInvariant() })
            $check={ param([string]$Pattern) if (@($names | Where-Object { $_ -like $Pattern }).Count -gt 0) {'Передан'} else {'Не передан'} }
            $security=& $check 'security.evtx'; $system=& $check 'system.evtx'
            $ps=& $check 'microsoft-windows-powershell%4operational.evtx'; $defender=& $check 'microsoft-windows-windows defender%4operational.evtx'
            $rdp=if ((& $check 'microsoft-windows-terminalservices-localSessionmanager%4operational.evtx') -eq 'Передан' -or (& $check 'microsoft-windows-terminalservices-remoteconnectionmanager%4operational.evtx') -eq 'Передан') {'Передан хотя бы один'} else {'Не передан'}
            $sysmon=& $check 'microsoft-windows-sysmon%4operational.evtx'
            $note='Это полнота переданной выгрузки, а не доказательство включения/выключения аудита. Запросить auditpol /get /category:* /r, размеры/retention журналов и сведения о централизованном сборе.'
            if ($security -eq 'Не передан') { $note+=' Security.evtx отсутствует в этой папке: выводы об аутентификации и УЗ ограничены.' }
            if ($system -eq 'Не передан') { $note+=' System.evtx отсутствует: ограничены выводы о времени, службах и сбоях.' }
            if ($g.Bad.Count -gt 0) { $note+=' Есть неполная обработка: '+($g.Bad -join '; ')+'.' }
            Write-Row $w @($folder,(@($g.Computers) -join ' | '),$security,$system,$ps,$defender,$rdp,$sysmon,($g.Bad -join ' | '),$note)
        }
    } finally { Close-Writer $w }
}
function Write-TriageReport([string]$WorkPath,$Groups,[int]$ScopeCount,[int]$BlockedCount,[int]$RowFailures,[int]$ChainFailures,[string]$BuildNote) {
    # Writing the report is isolated from correlation.  Thus a malformed
    # individual record can never remove the entire "Приоритетные" sheet.
    $w=New-Writer (Join-Path $WorkPath 'Triage.csv')
    try {
        Write-Row $w @('Приоритет','Event ID','Сценарий','Основание связи','Почему выделено','Что проверить','Компьютер','УЗ / объект / IP','Первое время UTC','Последнее время UTC','Связанных уникальных событий','Ссылки на находки и EVTX (до 10)','Папка источника','Ограничения')
        foreach ($g in (@($Groups.Values) | Sort-Object -Property @('Priority','Scenario','Computer','First'))) {
            $note='Кандидат для проверки, не подтвержденный инцидент. Повторы объединены; диапазон времени не является длительностью атаки.'
            if ($g.Recovered) { $note+=' Есть восстановленный XML: перепроверить исходную запись.' }
            $ids=@($g.Ids | Sort-Object {[int]$_}) -join ', '
            Write-Row $w @($g.Priority,$ids,$g.Scenario,$g.Evidence,$g.Why,$g.Check,$g.Computer,$g.Object,$g.First,$g.Last,[int]($g.Seen.Count),($g.Refs.ToArray() -join ' || '),$g.Scope,$note)
        }
        $limits=New-Object 'System.Collections.Generic.List[string]'
        if ($RowFailures -gt 0) { [void]$limits.Add('Строк с ошибкой приоритизации: '+$RowFailures+'. Они перечислены на листе Ошибки (этап «Приоритизация: строка»).') }
        if ($ChainFailures -gt 0) { [void]$limits.Add('Областей со сбойной связкой: '+$ChainFailures+'. Остальные области обработаны.') }
        if ($BuildNote) { [void]$limits.Add($BuildNote) }
        if ($limits.Count -gt 0) {
            Write-Row $w @('Справка','','Приоритизация выполнена с ограничениями',($limits.ToArray() -join ' '),'Это не отменяет уже сформированные P1/P2; проверить лист Ошибки и исходный EVTX.','После устранения причины повторить запуск на неизменяемой копии.','','','','','','','',$null)
        }
        Write-Row $w @('Справка','','Границы анализа','Связки не строятся через ошибки чтения, восстановленный XML, изменение времени/загрузку ОС и между разными папками либо компьютерами.','Обычные 4672, одиночные отказы входа и системные ошибки автоматически сюда не включаются.','Также просмотреть листы Подбор_пароля, Качество_выгрузки, Файлы и Ошибки.','','','','','','','',('Областей с кандидатами цепочек: '+$ScopeCount+'; областей с запретом цепочек: '+$BlockedCount+'. Окно цепочек: '+$TriageWindowMinutes+' мин.; окно отказов: '+$WindowMinutes+' мин.'))
    } finally { Close-Writer $w }
}
function Write-TriageFallback([string]$WorkPath,[string]$Reason) {
    $emptyGroups=@{}
    Write-TriageReport $WorkPath $emptyGroups 0 0 0 0 ('Не удалось полностью сформировать приоритеты: '+$Reason)
}
$script:TriageColumns=@('Номер','Event ID','Record ID','Время UTC','Папка источника','Полный путь','Компьютер','Провайдер','Результат аудита','SID целевой УЗ','SID участника','SID инициатора','Logon ID цели','Logon ID инициатора','Тип входа','Целевая УЗ','IP источника','Status','SubStatus','Данные события','Командная строка','Процесс','SHA256 XML события','Восстановление XML')
function Build-Triage([string]$WorkPath) {
    $script:TriageIncomplete=$false
    $script:TriageHasErrors=$false
    $groups=@{}; $scopes=@{}; $blocked=@{}; $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    $sourceScopes=@{}; $candidateCount=0; $limit=100000; $limitWarned=$false; $rowFailures=0; $chainFailures=0; $buildNote=''
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $WorkPath -Filter 'Findings-*.csv' -File | Sort-Object Name)) {
            Import-Csv -LiteralPath $file.FullName -Delimiter $Delimiter -Encoding UTF8 | ForEach-Object {
                $r=$_
                try {
                    Add-SingleTriage $groups $r
                    if (Test-TriageCandidate $r) {
                        $scope=Triage-Scope $r
                        $sourcePath=Triage-Value $r 'Полный путь'
                        if (-not $sourceScopes.ContainsKey($sourcePath)) { $sourceScopes[$sourcePath]=@{} }
                        $sourceScopes[$sourcePath][$scope]=$true
                        if ($r.'Восстановление XML' -or -not $r.'Компьютер') {
                            $blocked[$scope]=$true
                        } elseif ($seen.Add((Triage-Key $r))) {
                            if ($candidateCount -ge $limit) {
                                $blocked[$scope]=$true
                                if (-not $limitWarned) { Log-Issue 'Triage' $WorkPath '' 'Достигнут общий лимит 100000 уникальных кандидатов. Области с пропущенными кандидатами исключены из цепочек. Повторите анализ отдельных папок компьютеров; базовые отчеты и отдельные приоритеты сохранены.'; $limitWarned=$true }
                            } else {
                                if (-not $scopes.ContainsKey($scope)) { $scopes[$scope]=New-Object 'System.Collections.Generic.List[object]' }
                                # v9: direct projection instead of one Select-Object pipeline per row.
                                $projection=[ordered]@{}
                                foreach ($column in $script:TriageColumns) { $property=$r.PSObject.Properties[$column]; if ($property) { $projection[$column]=$property.Value } else { $projection[$column]=$null } }
                                [void]$scopes[$scope].Add([pscustomobject]$projection)
                                $candidateCount++
                            }
                        }
                    }
                } catch {
                    $rowFailures++; $script:TriageIncomplete=$true; $script:TriageHasErrors=$true
                    Log-Issue 'TriageRow' (Triage-Value $r 'Полный путь') (Triage-Value $r 'Record ID') (Get-TriageErrorText $_)
                }
            }
        }
    } catch {
        $script:TriageIncomplete=$true; $script:TriageHasErrors=$true; $buildNote=Get-TriageErrorText $_
        Log-Issue 'Triage' $WorkPath '' $buildNote
    }
    try {
        $script:ErrorWriter.Flush()
        $errorsPath=Join-Path $WorkPath 'Errors.csv'
        if (Test-Path -LiteralPath $errorsPath) {
            foreach ($issue in (Import-Csv -LiteralPath $errorsPath -Delimiter $Delimiter -Encoding UTF8)) {
                $source=$issue.'Файл источника'
                $blockingStages=@('ReadEvent','OpenQuery','ParseOrRule','InputChanged','ClockOrder','TriageRow') | ForEach-Object { Ru-Stage $_ }
                if ($source -and $sourceScopes.ContainsKey($source) -and $issue.'Этап' -in $blockingStages) {
                    foreach ($scope in $sourceScopes[$source].Keys) { $blocked[$scope]=$true }
                }
            }
        }
    } catch {
        $script:TriageIncomplete=$true; $script:TriageHasErrors=$true
        $errorText=Get-TriageErrorText $_
        if ($buildNote) { $buildNote+=' | ' }
        $buildNote+='Не удалось учесть ошибки исходных данных: '+$errorText
        Log-Issue 'Triage' $WorkPath '' $errorText
    }
    foreach ($scope in @($scopes.Keys)) {
        if ($blocked.ContainsKey($scope)) { continue }
        $scopeRows=$scopes[$scope].ToArray()
        try { Add-ChainTriage $groups $scopeRows }
        catch {
            $chainFailures++; $blocked[$scope]=$true; $script:TriageIncomplete=$true; $script:TriageHasErrors=$true
            $source=$WorkPath; if ($scopeRows.Count -gt 0) { $source=Triage-Value $scopeRows[0] 'Полный путь' }
            Log-Issue 'TriageChain' $source '' (Get-TriageErrorText $_)
        }
    }
    if ($blocked.Count -gt 0) {
        $script:TriageIncomplete=$true
        Log-Issue 'Triage' $WorkPath '' ('Новые цепочки ограничены: исключено областей '+$blocked.Count+'. Причины: ошибки исходных данных, восстановленные кандидаты, отсутствие имени компьютера либо лимит. Отдельные приоритеты сохранены.')
    }
    Write-TriageReport $WorkPath $groups $scopes.Count $blocked.Count $rowFailures $chainFailures $buildNote
}

function Test-V4 {
    $payload='<EventData><Data Name="Value">A'+[char]16+'B</Data></EventData>'
    $raw=Test-Xml 1000 'Application Error' $payload
    $e=Parse-Event $raw
    Assert-True ($e.Data['Value'] -eq 'A[U+0010]B' -and $e.Xml -ceq $raw -and $e.XmlRecovery) 'v4 literal invalid XML character; original preserved'
    $e=Parse-Event (Test-Xml 1000 'Application Error' '<EventData><Data Name="Value">&#x10;&#16;&amp;</Data></EventData>')
    Assert-True ($e.Data['Value'] -eq '[U+0010][U+0010]&') 'v4 invalid numeric XML references'
    $ok=Test-Xml 1000 'Application Error' '<EventData><Data Name="Value">ok</Data></EventData>'
    $e=Parse-Event $ok
    Assert-True (-not $e.XmlRecovery -and $e.Xml -ceq $ok) 'v4 valid XML unchanged'
    $rejected=$false
    try { $null=Parse-Event ('<!DOCTYPE Event [<!ENTITY x "bad">]>'+$ok) } catch { $rejected=$true }
    Assert-True $rejected 'v4 DTD still prohibited'
    $rejected=$false
    try { $null=Parse-Event ($ok.Replace('</EventData>','')) } catch { $rejected=$true }
    Assert-True $rejected 'v4 malformed XML is not silently repaired'
    Assert-True ((Is-PrivilegedGroup 'S-1-5-32-544') -and -not (Is-PrivilegedGroup 'S-1-5-32-545')) 'v4 privileged group SID'
    # Each fixture has its own object so later mutations do not alter another.
    $a=New-V7TestRow 4720 'Microsoft-Windows-Security-Auditing' '2026-01-01T10:00:00.0000000Z' '1' @{
        'SID целевой УЗ'='S-1-5-21-1-2-3-1001';'Целевая УЗ'='LAB\alice';'SHA256 XML события'='account-created'
    }
    $b=New-V7TestRow 4732 'Microsoft-Windows-Security-Auditing' '2026-01-01T10:01:00.0000000Z' '2' @{
        'SID участника'='S-1-5-21-1-2-3-1001';'SID целевой УЗ'='S-1-5-32-544';'SHA256 XML события'='admin-membership'
    }
    $groups=@{}; Add-ChainTriage $groups @($a,$b,$b)
    Assert-True ($groups.Count -eq 1) 'v7 account-to-admin chain'
    $seenCount=0
    foreach ($entry in $groups.GetEnumerator()) { $seenCount=[int]($entry.Value.Seen.Count) }
    Assert-True ($seenCount -eq 2) 'v7 account-to-admin evidence deduplication'
    $b.'SID участника'='S-1-5-21-9-9-9-999'
    $groups=@{}; Add-ChainTriage $groups @($a,$b)
    Assert-True ($groups.Count -eq 0) 'v4 different SID does not correlate'
    $groups=@{}; $a.'Event ID'='4672'; Add-SingleTriage $groups $a
    Assert-True ($groups.Count -eq 0) 'v4 privilege logon alone is not a priority'
    $a.'Event ID'='4624'; $a.'Тип входа'='10'; $a.'Logon ID цели'='0xabc'; $a.'IP источника'='192.0.2.10'
    $b.'Event ID'='4698'; $b.'SID инициатора'=$a.'SID целевой УЗ'; $b.'Logon ID инициатора'='0xabc'
    $groups=@{}; Add-ChainTriage $groups @($a,$b)
    Assert-True ($groups.Count -eq 1) 'v4 RDP to task uses logon ID and SID'
    $b.'Logon ID инициатора'='0xdef'
    $groups=@{}; Add-ChainTriage $groups @($a,$b)
    Assert-True ($groups.Count -eq 0) 'v4 different logon ID does not correlate'
    $b.'Logon ID инициатора'='0xabc'; $b.'Время UTC'='2026-01-03T10:01:00.0000000Z'
    $groups=@{}; Add-ChainTriage $groups @($a,$b)
    Assert-True ($groups.Count -eq 0) 'v4 time window enforced'
    $b.'Время UTC'='2026-01-01T10:01:00.0000000Z'
    $barrier=New-V7TestRow 4616 'Microsoft-Windows-Security-Auditing' '2026-01-01T10:00:30.0000000Z' '3' @{}
    $groups=@{}; Add-ChainTriage $groups @($a,$barrier,$b)
    Assert-True ($groups.Count -eq 0) 'v4 clock change breaks new chain'
    $other=New-V7TestRow 4720 'Microsoft-Windows-Security-Auditing' '2026-01-01T10:00:00.0000000Z' '4' @{'Папка источника'='C:\other'}
    Assert-True ((Triage-Scope $a) -ne (Triage-Scope $other)) 'v4 source folders are separate scopes'
    Write-Host 'V4 SelfTest OK'
}

function New-V7TestRow([int]$Id,[string]$Provider,[string]$Time,[string]$Record,[hashtable]$Values) {
    $row=[ordered]@{
        'Номер'=$Record;'Event ID'=[string]$Id;'Record ID'=$Record;'Время UTC'=$Time;'Папка источника'='C:\test';'Полный путь'='C:\test\Security.evtx';'Компьютер'='PC01';'Провайдер'=$Provider;'Результат аудита'='Успех';'SID целевой УЗ'='S-1-5-21-1-2-3-1001';'SID участника'='';'SID инициатора'='';'Logon ID цели'='';'Logon ID инициатора'='';'Тип входа'='';'Целевая УЗ'='LAB\alice';'IP источника'='';'Status'='';'SubStatus'='';'Данные события'='';'Командная строка'='';'Процесс'='';'SHA256 XML события'=('test-'+$Record);'Восстановление XML'='';'Приоритет'='';'Событие'='';'Что проверить'='';'Инициатор'='';'Привилегии'='';'Имя угрозы'='';'Ресурс / путь'='';'Сдвиг времени, сек'=''
    }
    foreach ($key in $Values.Keys) { $row[$key]=$Values[$key] }
    return [pscustomobject]$row
}
function Test-V7 {
    $csvSingle="Номер;Event ID;Record ID;Время UTC;Папка источника;Полный путь;Компьютер;SHA256 XML события;Восстановление XML`r`n1;1102;1;2026-01-01T09:00:00.0000000Z;C:\test;C:\test\Security.evtx;PC01;csv-one;"
    $importedSingle=$csvSingle | ConvertFrom-Csv -Delimiter ';'
    $groups=@{}
    Add-Triage -Groups $groups -Priority 'P1 — сначала' -Scenario 'Проверка одиночной CSV-строки' -Evidence 'SelfTest' -Why 'SelfTest' -Check 'SelfTest' -Object 'SelfTest' -Rows $importedSingle
    Assert-True ($groups.Count -eq 1) 'v7 imported scalar CSV row does not use a synthetic Count property'
    $service=New-V7TestRow 4697 'Microsoft-Windows-Security-Auditing' '2026-01-01T10:00:00.0000000Z' '1' @{'Данные события'='ServiceName=BadSvc | ServiceFileName=C:\Users\Public\bad.exe | ServiceType=0x10 | ServiceStartType=2 | ServiceAccount=LAB\svc'}
    $risk=Get-ServiceRisk $service
    Assert-True ($risk.HasRisk -and $risk.Evidence -match 'исполняемый файл вне' -and $risk.Evidence -match 'учетная запись запуска') 'v7 service risk fields'
    # Test-V8 also exercises real callers and the CSV reporting path.
    $rows=New-Object 'System.Collections.Generic.List[object]'
    for ($i=0;$i -lt $FailureThreshold;$i++) {
        $time=([DateTimeOffset]::Parse('2026-01-01T11:00:00Z')).AddSeconds($i).ToString('o')
        $rows.Add((New-V7TestRow 4625 'Microsoft-Windows-Security-Auditing' $time (20+$i) @{'Результат аудита'='Отказ';'Тип входа'='10';'IP источника'='192.0.2.5';'SubStatus'='0xc000006a'}))
    }
    $success=New-V7TestRow 4624 'Microsoft-Windows-Security-Auditing' '2026-01-01T11:01:00.0000000Z' '40' @{'Тип входа'='10';'IP источника'='192.0.2.5';'Logon ID цели'='0xabc'}
    $rows.Add($success); $groups=@{}; Add-ChainTriage $groups $rows.ToArray()
    Assert-True ($groups.Count -eq 1) 'v7 failed RDP passwords then success'
    $success.'IP источника'='192.0.2.6'; $groups=@{}; Add-ChainTriage $groups $rows.ToArray()
    Assert-True ($groups.Count -eq 0) 'v7 password-success requires same source IP'
    $rdp=New-V7TestRow 4624 'Microsoft-Windows-Security-Auditing' '2026-01-01T12:00:00.0000000Z' '50' @{'Тип входа'='10';'IP источника'='192.0.2.7';'Logon ID цели'='0x111'}
    $audit=New-V7TestRow 4719 'Microsoft-Windows-Security-Auditing' '2026-01-01T12:01:00.0000000Z' '51' @{'SID инициатора'='S-1-5-21-1-2-3-1001';'Logon ID инициатора'='0x111';'Данные события'='CategoryId=1'}
    $groups=@{}; Add-ChainTriage $groups @($rdp,$audit)
    Assert-True ($groups.Count -eq 1) 'v7 RDP to audit change requires SID and Logon ID'
    $loss=New-V7TestRow 1102 'Microsoft-Windows-Eventlog' '2026-01-01T12:02:00.0000000Z' '52' @{'SID инициатора'='S-1-5-21-1-2-3-1001';'Logon ID инициатора'='0x111'}
    $groups=@{}; Add-ChainTriage $groups @($audit,$loss)
    Assert-True ($groups.Count -eq 1) 'v7 audit change to telemetry loss exact actor'
    $loss.'Logon ID инициатора'='0x222'; $groups=@{}; Add-ChainTriage $groups @($audit,$loss)
    Assert-True ($groups.Count -eq 0) 'v7 audit chain requires same Logon ID'
    Write-Host 'V7/V7.1 regression tests OK'
}

function Assert-TriageGroup($Groups,[string]$Scenario,[string[]]$ExpectedIds,[int]$ExpectedCount) {
    $matches=@($Groups.Values | Where-Object { $_.Scenario -eq $Scenario })
    Assert-True ($matches.Count -eq 1) ($Scenario+': one group')
    $g=$matches[0]
    Assert-True ($g.Seen.Count -eq $ExpectedCount) ($Scenario+': unique evidence count')
    Assert-True ((@($g.Ids | Sort-Object) -join ',') -eq (@($ExpectedIds | Sort-Object) -join ',')) ($Scenario+': exact Event IDs')
    Assert-True ($g.Check -and $g.Why -and $g.Evidence -and $g.Refs.Count -gt 0) ($Scenario+': evidence and review fields')
}
function Test-V8 {
    $sec='Microsoft-Windows-Security-Auditing'
    $time='2026-01-01T10:00:00.0000000Z'
    $svc=New-V7TestRow 4697 $sec $time '80' @{'Данные события'='ServiceName=BadSvc | ServiceFileName=C:\Users\Public\bad.exe'}
    $groups=@{}; Add-SingleTriage $groups $svc
    Assert-TriageGroup $groups 'Служба с нетипичными параметрами' @('4697') 1
    $task=New-V7TestRow 4698 $sec $time '81' @{'Данные события'='TaskName=BadTask | TaskContent=powershell.exe -enc AAAA'}
    $groups=@{}; Add-SingleTriage $groups $task
    Assert-TriageGroup $groups 'Задание с рискованной командой' @('4698') 1
    $created=New-V7TestRow 4720 $sec $time '82' @{}
    $admin=New-V7TestRow 4732 $sec '2026-01-01T10:01:00Z' '83' @{'SID целевой УЗ'='S-1-5-32-544';'SID участника'='S-1-5-21-1-2-3-1001'}
    $groups=@{}; Add-ChainTriage $groups @($admin,$created,$admin)
    Assert-TriageGroup $groups 'Новая УЗ получила привилегии' @('4720','4732') 2
    $admin.'Компьютер'='OTHER'; $groups=@{}; Add-ChainTriage $groups @($created,$admin)
    Assert-True ($groups.Count -eq 0) 'v8 different computers cannot correlate'
    $admin.'Компьютер'='PC01'; $admin.'Папка источника'='C:\other'
    $groups=@{}; Add-ChainTriage $groups @($created,$admin)
    Assert-True ($groups.Count -eq 0) 'v8 different source folders cannot correlate'
    $admin.'Папка источника'='C:\test'
    $rows=New-Object 'System.Collections.Generic.List[object]'
    for ($i=0;$i -lt $FailureThreshold;$i++) {
        $t=([DateTimeOffset]::Parse('2026-01-01T11:00:00Z')).AddSeconds($i).ToString('o')
        $f=New-V7TestRow 4625 $sec $t (100+$i) @{'SID целевой УЗ'='S-1-0-0';'Результат аудита'='Отказ';'Тип входа'='10';'IP источника'='::ffff:192.0.2.5';'SubStatus'='0xc000006a'}
        [void]$rows.Add($f)
    }
    $success=New-V7TestRow 4624 $sec '2026-01-01T11:01:00Z' '200' @{'Тип входа'='10';'IP источника'='192.0.2.5';'Logon ID цели'='0xabc'}
    [void]$rows.Add($success)
    $groups=@{}; Add-ChainTriage $groups $rows.ToArray()
    Assert-TriageGroup $groups 'Отказы RDP с неверным паролем → успешный вход' @('4625','4624') ($FailureThreshold+1)
    $duplicateRows=New-Object 'System.Collections.Generic.List[object]'
    for ($i=0;$i -lt $FailureThreshold;$i++) { [void]$duplicateRows.Add($rows[0]) }
    [void]$duplicateRows.Add($success)
    $groups=@{}; Add-ChainTriage $groups $duplicateRows.ToArray()
    Assert-True ($groups.Count -eq 0) 'v8 duplicate failures do not reach threshold'
    foreach ($r in $rows) { if ($r.'Event ID' -eq '4625') { $r.'SID целевой УЗ'='S-1-5-21-9-9-9-999' } }
    $groups=@{}; Add-ChainTriage $groups $rows.ToArray()
    Assert-True ($groups.Count -eq 0) 'v8 conflicting known SIDs cannot correlate'
    $login=New-V7TestRow 4624 $sec $time '300' @{'Тип входа'='10';'Logon ID цели'='0x000abc'}
    $logout=New-V7TestRow 4634 $sec '2026-01-01T10:00:30Z' '301' @{'Тип входа'='10';'Logon ID цели'='0xabc'}
    $action=New-V7TestRow 4698 $sec '2026-01-01T10:01:00Z' '302' @{'SID инициатора'='S-1-5-21-1-2-3-1001';'Logon ID инициатора'='0xabc'}
    $groups=@{}; Add-ChainTriage $groups @($login,$action)
    Assert-TriageGroup $groups 'RDP-сеанс: создание задания' @('4624','4698') 2
    $groups=@{}; Add-ChainTriage $groups @($login,$logout,$action)
    Assert-True ($groups.Count -eq 0) 'v8 logoff closes session correlation'
    # Integration test exercises the actual CSV->Build-Triage->Triage.csv path.
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-V8-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tmp)
    $script:IssueCount=0; $script:WarningCount=0
    try {
        @($svc,$task,$created,$admin) | Export-Csv -LiteralPath (Join-Path $tmp 'Findings-0001.csv') -Delimiter $Delimiter -Encoding UTF8 -NoTypeInformation
        $script:ErrorWriter=New-Writer (Join-Path $tmp 'Errors.csv')
        Write-Row $script:ErrorWriter @('Время UTC','Этап','Файл источника','Record ID','Ошибка')
        Log-Issue 'ClockOrder' 'C:\test\Application.evtx' '1' 'Synthetic warning in an unrelated file'
        Build-Triage $tmp
        $out=@(Import-Csv -LiteralPath (Join-Path $tmp 'Triage.csv') -Delimiter $Delimiter -Encoding UTF8)
        $chain=@($out | Where-Object { $_.'Сценарий' -eq 'Новая УЗ получила привилегии' })
        Assert-True (-not $script:TriageHasErrors -and $chain.Count -eq 1) 'v8 CSV integration: unrelated warning does not block chain'
        Assert-True ($chain[0].'Event ID' -eq '4720, 4732' -and $chain[0].'Связанных уникальных событий' -eq '2') 'v8 CSV integration: exact evidence exported'
        Log-Issue 'ReadEvent' 'C:\test\Security.evtx' '84' 'Synthetic incomplete relevant source'
        Build-Triage $tmp
        $out=@(Import-Csv -LiteralPath (Join-Path $tmp 'Triage.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True (@($out | Where-Object { $_.'Сценарий' -eq 'Новая УЗ получила привилегии' }).Count -eq 0) 'v8 CSV integration: incomplete relevant source blocks chain'
        Assert-True (@($out | Where-Object { $_.'Сценарий' -eq 'Служба с нетипичными параметрами' }).Count -eq 1) 'v8 CSV integration: single evidence retained'
    } finally {
        Close-Writer $script:ErrorWriter
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    if (-not $IncludeNoise) {
        $serviceLogon=Parse-Event (Test-Xml 4672 $sec '<EventData><Data Name="SubjectUserSid">S-1-5-18</Data></EventData>')
        Assert-True ($null -eq (Match-Event $serviceLogon $false)) 'v8 SYSTEM 4672 excluded'
        $serviceLogon.Data['SubjectUserSid']='S-1-5-21-1-2-3-1001'
        Assert-True ($null -eq (Match-Event $serviceLogon $false)) 'v9 user 4672 is noise by default (-IncludeNoise returns it)'
        Assert-True (-not $script:Rules.ContainsKey('Windows Error Reporting|1001')) 'v8 optional WER 1001 excluded'
        Assert-True ($script:Rules.ContainsKey('Microsoft-Windows-WER-SystemErrorReporting|1001')) 'v8 BugCheck 1001 retained'
    }
}
function Test-V81 {
    $samples=@($null,'','русский текст','a;b','a"b',"a`r`nb`tc",'=SUM(A1:A2)','  +1','-2','@test',([string][char]16),'x'+[char]0+'y',('z'*30001),('='+('x'*30002)))
    foreach ($safe in @($true,$false)) {
        $writer=New-Object IO.StringWriter
        try {
            Write-Row $writer $samples $safe
            $expectedCells=foreach ($value in $samples) { Cell $value $safe }
            $expected=[string]::Join([string]$Delimiter,[string[]]$expectedCells)+$writer.NewLine
            Assert-True ($writer.ToString() -ceq $expected) ('v8.1 CSV exact equivalence; Safe='+$safe)
        } finally { $writer.Dispose() }
    }
    foreach ($text in @('','abc','русский XML','abc',('x'*100000))) {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $expected=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
        Assert-True ((Hash-Text $text) -ceq $expected) 'v8.1 reused SHA256 exact equivalence'
    }
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-V81-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tmp)
    try {
        $path=Join-Path $tmp 'input.jsonl'
        $w=New-Writer $path
        try {
            $origin=[DateTimeOffset]::Parse('2026-01-01T00:00:00Z')
            for ($i=0; $i -lt 1200; $i++) {
                $time=$origin.AddSeconds($i*4)
                $account='LAB\user'+($i%7)
                if ($i%29 -eq 0) { $account='[unknown]' }
                $row=[ordered]@{Ticks=$time.UtcDateTime.Ticks;TimeUtc=$time.ToString('o');Computer='PC01';Scope='C:\test';EventId=4625;Account=$account;Source=('192.0.2.'+(1+($i%3)));Fingerprint=('event-'+$i);FindingId=$i;File='Security.evtx';RecordId=$i;Status='0xc000006d';SubStatus='0xc000006a'}
                $line=$row | ConvertTo-Json -Compress
                $w.WriteLine($line)
                if ($i%11 -eq 0) { $w.WriteLine($line) }
            }
        } finally { Close-Writer $w }
        $referencePath=Join-Path $tmp 'reference.csv'; $fastPath=Join-Path $tmp 'fast.csv'
        $script:BurstCount=0; $script:BurstWriter=New-Writer $referencePath
        try { Correlate-FailuresReference $path; $referenceCount=$script:BurstCount }
        finally { Close-Writer $script:BurstWriter }
        $script:BurstCount=0; $script:BurstWriter=New-Writer $fastPath
        try { Correlate-Failures $path; $fastCount=$script:BurstCount }
        finally { Close-Writer $script:BurstWriter }
        Assert-True ($referenceCount -gt 0 -and $fastCount -eq $referenceCount) 'v8.1 burst count equals v8 reference'
        Assert-True ([IO.File]::ReadAllText($referencePath) -ceq [IO.File]::ReadAllText($fastPath)) 'v8.1 complete burst CSV equals v8 reference (expiry, duplicates, cleanup)'
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
function Test-V9 {
    $sec='Microsoft-Windows-Security-Auditing'
    # Event ID limit and trimmed rule set.
    Assert-True (@($script:RuleTable | Where-Object { [int]$_.Id -gt $MaxEventId }).Count -eq 0) 'v9 no rule above MaxEventId'
    $e=Parse-Event (Test-Xml 10016 'Microsoft-Windows-DistributedCOM' '<EventData><Data Name="x">1</Data></EventData>')
    $e.Level=2
    Assert-True ($null -eq (Match-Event $e $false)) 'v9 Event ID above 10000 is not a finding'
    Assert-True ($null -eq (Match-Event $e $true)) 'v9 Event ID above 10000 ignored in AV vendor logs too'
    $e=Parse-Event (Test-Xml 999 'Some-Provider' '<EventData><Data Name="x">1</Data></EventData>'); $e.Level=2
    Assert-True (($null -ne (Match-Event $e $false)) -eq $script:GenericErrors) 'v9 generic Critical/Error rule follows -IncludeAllErrors'
    if (-not $IncludeNoise) {
        foreach ($k in @('Microsoft-Windows-Security-Auditing|4670','Service Control Manager|7036','Application Error|1000','Microsoft-Windows-Sysmon|6')) {
            Assert-True (-not $script:Rules.ContainsKey($k)) ('v9 noise rule excluded: '+$k)
        }
    }
    foreach ($k in @('Microsoft-Windows-Security-Auditing|4625','Microsoft-Windows-Security-Auditing|4720','Microsoft-Windows-Security-Auditing|4732','Microsoft-Windows-Eventlog|1102','Service Control Manager|7045','Microsoft-Windows-Windows Defender|1116','Microsoft-Windows-Security-Auditing|4698')) {
        if ([int]$k.Split('|')[1] -gt $MaxEventId) { continue }
        Assert-True ($script:Rules.ContainsKey($k)) ('v9 key rule retained: '+$k)
    }
    $query=Build-Query 'C:\x\Security.evtx' $false
    $doc=New-Object Xml.XmlDocument; $doc.LoadXml($query)
    $selects=@($doc.SelectNodes("//Select") | ForEach-Object { $_.InnerText })
    Assert-True (@($selects | Where-Object { $_ -notmatch "EventID=\d|EventID<=$MaxEventId" }).Count -eq 0) 'v9 every selector has explicit IDs or the MaxEventId limit'
    Assert-True (@((Build-Query 'C:\x\kaspersky.evtx' $true) -split '<Select>' | Where-Object { $_ -like '*</Select>*' -and $_ -notlike "*EventID&lt;=$MaxEventId*" }).Count -eq 0) 'v9 AV vendor selector limited by MaxEventId'
    Assert-True (@($selects | Where-Object { $_ -like "*EventID=4776*Status']!='0x0'*" }).Count -eq 1) 'v9 successful 4776 filtered by Windows API'
    Assert-True (@($selects | Where-Object { $_ -match '(^|[^<>!])EventID=4776 or|or EventID=4776\)' }).Count -eq 0) 'v9 4776 not selected unfiltered'
    Write-Host 'V9 SelfTest OK'
}
if ($SelfTest) {
    # Fixtures use deterministic thresholds, independent of scan parameters.
    $FailureThreshold=10; $WindowMinutes=10; $TriageWindowMinutes=30; $SprayUserThreshold=5
    try {
    Run-SelfTest
    # Run current regression tests before the legacy compatibility suite so a
    # later failure cannot hide the exact fixes introduced in v7/v7.1.
    Test-V7
    Test-V4
    Test-V8
    Test-V81
    Test-V9
    Write-Host ('ALL SELFTESTS PASSED — version '+$script:Version)
    } finally { $script:HashEngine.Dispose() }
    return
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Для чтения EVTX нужна Windows. Запускайте в Windows PowerShell 5.1.' }
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Нужен режим PowerShell FullLanguage. Используйте одобренный организацией способ запуска; скрипт не обходит политики защиты.' }
if ([string]::IsNullOrWhiteSpace($InputPath)) { throw 'Укажите -InputPath: файл EVTX или папку с EVTX.' }
$inputItem=Get-Item -LiteralPath $InputPath
if (-not $inputItem.PSIsContainer -and $inputItem.Extension -ne '.evtx') { throw 'Входной файл должен иметь расширение .evtx.' }
if ($Delimiter -in @('"',"`r","`n")) { throw 'Недопустимый разделитель CSV.' }
if ($script:HasStart -and $script:HasEnd -and $script:StartTicks -gt $script:EndTicks) { throw 'StartTime должен быть не позже EndTime.' }
if ($IncludeMessages -and $SkipMessages) { throw 'Нельзя одновременно указывать -IncludeMessages и -SkipMessages.' }
# Rendering localized descriptions can dominate the runtime for offline EVTX
# because Windows loads provider resources for every selected event. XML fields
# contain the data used by the rules, so descriptions are opt-in in v7.
$script:FormatMessages = [bool]$IncludeMessages
$started=[DateTime]::UtcNow
$outputRoot=[IO.Path]::GetFullPath($OutputPath)
[void][IO.Directory]::CreateDirectory($outputRoot)
$script:RunId=$started.ToString('yyyyMMdd_HHmmss')+'_'+[guid]::NewGuid().ToString('N').Substring(0,8)
$script:FinalBase='Audit_EVTX_'+$script:RunId
$script:RunPath=Join-Path $outputRoot ('_tmp_'+$script:FinalBase)
[void][IO.Directory]::CreateDirectory($script:RunPath)
$script:SpoolPath=Join-Path $script:RunPath 'CorrelationInput'
[void][IO.Directory]::CreateDirectory($script:SpoolPath)
$script:IssueCount=0; $script:WarningCount=0; $script:FindingCount=[long]0; $script:RdpCount=0; $script:BurstCount=0
$script:Part=0; $script:PartRows=0; $script:FindingWriter=$null; $script:EvidenceWriter=$null; $script:Summary=@{}
$script:FindingHeaders=@('Номер','Event ID','Record ID','Приоритет','Категория','Событие','Что проверить','Время UTC','Компьютер','Папка источника','Файл журнала','Полный путь','Канал','Провайдер','Уровень Windows','Результат аудита','Инициатор','SID инициатора','Целевая УЗ','SID целевой УЗ','Участник группы','SID участника','IP источника','Порт источника','Рабочая станция','Тип входа','Logon ID цели','Logon ID инициатора','Session ID','Имя сеанса','Status','SubStatus','Процесс','Командная строка','Привилегии','Имя угрозы','Ресурс / путь','Старое время','Новое время','Сдвиг времени, сек','Данные события','Описание Windows','Статус описания','Правило','SHA256 XML события','Восстановление XML')
$script:ErrorWriter=New-Writer (Join-Path $script:RunPath 'Errors.csv')
Write-Row $script:ErrorWriter @('Время UTC','Этап','Файл источника','Record ID','Ошибка')
$inventoryWriter=New-Writer (Join-Path $script:RunPath 'Files.csv')
Write-Row $inventoryWriter @('Полный путь','Размер, байт','Изменен UTC','SHA256 файла','Статус обработки','Прочитано подходящих событий','Находок','Ошибок разбора','Нет описания Windows','Время первой записи UTC','Время последней записи UTC','Каналы','Компьютеры','Способ отбора','Комментарий','Время обработки, сек')
$script:RdpWriter=New-Writer (Join-Path $script:RunPath 'RdpIntervals.csv')
Write-Row $script:RdpWriter @('Event ID начала','Event ID конца','Файл источника','Компьютер','Учетная запись','Logon ID','IP источника','Начало UTC','Окончание UTC','Длительность, сек','Статус','Комментарий','Record ID начала','Record ID конца','Номер находки начала','Номер находки конца')
$script:BurstWriter=New-Writer (Join-Path $script:RunPath 'AuthBursts.csv')
Write-Row $script:BurstWriter @('Приоритет','Event ID','Событие','Папка источника','Компьютер','Источник','Окно: начало UTC','Окно: конец UTC','Событий в окне','Разных УЗ','Учетные записи','Номера находок (пример)','Файлы и Record ID (пример)','Коды статуса','Комментарий')
New-FindingFile
$runStatus='Running'; $files=@(); $processed=0; $warningFiles=0; $failedFiles=0; $processingWarnings=0; $correlationErrors=0; $fatalError=$null
$metaPath=Join-Path $script:RunPath 'Run.json'
$metadata=[ordered]@{ScriptVersion=$script:Version;StartedUtc=$started.ToString('o');FinishedUtc=$null;Status='Running';InputPath=$inputItem.FullName;OutputPath=$outputRoot;
    PowerShell=$PSVersionTable.PSVersion.ToString();Parameters=[ordered]@{FailureThreshold=$FailureThreshold;WindowMinutes=$WindowMinutes;SprayUserThreshold=$SprayUserThreshold;MaxRdpHours=$MaxRdpHours;RowsPerCsv=$RowsPerCsv;Delimiter=[string]$Delimiter;IncludeNoise=[bool]$IncludeNoise;IncludeAllErrors=[bool]$IncludeAllErrors;MaxEventId=$MaxEventId;StartTimeUtc=$(if($script:HasStart){$StartTime.ToUniversalTime().ToString('o')}else{''});EndTimeUtc=$(if($script:HasEnd){$EndTime.ToUniversalTime().ToString('o')}else{''});IncludeMessages=[bool]$script:FormatMessages;SkipMessages=[bool]$SkipMessages;IncludeNetworkLogons=[bool]$IncludeNetworkLogons;DeepScriptScan=[bool]$DeepScriptScan;IncludeProcessCreation=[bool]$IncludeProcessCreation;HashFiles=[bool]$HashFiles;SkipCorrelation=[bool]$SkipCorrelation;SkipTriage=[bool]$SkipTriage;TriageWindowMinutes=$TriageWindowMinutes;NoExcel=[bool]$NoExcel;KeepTechnicalFiles=[bool]$KeepTechnicalFiles;IncludeAllAntivirusEvents=[bool]$IncludeAllAntivirusEvents;ExtraAvFilePattern=$ExtraAvFilePattern};FilesDiscovered=0;FilesProcessed=0;WarningFiles=0;FailedOrPartialFiles=0;Findings=0;RdpRows=0;AuthBursts=0;Issues=0;ProcessingWarnings=0;CorrelationErrors=0}
[IO.File]::WriteAllText($metaPath,($metadata|ConvertTo-Json -Depth 6),$script:Utf8)
try {
    $discoveryErrors=@()
    if ($inputItem.PSIsContainer) {
        $files=@(Get-ChildItem -LiteralPath $inputItem.FullName -Filter '*.evtx' -File -Recurse -ErrorAction SilentlyContinue -ErrorVariable discoveryErrors | Sort-Object FullName)
    } else { $files=@($inputItem) }
    foreach ($err in $discoveryErrors) { Log-Issue 'Discovery' $inputItem.FullName '' $err.ToString() }
    if ($files.Count -eq 0) { throw 'Доступные .evtx не найдены. Проверьте InputPath и отчет об ошибках.' }
    if ($KeepTechnicalFiles) { $script:RuleTable | Export-Csv -LiteralPath (Join-Path $script:RunPath 'Rules.csv') -Delimiter $Delimiter -Encoding UTF8 -NoTypeInformation }
    for ($index=0; $index -lt $files.Count; $index++) {
        $file=$files[$index]
        $fileStopwatch=[Diagnostics.Stopwatch]::StartNew()
        $originalLength=$file.Length; $originalWriteTime=$file.LastWriteTimeUtc
        Write-Host ('[{0}/{1}] {2}' -f ($index+1),$files.Count,$file.FullName)
        Write-Progress -Activity 'Offline EVTX audit' -Status $file.Name -PercentComplete (100*$index/$files.Count)
        $selected=0; $parseErrors=0; $messageMissing=0; $before=$script:FindingCount
        $status='OK'; $hash=''
        if ($script:GenericErrors) { $note='Отбор через Windows API выполнен; читаются только записи по правилам и Critical/Error.'; $selectionMethod='Правила + Critical/Error' }
        else { $note='Отбор через Windows API выполнен; читаются только записи по правилам (общий отбор Critical/Error выключен, см. -IncludeAllErrors).'; $selectionMethod='Правила' }
        if ($script:HasStart -or $script:HasEnd) { $note+=' Задан период -StartTime/-EndTime: события вне периода не читались.' }
        $first=''; $last=''; $reader=$null; $state=@{}; $spoolWriters=@{}; $lastTimes=@{}
        $channels=New-Object 'System.Collections.Generic.HashSet[string]'
        $computers=New-Object 'System.Collections.Generic.HashSet[string]'
        $xmlRecovered=0
        $xmlRecoveryIds=New-Object 'System.Collections.Generic.List[string]'
        $vendorFile=$file.Name -match $ExtraAvFilePattern
        $evidenceName=''
        $script:EvidenceWriter=$null
        if ($KeepTechnicalFiles) {
            $evidenceName='Evidence-{0:D5}.jsonl' -f ($index+1)
            $script:EvidenceWriter=New-Writer (Join-Path $script:RunPath $evidenceName)
        }
        try {
            if ($HashFiles) {
                try { $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
                catch { Log-Issue 'Hash' $file.FullName '' $_.Exception.Message; $status='Partial' }
            }
            # Boundary records are fetched without filtering; these are not min/max
            # timestamps when the source computer's clock has moved backwards.
            foreach ($reverse in @($false,$true)) {
                $boundaryReader=$null; $boundary=$null
                try {
                    $q=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($file.FullName,[System.Diagnostics.Eventing.Reader.PathType]::FilePath,'*')
                    $q.ReverseDirection=$reverse
                    $boundaryReader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
                    $boundary=$boundaryReader.ReadEvent()
                    if ($boundary) {
                        $b=Parse-Event $boundary.ToXml()
                        if ($reverse) { $last=$b.TimeUtc } else { $first=$b.TimeUtc }
                        [void]$channels.Add($b.Channel); [void]$computers.Add($b.Computer)
                    }
                } catch { Log-Issue 'BoundaryRead' $file.FullName '' $_.Exception.Message; $status='Partial' }
                finally { if ($boundary) {$boundary.Dispose()}; if ($boundaryReader) {$boundaryReader.Dispose()} }
            }
            try {
                $queryText=Build-Query $file.FullName $vendorFile
                $q=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($file.FullName,[System.Diagnostics.Eventing.Reader.PathType]::FilePath,$queryText)
                $q.ReverseDirection=$false; $q.TolerateQueryErrors=$false
                $reader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
                $reader.BatchSize=1024
            } catch {
                # Safety fallback: if the optimized structured query is rejected by this
                # Windows/.NET build, read the EVTX sequentially and apply the same rules
                # in PowerShell. Slower, but it avoids treating an unread file as clean.
                $filteredError=$_.Exception.Message
                try {
                    $q=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($file.FullName,[System.Diagnostics.Eventing.Reader.PathType]::FilePath,'*')
                    $q.ReverseDirection=$false; $q.TolerateQueryErrors=$false
                    $reader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
                    $reader.BatchSize=1024
                    $note='Фильтрованный запрос Windows API отклонен; выполнен полный последовательный просмотр EVTX с теми же правилами. Причина фильтра: '+$filteredError
                    $selectionMethod='Полный просмотр (fallback)'
                    Write-Warning ('Фильтрованный запрос не открылся; используется полный просмотр: '+$file.FullName)
                } catch {
                    Log-Issue 'OpenQuery' $file.FullName '' ($filteredError+' | Fallback: '+$_.Exception.Message)
                    $status='Failed'; $note='Не удалось открыть EVTX ни фильтрованным запросом, ни полным просмотром; файл не проверен полностью.'
                }
            }
            if ($reader) {
                while ($true) {
                    $record=$null
                    try { $record=$reader.ReadEvent() }
                    catch { Log-Issue 'ReadEvent' $file.FullName '' $_.Exception.Message; $status='Partial'; $note='Чтение прервано; оставшиеся события этого файла НЕ проверены.'; break }
                    if ($null -eq $record) { break }
                    $selected++; $e=$null; $r=$null
                    try {
                        try {
                            $e=Parse-Event $record.ToXml()
                            if ($e.XmlRecovery) {
                                $xmlRecovered++
                                if ($xmlRecoveryIds.Count -lt 10) { $xmlRecoveryIds.Add([string]$e.RecordId) }
                            }
                            [void]$channels.Add($e.Channel); [void]$computers.Add($e.Computer)
                            $r=Match-Event $e $vendorFile
                            if ($script:FormatMessages -and ($r -or $vendorFile)) {
                                try {
                                    $e.Message=[string]$record.FormatDescription()
                                    $e.MessageStatus='Available'
                                    if (-not $e.Message) { $e.MessageStatus='Unavailable'; $messageMissing++ }
                                } catch { $e.MessageStatus='Unavailable'; $messageMissing++ }
                                # A third-party AV may expose the product-specific text
                                # only after rendering. Re-evaluate that record once.
                                if ($vendorFile) { $r=Match-Event $e $vendorFile }
                            }
                        } catch {
                            $parseErrors++; $status='Partial'
                            Log-Issue 'ParseOrRule' $file.FullName ([string]$record.RecordId) $_.Exception.Message
                            Reset-Rdp $state '' 'Пропущено событие из-за ошибки разбора: корреляция разорвана.'
                            continue
                        }
                        # The XPath time window is not applied by the full-scan fallback.
                        if (($script:HasStart -and $e.Ticks -lt $script:StartTicks) -or ($script:HasEnd -and $e.Ticks -gt $script:EndTicks)) { continue }
                        # Event timestamps can move slightly backwards because of NTP corrections or
                        # provider/write ordering. Treat only a material rollback (>= 5 minutes)
                        # as an audit warning and RDP-correlation boundary. Security 4616 remains
                        # the primary signal for explicit system-time changes.
                        if ($lastTimes.ContainsKey($e.Computer) -and $e.Ticks -lt $lastTimes[$e.Computer]) {
                            $rollbackSeconds = [Math]::Round((($lastTimes[$e.Computer] - $e.Ticks) / [double][TimeSpan]::TicksPerSecond),3)
                            if ($rollbackSeconds -ge 300) {
                                Reset-Rdp $state $e.Computer 'Время событий существенно пошло назад; корреляция разорвана.'
                                Log-Issue 'ClockOrder' $file.FullName $e.RecordId ('Предупреждение, не ошибка чтения: время события меньше предыдущего выбранного события на '+$rollbackSeconds+' сек. Проверить Security 4616, синхронизацию времени и порядок записей.')
                            }
                        }
                        $lastTimes[$e.Computer]=$e.Ticks
                        $findingId=[long]0
                        if ($r) {
                            $e.Fingerprint=Hash-Text $e.Xml
                            $findingId=Save-Finding $e $r $file $evidenceName
                            if ($e.Id -in $script:FailureIds) { Save-Failure $e $file $findingId $spoolWriters }
                        }
                        # Skip the call for events that cannot open, close or reset an RDP interval.
                        if ($script:RdpRelevant.Contains($e.Provider+'|'+$e.Id)) { Handle-Rdp $e $state $file.FullName $findingId }
                    } finally { $record.Dispose() }
                    if ($selected % 10000 -eq 0) {
                        Write-Progress -Activity 'Offline EVTX audit' -Status ($file.Name+': selected '+$selected) -PercentComplete (100*$index/$files.Count)
                        $script:FindingWriter.Flush(); if ($script:EvidenceWriter) { $script:EvidenceWriter.Flush() }
                    }
                }
            }
            Reset-Rdp $state '' 'Конец файла; конец сеанса неизвестен. Между файлами RDP автоматически не объединяется.'
            $file.Refresh()
            if ($file.Length -ne $originalLength -or $file.LastWriteTimeUtc -ne $originalWriteTime) {
                $status='Partial'; Log-Issue 'InputChanged' $file.FullName '' 'Размер или время изменения файла поменялись во время чтения. Повторить анализ неизменяемой копии.'
            }
            if ($xmlRecovered -gt 0) {
                if ($status -eq 'OK') { $status='Warning' }
                $note+=' Восстановлено XML записей: '+$xmlRecovered+'. Сверить отмеченные данные с исходным EVTX.'
                Log-Issue 'XmlRecovered' $file.FullName ($xmlRecoveryIds -join ', ') ('Восстановлено записей: '+$xmlRecovered+'. Недопустимые XML-символы заменены видимыми маркерами; EVTX не изменен. Record ID — до 10 примеров.')
            }
            if ($status -eq 'OK' -and $selected -eq 0) { $status='NoCandidates'; $note='Записей, подходящих под правила, не найдено. Это НЕ доказывает отсутствие инцидентов.' }
            if ($messageMissing -gt 0) { $note+=' Часть описаний провайдеров недоступна; анализ выполнен по XML.' }
            if ($vendorFile) { $note+=' Для журнала стороннего антивируса прочитаны все события, но в находки попали только угрозы/ошибки или все события при -IncludeAllAntivirusEvents.' }
            $fileStopwatch.Stop()
            Write-Host ('  Завершено: {0:N1} сек.; прочитано {1}; находок {2}; режим: {3}' -f $fileStopwatch.Elapsed.TotalSeconds,$selected,($script:FindingCount-$before),$selectionMethod)
            Write-Row $inventoryWriter @($file.FullName,$file.Length,$file.LastWriteTimeUtc.ToString('o'),$hash,(Ru-FileStatus $status),$selected,($script:FindingCount-$before),$parseErrors,$messageMissing,$first,$last,([string]::Join(' | ',[string[]]@($channels))),([string]::Join(' | ',[string[]]@($computers))),$(if($vendorFile){'Все события антивируса'}else{$selectionMethod}),$note,[Math]::Round($fileStopwatch.Elapsed.TotalSeconds,1))
            $inventoryWriter.Flush()
            if ($status -eq 'Warning') { $warningFiles++ }
            if ($status -in @('Partial','Failed')) { $failedFiles++ }
            $processed++
        } finally {
            if ($reader) { $reader.Dispose() }
            Close-Writer $script:EvidenceWriter
            foreach ($w in $spoolWriters.Values) { Close-Writer $w }
            $script:FindingWriter.Flush(); $script:ErrorWriter.Flush()
        }
    }
    if (-not $SkipCorrelation) {
        $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
        Write-Host 'Корреляция неудачных аутентификаций...'
        foreach ($spool in (Get-ChildItem -LiteralPath $script:SpoolPath -Filter '*.jsonl' -File)) {
            try { Correlate-Failures $spool.FullName }
            catch { $correlationErrors++; Log-Issue 'Correlation' $spool.FullName '' $_.Exception.Message }
        }
        Write-Host ('Корреляция отказов: {0:N1} сек.' -f $phaseTimer.Elapsed.TotalSeconds)
    }
    $summaryWriter=New-Writer (Join-Path $script:RunPath 'Summary.csv')
    Write-Row $summaryWriter @('Приоритет','Категория','Компьютер','Количество')
    foreach ($row in ($script:Summary.Values | Sort-Object -Property @('Computer','Category','Severity'))) { Write-Row $summaryWriter @((Ru-Severity $row.Severity),$row.Category,$row.Computer,$row.Count) }
    Close-Writer $summaryWriter
    if (-not $SkipTriage) {
        $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
        Write-Host 'Формирование листов Приоритетные и Качество_выгрузки...'
        $script:FindingWriter.Flush(); $inventoryWriter.Flush(); $script:ErrorWriter.Flush()
        try {
            Build-Triage $script:RunPath
            if ($script:TriageHasErrors) { $correlationErrors++ }
            elseif ($script:TriageIncomplete) { $processingWarnings++ }
        }
        catch {
            $correlationErrors++
            $triageError=Get-TriageErrorText $_
            Log-Issue 'Triage' $script:RunPath '' $triageError
            $triageFile=Join-Path $script:RunPath 'Triage.csv'
            if (-not (Test-Path -LiteralPath $triageFile)) {
                try { Write-TriageFallback $script:RunPath $triageError }
                catch { Log-Issue 'Triage' $script:RunPath '' ('Не удалось создать даже резервный лист Приоритетные: '+(Get-TriageErrorText $_)) }
            }
            Write-Warning 'Приоритизация выполнена с ограничениями. Лист Приоритетные сохранен; подробность есть на листе Ошибки.'
        }
        try { Build-LogCoverage $script:RunPath }
        catch {
            $correlationErrors++
            Log-Issue 'Triage' $script:RunPath '' ('Не сформирован лист Качество_выгрузки: '+$_.Exception.Message)
            $coverageFile=Join-Path $script:RunPath 'Coverage.csv'
            if (Test-Path -LiteralPath $coverageFile) { Remove-Item -LiteralPath $coverageFile -Force }
            Write-Warning 'Лист Качество_выгрузки не сформирован; базовые отчеты сохранены.'
        }
        Write-Host ('Приоритетные и качество выгрузки: {0:N1} сек.' -f $phaseTimer.Elapsed.TotalSeconds)
    }
    $runStatus='Completed'
    if ($failedFiles -gt 0 -or $discoveryErrors.Count -gt 0 -or $correlationErrors -gt 0) { $runStatus='CompletedWithErrors' }
    elseif ($warningFiles -gt 0 -or $script:WarningCount -gt 0 -or $processingWarnings -gt 0) { $runStatus='CompletedWithWarnings' }
} catch {
    $runStatus='Failed'
    $fatalError=$_
    try { Log-Issue 'Fatal' $script:RunPath '' $_.Exception.Message } catch { }
} finally {
    $metadata.FinishedUtc=[DateTime]::UtcNow.ToString('o'); $metadata.Status=$runStatus
    $metadata.FilesDiscovered=$files.Count; $metadata.FilesProcessed=$processed; $metadata.WarningFiles=$warningFiles; $metadata.FailedOrPartialFiles=$failedFiles
    $metadata.Findings=$script:FindingCount; $metadata.RdpRows=$script:RdpCount; $metadata.AuthBursts=$script:BurstCount
    $metadata.Issues=$script:IssueCount; $metadata.ProcessingWarnings=($script:WarningCount+$processingWarnings); $metadata.CorrelationErrors=$correlationErrors
    foreach ($w in @($script:Writers)) { try { $w.Dispose() } catch { } }
    $script:Writers.Clear()
    $script:HashEngine.Dispose()
    [IO.File]::WriteAllText($metaPath,($metadata|ConvertTo-Json -Depth 6),$script:Utf8)
    Write-Progress -Activity 'Offline EVTX audit' -Completed
}
Write-Host 'Сохранение итогового отчета Excel/CSV...'
$phaseTimer=[Diagnostics.Stopwatch]::StartNew()
$finalReports = Publish-FinalReports -WorkPath $script:RunPath -OutputRoot $outputRoot -BaseName $script:FinalBase
Write-Host ('Сохранение отчета: {0:N1} сек.' -f $phaseTimer.Elapsed.TotalSeconds)
Write-Host ('Статус: '+(Ru-RunStatus $runStatus))
Write-Host ('Файлов обработано: '+$processed+'; находок: '+$script:FindingCount+'; замечаний обработки: '+$script:IssueCount)
foreach ($report in $finalReports) { Write-Host ('Результат: '+$report) }
if ($KeepTechnicalFiles) {
    $technicalPath=Join-Path $outputRoot ($script:FinalBase+'_Technical')
    if (Test-Path -LiteralPath $technicalPath) { Remove-Item -LiteralPath $technicalPath -Recurse -Force }
    Move-Item -LiteralPath $script:RunPath -Destination $technicalPath
    Write-Host ('Технические файлы: '+$technicalPath)
} else {
    try { Remove-Item -LiteralPath $script:RunPath -Recurse -Force -ErrorAction Stop } catch { Write-Warning ('Не удалось удалить временную папку: '+$script:RunPath+'. '+$_.Exception.Message) }
}
if ($runStatus -eq 'CompletedWithErrors') { Write-Warning 'Часть файлов обработана не полностью. Откройте листы "Файлы" и "Ошибки" (или второй CSV при fallback).' }
elseif ($runStatus -eq 'CompletedWithWarnings') { Write-Warning 'Обработка завершена. Есть предупреждения качества данных или ограничения временных связок; это не означает, что чтение файлов было прервано. Проверьте листы "Файлы" и "Ошибки".' }
if ($fatalError) { throw $fatalError.Exception }
