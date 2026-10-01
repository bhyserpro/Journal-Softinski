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
    [ValidateRange(1,720)][int]$IncidentGapHours = 24,
    [string]$DisplayTimeZone,
    [switch]$NoExcel,
    [switch]$KeepTechnicalFiles,
    [switch]$IncludeAllAntivirusEvents,
    [string]$ExtraAvFilePattern = '(?i)(doctor[ ._-]*web|dr[ ._-]*web|kaspersky|eset|symantec|sophos|mcafee|trend.?micro)',
    [switch]$SelfTest
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Version = '9.2.0'
$script:Utf8 = New-Object System.Text.UTF8Encoding($true)
$script:Invariant = [Globalization.CultureInfo]::InvariantCulture
# Time zone for the "(местное)" columns: -DisplayTimeZone (Windows id, e.g. 'Russian Standard Time') or this computer's zone.
$script:DisplayTz=[TimeZoneInfo]::Local
if ($DisplayTimeZone) { $script:DisplayTz=[TimeZoneInfo]::FindSystemTimeZoneById($DisplayTimeZone) }
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
Microsoft-Windows-Security-Auditing	4766	Привилегии	High	Неудачная попытка добавить SID History к УЗ	Попытка изменения SID History не удалась; проверить инициатора и цель — сама попытка подозрительна.
Microsoft-Windows-Security-Auditing	4964	Привилегии	Medium	Вход члена особой группы (Special Groups)	Особые группы задаются политикой аудита Special Logon; проверить УЗ, источник входа и тип входа.
Microsoft-Windows-Security-Auditing	4672	Привилегии	Low	Специальные привилегии назначены при входе	Контекст привилегированного входа; это не доказательство повышения привилегий.
Microsoft-Windows-Security-Auditing	4625	Аутентификация	Low	Неудачный вход	Проверить Status/SubStatus; повторные отказы могут быть вызваны сохраненным старым паролем.
Microsoft-Windows-Security-Auditing	4648	Удаленный доступ	Low	Вход с явными учетными данными	Проверить инициатора, целевую УЗ, TargetServerName и процесс; характерно для runas, подключения к ресурсам и бокового перемещения.
Microsoft-Windows-Security-Auditing	4771	Аутентификация	Low	Ошибка предварительной аутентификации Kerberos	Проверить Status/SubStatus; повторные отказы могут быть вызваны сохраненным старым паролем.
Microsoft-Windows-Security-Auditing	4776	Аутентификация	Low	Проверка учетных данных NTLM	Проверить Status/SubStatus; повторные отказы могут быть вызваны сохраненным старым паролем.
Microsoft-Windows-Security-Auditing	4740	Аутентификация	Medium	Учетная запись заблокирована	Проверить источник и контекст; само событие не доказывает атаку или успешный вход.
Microsoft-Windows-Security-Auditing	4624	Удаленный доступ	Info	Успешный вход	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4634	Удаленный доступ	Info	Сеанс входа завершен	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4647	Удаленный доступ	Info	Выход, инициированный пользователем	Закрывает RDP-интервал по Logon ID; для локального сеанса — только контекст.
Microsoft-Windows-Security-Auditing	4778	Удаленный доступ	Info	Повторное подключение к сеансу Window Station	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4779	Удаленный доступ	Info	Отключение от сеанса Window Station	RDP определяется типом входа/именем сеанса; отключение не тождественно выходу.
Microsoft-Windows-Security-Auditing	4719	Политики защиты	High	Изменена политика аудита	Проверить значения и согласованное администрирование.
Microsoft-Windows-Security-Auditing	4902	Политики защиты	Medium	Создана таблица политики аудита для пользователя	Проверить, кто и зачем изменял per-user audit policy; само событие не означает очистку журнала.
Microsoft-Windows-Security-Auditing	4904	Политики защиты	High	Попытка зарегистрировать источник событий безопасности	Нетипичная регистрация источника Security требует проверки инициатора и легитимности ПО.
Microsoft-Windows-Security-Auditing	4905	Политики защиты	High	Попытка отменить регистрацию источника событий безопасности	Может повлиять на журналирование; проверить инициатора, источник и согласование.
Microsoft-Windows-Security-Auditing	4906	Политики защиты	High	Изменено значение CrashOnAuditFail	Изменение поведения системы при невозможности записывать аудит; проверить новое значение и инициатора.
Microsoft-Windows-Security-Auditing	4907	Политики защиты	High	Изменены параметры аудита объекта	Проверить значения и согласованное администрирование.
Microsoft-Windows-Security-Auditing	4715	Политики защиты	High	Изменена политика аудита (SACL) объекта политики	Изменение SACL самой политики аудита; проверить инициатора и согласование.
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
Microsoft-Windows-Kernel-General	24	Время	Medium	Изменен/обновлен часовой пояс	Проверить текущее смещение (bias) и инициатора; обновление также записывается при загрузке.
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
Microsoft-Windows-Windows Defender	1121	Антивирус	High	Правило ASR/Exploit Guard заблокировало операцию	Проверить правило ASR, процесс и путь; блокировка может быть ложной для легитимного ПО.
Microsoft-Windows-Windows Defender	2012	Антивирус	Medium	Ошибка Dynamic Signature Service Defender	Ошибка получения динамических сигнатур/облачной защиты; проверить связь и состояние защиты.
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
    'Microsoft-Windows-Security-Auditing|4700',
    'Microsoft-Windows-Security-Auditing|4723',  # user changes own password
    'Microsoft-Windows-Security-Auditing|4946',  # firewall rules: mass-created by app installs/updates
    'Microsoft-Windows-Security-Auditing|4947',
    'Microsoft-Windows-Security-Auditing|4948',
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
    'Microsoft-Windows-Kernel-General|12',
    'Microsoft-Windows-Kernel-General|13',
    'Service Control Manager|7000',
    'Service Control Manager|7001',
    'Service Control Manager|7011',
    'Service Control Manager|7023',
    'Service Control Manager|7024',
    'Application Error|1000',
    'Windows Error Reporting|1001',
    'Microsoft-Windows-Windows Defender|1013',
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
    'Microsoft-Windows-Security-Auditing|4778','Microsoft-Windows-Security-Auditing|4779','Microsoft-Windows-Security-Auditing|4647',
    'Microsoft-Windows-TerminalServices-LocalSessionManager|21','Microsoft-Windows-TerminalServices-LocalSessionManager|23',
    'Microsoft-Windows-TerminalServices-LocalSessionManager|24','Microsoft-Windows-TerminalServices-LocalSessionManager|25',
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
$script:RuSeverityMap=@{}; foreach ($v in @('High','Medium','Low','Info')) { $script:RuSeverityMap[$v]=Ru-Severity $v }
$script:RuAuditMap=@{}; foreach ($v in @('Success','Failure','')) { $script:RuAuditMap[$v]=Ru-AuditOutcome $v }
function Ru-MessageStatus([string]$Value) {
    switch ($Value) {
        'Available' { return 'Доступно' }
        'Unavailable' { return 'Недоступно' }
        'NotRequested' { return 'Не запрашивалось' }
        default { return $Value }
    }
}
$script:RuMessageMap=@{}; foreach ($v in @('Available','Unavailable','NotRequested')) { $script:RuMessageMap[$v]=Ru-MessageStatus $v }
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

# Fields resolved once per event (first non-empty, non-'-' value among the names).
# Replaces ~28 calls of Field per finding; semantics are identical to Field.
$script:FieldSpecs=@(
    @('SubjectDomainName','SubjectDomainName'),@('SubjectUserName','SubjectUserName'),
    @('TargetDomain','TargetDomainName','AccountDomain'),@('TargetUser','TargetUserName','AccountName'),
    @('SourceIP','IpAddress','ClientAddress','Address','Param3'),@('LogonType','LogonType'),
    @('LogonId','TargetLogonId','LogonID','LogonId'),@('SessionName','SessionName'),
    @('SubjectUserSid','SubjectUserSid'),@('TargetSid','TargetUserSid','TargetSid'),@('MemberName','MemberName'),@('MemberSid','MemberSid'),
    @('Port','IpPort','ClientPort'),@('Workstation','WorkstationName','Workstation','ClientName'),@('SubjectLogonId','SubjectLogonId'),
    @('SessionID','SessionID','SessionId'),@('Status','Status'),@('SubStatus','SubStatus'),@('Process','ProcessName','NewProcessName','Image'),
    @('CommandLine','CommandLine'),@('Privileges','PrivilegeList','AccessGranted','AccessRemoved','AccessList'),@('Threat','Threat Name','ThreatName'),
    @('Path','Path','Resource Path'),@('OldTime','PreviousTime','OldTime'),@('NewTime','NewTime'),@('User','User'),
    @('TargetServer','TargetServerName'),@('ServiceName','ServiceName','param1'),@('ImagePath','ImagePath','ServiceFileName')
)
# Name -> (field key, preference); built once so each event needs one pass over its data.
$script:FieldIndex=@{}
foreach ($spec in $script:FieldSpecs) {
    for ($n=1; $n -lt $spec.Length; $n++) {
        if (-not $script:FieldIndex.ContainsKey($spec[$n])) { $script:FieldIndex[$spec[$n]]=New-Object 'System.Collections.Generic.List[object]' }
        $script:FieldIndex[$spec[$n]].Add(@($spec[0],$n))
    }
}
function New-EventRecord([string]$Provider,[string]$IdText,[string]$Channel,[string]$Computer,[string]$RecordId,[string]$LevelText,[string]$SystemTime,[string]$Keywords,$Data,[string]$XmlText,[string]$Recovery) {
    $time = [DateTimeOffset]::Parse($SystemTime, $script:Invariant)
    $audit = ''
    if ($Keywords) {
        $kw = [Convert]::ToUInt64(($Keywords -replace '^0x',''),16)
        if (($kw -band [UInt64]4503599627370496) -ne 0) { $audit = 'Failure' }
        elseif (($kw -band [UInt64]9007199254740992) -ne 0) { $audit = 'Success' }
    }
    # Missing keys read as $null (written as empty cells).
    $f=@{}; $rank=@{}
    foreach ($entry in $Data.GetEnumerator()) {
        $targets=$script:FieldIndex[$entry.Key]
        if ($null -eq $targets) { continue }
        $v=[string]$entry.Value
        if ([string]::IsNullOrWhiteSpace($v) -or $v -eq '-') { continue }
        foreach ($t in $targets) { $k=$t[0]; if (-not $rank.ContainsKey($k) -or $t[1] -lt $rank[$k]) { $f[$k]=$v; $rank[$k]=$t[1] } }
    }
    $subject=''; if ($f['SubjectUserName']) { $subject=$f['SubjectUserName']; if ($f['SubjectDomainName']) { $subject=$f['SubjectDomainName']+'\'+$subject } }
    $target=''; if ($f['TargetUser']) { $target=$f['TargetUser']; if ($f['TargetDomain']) { $target=$f['TargetDomain']+'\'+$target } }
    return [pscustomobject]@{
        Provider=$Provider; Id=[int]$IdText
        Channel=$Channel; Computer=$Computer; RecordId=$RecordId; Level=[int]$LevelText
        TimeUtc=$time.UtcDateTime.ToString('o',$script:Invariant); Ticks=$time.UtcDateTime.Ticks
        Data=$Data; F=$f; AuditOutcome=$audit; Xml=$XmlText; XmlRecovery=$Recovery
        Subject=$subject; Target=$target; SourceIP=[string]$f['SourceIP']; LogonType=[string]$f['LogonType']; LogonId=[string]$f['LogonId']; SessionName=[string]$f['SessionName']
        Message=''; MessageStatus='NotRequested'; Fingerprint=''
    }
}
# v9.2 fast path: Windows renders event XML in a fixed, simple shape. Regular
# expressions read System and EventData without building an XmlDocument. Anything
# unusual (UserData, CDATA, numeric references, control characters, CR, nested
# elements, attributes on EventData, unknown entities) goes to the full XML parser.
$script:RxOpt=[Text.RegularExpressions.RegexOptions]::CultureInvariant
$script:RxHead=New-Object Text.RegularExpressions.Regex('^<Event xmlns=([''"])http://schemas\.microsoft\.com/win/2004/08/events/event\1>',$script:RxOpt)
$script:RxUnsafe=New-Object Text.RegularExpressions.Regex('[\x00-\x08\x0B\x0C\x0E-\x1F\r￾￿]|<!|&#|<\?|<UserData|<EventData[ /]|&(?!(?:lt|gt|amp|quot|apos);)',$script:RxOpt)
$script:RxSysItem=New-Object Text.RegularExpressions.Regex('<(Provider|EventID|Level|Keywords|TimeCreated|EventRecordID|Channel|Computer)\b([^>]*?)(?:/>|>([^<]*)</\1>)',$script:RxOpt)
$script:RxAttrName=New-Object Text.RegularExpressions.Regex('\sName=(?:''([^'']*)''|"([^"]*)")',$script:RxOpt)
$script:RxAttrTime=New-Object Text.RegularExpressions.Regex('\sSystemTime=(?:''([^'']*)''|"([^"]*)")',$script:RxOpt)
$script:RxData=New-Object Text.RegularExpressions.Regex('<Data(?: Name=(?:''([^'']*)''|"([^"]*)"))?\s*(?:/>|>([^<]*)</Data>)',$script:RxOpt)
$script:RxDataRest=New-Object Text.RegularExpressions.Regex('^(?:<Binary>[0-9A-Fa-f]*</Binary>)?$',$script:RxOpt)
function Parse-EventFast([string]$XmlText) {
    # Returns $null when the text is not in the simple shape; the caller then uses the XML parser.
    if (-not $script:RxHead.IsMatch($XmlText) -or $script:RxUnsafe.IsMatch($XmlText)) { return $null }
    $sysStart=$XmlText.IndexOf('<System>'); $sysEnd=$XmlText.IndexOf('</System>')
    if ($sysStart -lt 0 -or $sysEnd -lt $sysStart -or $XmlText.IndexOf('<System>',$sysStart+8) -ge 0) { return $null }
    $sys=$XmlText.Substring($sysStart+8,$sysEnd-$sysStart-8)
    if ($sys.IndexOf('&') -ge 0) { return $null }
    $items=@{}
    foreach ($m in $script:RxSysItem.Matches($sys)) { $tag=$m.Groups[1].Value; if (-not $items.ContainsKey($tag)) { $items[$tag]=$m } }
    if (-not $items.ContainsKey('Provider') -or -not $items.ContainsKey('EventID') -or -not $items.ContainsKey('TimeCreated') -or -not $items.ContainsKey('Keywords')) { return $null }
    $pm=$script:RxAttrName.Match($items['Provider'].Groups[2].Value); if (-not $pm.Success) { return $null }
    $provider=$pm.Groups[1].Value+$pm.Groups[2].Value
    $tm=$script:RxAttrTime.Match($items['TimeCreated'].Groups[2].Value); if (-not $tm.Success) { return $null }
    $data=[ordered]@{}
    $edStart=$XmlText.IndexOf('<EventData>')
    if ($edStart -ge 0) {
        $edEnd=$XmlText.IndexOf('</EventData>',$edStart)
        if ($edEnd -lt 0 -or $XmlText.IndexOf('<EventData>',$edEnd) -ge 0) { return $null }
        $body=$XmlText.Substring($edStart+11,$edEnd-$edStart-11)
        $i=0
        foreach ($m in $script:RxData.Matches($body)) {
            $name=$m.Groups[1].Value+$m.Groups[2].Value
            if (-not $name) { $name='Data'+$i }
            if ($data.Contains($name)) { $name=$name+'#'+$i }
            $v=$m.Groups[3].Value
            # Inline entity decoding: a function call per field costs more than the parse itself.
            if ($v.IndexOf('&') -ge 0) { $v=$v.Replace('&lt;','<').Replace('&gt;','>').Replace('&quot;','"').Replace('&apos;',"'").Replace('&amp;','&') }
            $data[$name]=$v
            $i++
        }
        if (-not $script:RxDataRest.IsMatch($script:RxData.Replace($body,''))) { return $null }
    }
    # System values contain no '&' (checked above), so no entity decoding is needed.
    $level='0'; $channel=''; $computer=''; $rid=''
    if ($items.ContainsKey('Level')) { $level=$items['Level'].Groups[3].Value; if (-not $level) { $level='0' } }
    if ($items.ContainsKey('Channel')) { $channel=$items['Channel'].Groups[3].Value }
    if ($items.ContainsKey('Computer')) { $computer=$items['Computer'].Groups[3].Value }
    if ($items.ContainsKey('EventRecordID')) { $rid=$items['EventRecordID'].Groups[3].Value }
    return New-EventRecord $provider $items['EventID'].Groups[3].Value $channel $computer $rid $level ($tm.Groups[1].Value+$tm.Groups[2].Value) $items['Keywords'].Groups[3].Value $data $XmlText ''
}
function Parse-Event([string]$XmlText) {
    $fast=Parse-EventFast $XmlText
    if ($null -ne $fast) { return $fast }
    return Parse-EventDom $XmlText
}
function Parse-EventDom([string]$XmlText) {
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
    $systemTime=$sys.TimeCreated.GetAttribute('SystemTime')
    $keywords = [string]$sys.Keywords
    $levelNode = $sys.SelectSingleNode('e:Level',$ns)
    $ridNode = $sys.SelectSingleNode('e:EventRecordID',$ns)
    $channelNode = $sys.SelectSingleNode('e:Channel',$ns)
    $computerNode = $sys.SelectSingleNode('e:Computer',$ns)
    $level = '0'; if ($levelNode) { $level = $levelNode.InnerText; if (-not $level) { $level='0' } }
    $rid = ''; if ($ridNode) { $rid = $ridNode.InnerText }
    $channel = ''; if ($channelNode) { $channel = $channelNode.InnerText }
    $computer = ''; if ($computerNode) { $computer = $computerNode.InnerText }
    $provider=$sys.Provider.GetAttribute('Name'); $idText=$sys.SelectSingleNode('e:EventID',$ns).InnerText
    return New-EventRecord $provider $idText $channel $computer $rid $level $systemTime $keywords $data $XmlText $recovery
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
        if ($r -and $e.Id -in @(4672,4648) -and (Field $d @('SubjectUserSid')) -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
            if (-not $IncludeNoise) { return }
            $r.Severity = 'Info'; $r.Note += ' Встроенная служебная учетная запись.'
        }
        # Computer accounts (NAME$) and Window Manager / font driver sessions (S-1-5-90-*, S-1-5-96-*) are not people.
        if ($r -and $e.Id -in @(4672,4648) -and -not $IncludeNoise -and ((Field $d @('SubjectUserName')).EndsWith('$') -or (Field $d @('SubjectUserSid')) -match '^S-1-5-(90|96)-')) { return }
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
        # 4624/4634 need LogonType, 4776 needs Status, 4672/4648 need SubjectUserSid: dedicated selectors below.
        $excludedSecurityIds=@(4624,4634,4776)
        if (-not $IncludeNoise) { $excludedSecurityIds+=@(4672,4648) }
        $ids = @($g.Group | Where-Object { $_.Provider -ne 'Microsoft-Windows-Security-Auditing' -or [int]$_.Id -notin $excludedSecurityIds } | ForEach-Object { [int]$_.Id })
        # Short selectors keep each XPath below Windows Event Log complexity limits.
        for ($i=0; $i -lt $ids.Count; $i+=8) {
            $last = [Math]::Min($i+7,$ids.Count-1)
            $parts = @($ids[$i..$last] | ForEach-Object { 'EventID=' + $_ })
            $selectors.Add("*[System[Provider[@Name='$($g.Name)'] and ($($parts -join ' or '))$time]]")
        }
    }
    $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4634)$time] and EventData[Data[@Name='LogonType']='10']]")
    if (-not $IncludeNoise) {
        # Built-in service accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) produce the bulk of 4672/4648.
        foreach ($sidId in @(4672,4648)) {
            if (-not $script:Rules.ContainsKey('Microsoft-Windows-Security-Auditing|'+$sidId)) { continue }
            $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=$sidId$time] and EventData[Data[@Name='SubjectUserSid']!='S-1-5-18' and Data[@Name='SubjectUserSid']!='S-1-5-19' and Data[@Name='SubjectUserSid']!='S-1-5-20']]")
        }
    }
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
    $f=$e.F
    $old=$f['OldTime']; $new=$f['NewTime']
    if ($old -and $new) {
        try { $delta=([DateTimeOffset]::Parse($new,$script:Invariant)-[DateTimeOffset]::Parse($old,$script:Invariant)).TotalSeconds.ToString('0.#######',$script:Invariant) } catch { $delta='Unparsed' }
    }
    # Table lookups instead of three Ru-* function calls per finding.
    $sevText=$script:RuSeverityMap[$r.Severity]; if ($null -eq $sevText) { $sevText=$r.Severity }
    $auditText=$script:RuAuditMap[$e.AuditOutcome]; if ($null -eq $auditText) { $auditText=$e.AuditOutcome }
    $msgText=$script:RuMessageMap[$e.MessageStatus]; if ($null -eq $msgText) { $msgText=$e.MessageStatus }
    Write-Row $script:FindingWriter @($id,$e.Id,$e.RecordId,$sevText,$r.Category,$r.Title,$r.Note,$e.TimeUtc,$e.Computer,
        $file.DirectoryName,$file.Name,$file.FullName,$e.Channel,$e.Provider,$e.Level,$auditText,
        $e.Subject,$f['SubjectUserSid'],$e.Target,$f['TargetSid'],
        $f['MemberName'],$f['MemberSid'],$e.SourceIP,$f['Port'],
        $f['Workstation'],$e.LogonType,$e.LogonId,
        $f['SubjectLogonId'],$f['SessionID'],$e.SessionName,
        $f['Status'],$f['SubStatus'],$f['Process'],
        $f['CommandLine'],$f['Privileges'],
        $f['Threat'],$f['Path'],
        $old,$new,$delta,$details,$message,$msgText,$r.RuleId,$e.Fingerprint,$e.XmlRecovery)
    if ($script:EvidenceWriter) {
        $script:EvidenceWriter.WriteLine(([ordered]@{FindingId=$id;SourceFile=$file.FullName;RuleId=$r.RuleId;
            Fingerprint=$e.Fingerprint;Xml=$e.Xml;Message=$e.Message;MessageStatus=$e.MessageStatus} | ConvertTo-Json -Depth 6 -Compress))
    }
    $key=$r.Severity+'|'+$r.Category+'|'+$e.Computer
    if (-not $script:Summary.ContainsKey($key)) { $script:Summary[$key]=[pscustomobject]@{Severity=$r.Severity;Category=$r.Category;Computer=$e.Computer;Count=0} }
    $script:Summary[$key].Count++
    return $id
}

# RDP intervals: conservative pairing inside ONE file.
#  Security: computer + Logon ID; start 4624 type 10 / 4778 (RDP-*), end 4634 / 4647 / 4779.
#  TerminalServices-LocalSessionManager: computer + Session ID; start 21 / 25 with a remote
#  address, end 23 (logoff) / 24 (disconnect).
# An end event right after an already closed interval (logoff after disconnect, 24 after 23)
# is a trailing event of the same session and does not create a "start not found" row.
$script:LsmProvider='Microsoft-Windows-TerminalServices-LocalSessionManager'
$script:RdpClosed=@{}
$script:RdpTotals=@{}
function Rdp-Key($e) { return $e.Computer.ToLowerInvariant()+'|'+$e.LogonId.ToLowerInvariant() }
function Format-Duration([double]$Seconds) {
    $ts=[TimeSpan]::FromSeconds([Math]::Round($Seconds))
    return ('{0}:{1:D2}:{2:D2}' -f [int][Math]::Floor($ts.TotalHours),$ts.Minutes,$ts.Seconds)
}
function Save-Rdp($start,$end,[string]$Status,[string]$Reason) {
    $script:RdpCount++
    $duration=''; $durationText=''; $endTime=''; $endRecord=''; $endId=''; $endEvent=''
    if ($end) { $endTime=$end.TimeUtc; $endRecord=$end.RecordId; $endId=$end.FindingId; $endEvent=$end.Id }
    $anchor=$end; if ($start) { $anchor=$start }
    if ($start -and $end -and $Status -eq 'Paired') {
        $seconds=($end.Ticks-$start.Ticks)/[TimeSpan]::TicksPerSecond
        if ($seconds -lt 0 -or $seconds -gt $MaxRdpHours*3600) { $Status='UncertainDuration'; $Reason='Отрицательная или слишком большая длительность; проверить часы/границы загрузки.' }
        else {
            $duration=$seconds.ToString('0.###',$script:Invariant); $durationText=Format-Duration $seconds
            $account=$start.Target; if (-not $account) { $account=$end.Target }
            $totalKey=($start.Computer+'|'+$account+'|'+$start.SourceIP+'|'+$start.Source).ToLowerInvariant()
            if (-not $script:RdpTotals.ContainsKey($totalKey)) {
                $script:RdpTotals[$totalKey]=[pscustomobject]@{Computer=$start.Computer;Account=$account;SourceIP=$start.SourceIP;Source=$start.Source;Count=0;Seconds=[double]0;Max=[double]0;First=$start.TimeUtc;Last=$end.TimeUtc}
            }
            $t=$script:RdpTotals[$totalKey]
            $t.Count++; $t.Seconds+=$seconds
            if ($seconds -gt $t.Max) { $t.Max=$seconds }
            if ([string]::CompareOrdinal($start.TimeUtc,$t.First) -lt 0) { $t.First=$start.TimeUtc }
            if ([string]::CompareOrdinal($end.TimeUtc,$t.Last) -gt 0) { $t.Last=$end.TimeUtc }
        }
    }
    $startTime=''; $startRecord=''; $startId=''; $startEvent=''
    if ($start) { $startTime=$start.TimeUtc; $startRecord=$start.RecordId; $startId=$start.FindingId; $startEvent=$start.Id }
    $ip=$anchor.SourceIP; if (-not $ip -and $start -and $end) { $ip=$end.SourceIP }
    Write-Row $script:RdpWriter @($startEvent,$endEvent,$anchor.File,$anchor.Computer,$anchor.Target,$anchor.LogonId,$ip,
        $startTime,$endTime,$duration,$durationText,(Ru-RdpStatus $Status),$Reason,$startRecord,$endRecord,$startId,$endId,$anchor.Source)
}
function Write-RdpTotals([string]$Path) {
    $w=New-Writer $Path
    try {
        Write-Row $w @('Компьютер','Учетная запись','IP источника','Источник данных','Сеансов (пар)','Суммарная длительность, сек','Суммарная длительность (ч:мм:сс)','Максимальный сеанс (ч:мм:сс)','Первое подключение UTC','Последнее отключение UTC','Комментарий')
        foreach ($t in (@($script:RdpTotals.Values) | Sort-Object -Property @('Computer','Account','SourceIP','Source'))) {
            Write-Row $w @($t.Computer,$t.Account,$t.SourceIP,$t.Source,$t.Count,$t.Seconds.ToString('0.###',$script:Invariant),(Format-Duration $t.Seconds),(Format-Duration $t.Max),$t.First,$t.Last,
                'Сумма только по парам «начало–конец» со статусом «Пара найдена». Security и TerminalServices описывают одни и те же сеансы разными событиями: не складывайте их строки.')
        }
    } finally { Close-Writer $w }
}
function Reset-Rdp($state,[string]$Computer,[string]$Reason) {
    foreach ($key in @($state.Keys)) {
        if (-not $Computer -or $state[$key].Computer -eq $Computer) {
            Save-Rdp $state[$key] $null 'MissingEnd' $Reason
            $state.Remove($key)
        }
    }
    $prefix=$Computer.ToLowerInvariant()+'|'
    foreach ($key in @($script:RdpClosed.Keys)) { if (-not $Computer -or $key.StartsWith($prefix)) { $script:RdpClosed.Remove($key) } }
}
function Handle-RdpPoint($state,[string]$Key,$Point,[bool]$IsStart,[bool]$ReportOrphan,[string]$PairReason) {
    if ($IsStart) {
        if ($state.ContainsKey($Key)) { Save-Rdp $state[$Key] $null 'MissingEnd' 'Новый вход/переподключение до найденного конца; прежний интервал не закрывается предположением.' }
        $state[$Key]=$Point
        $script:RdpClosed.Remove($Key)
    } elseif ($state.ContainsKey($Key)) {
        $start=$state[$Key]
        if ($start.Target -and $Point.Target -and $start.Target -ne $Point.Target) {
            Save-Rdp $start $null 'MissingEnd' 'Разные учетные записи при одинаковом идентификаторе сеанса.'
            Save-Rdp $null $Point 'MissingStart' 'Начало с подходящей учетной записью не найдено.'
        } else { Save-Rdp $start $Point 'Paired' $PairReason }
        $state.Remove($Key)
        $script:RdpClosed[$Key]=$true
    } elseif ($script:RdpClosed.ContainsKey($Key)) {
        return  # trailing end of an interval that is already closed
    } elseif ($ReportOrphan) { Save-Rdp $null $Point 'MissingStart' 'Начало в этом файле не найдено; выход после ранее зафиксированного отключения также возможен.' }
}
function Handle-Rdp($e,$state,[string]$File,[long]$FindingId) {
    if (($e.Provider -eq 'Microsoft-Windows-Security-Auditing' -and $e.Id -in @(4608,4616)) -or
        ($e.Provider -eq 'Microsoft-Windows-Eventlog' -and $e.Id -eq 1102)) {
        Reset-Rdp $state $e.Computer 'Запуск ОС, изменение часов или очистка журнала: пара не строится через эту границу.'
        return
    }
    if (-not $e.Computer) { return }
    if ($e.Provider -eq $script:LsmProvider) {
        $session=$e.F['SessionID']
        if (-not $session -or $e.Id -notin @(21,23,24,25)) { return }
        $address=$e.SourceIP
        $remote=$address -and $address -notin @('LOCAL','127.0.0.1','::1')
        $isStart=$e.Id -in @(21,25)
        if ($isStart -and -not $remote) { return }  # console / local session
        $key=$e.Computer.ToLowerInvariant()+'|lsm|'+$session
        $point=[pscustomobject]@{File=$File;Computer=$e.Computer;Target=$e.F['User'];LogonId=('Session '+$session);SourceIP=$address;
            TimeUtc=$e.TimeUtc;Ticks=$e.Ticks;RecordId=$e.RecordId;FindingId=$FindingId;Id=$e.Id;Source='TerminalServices-LocalSessionManager'}
        Handle-RdpPoint $state $key $point $isStart ($e.Id -eq 24 -and $remote) 'Интервал по TerminalServices-LocalSessionManager (Session ID): от входа/переподключения до выхода/отключения, не активность пользователя.'
        return
    }
    if ($e.Provider -ne 'Microsoft-Windows-Security-Auditing' -or -not $e.LogonId -or $e.LogonId -eq '0x0') { return }
    $key=Rdp-Key $e
    $isRdpName=$e.SessionName -match '^RDP-'
    $isStart=($e.Id -eq 4624 -and $e.LogonType -eq '10') -or ($e.Id -eq 4778 -and $isRdpName)
    $known=$state.ContainsKey($key) -or $script:RdpClosed.ContainsKey($key)
    # 4647 has no LogonType: it ends an interval only for a Logon ID already seen as RDP.
    $isEnd=($e.Id -eq 4634 -and ($e.LogonType -eq '10' -or $known)) -or ($e.Id -eq 4779 -and ($isRdpName -or $known)) -or ($e.Id -eq 4647 -and $known)
    if (-not $isStart -and -not $isEnd) { return }
    $point=[pscustomobject]@{File=$File;Computer=$e.Computer;Target=$e.Target;LogonId=$e.LogonId;SourceIP=$e.SourceIP;
        TimeUtc=$e.TimeUtc;Ticks=$e.Ticks;RecordId=$e.RecordId;FindingId=$FindingId;Id=$e.Id;Source='Security'}
    Handle-RdpPoint $state $key $point $isStart $true 'Интервал по Security; время между подключением и отключением/выходом, не активность пользователя.'
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
    if (-not $source -or $source -eq '-') { $source=$e.F['Workstation'] }
    if (-not $source) { $source='[unknown]' }
    $account=$e.Target; if (-not $account) { $account='[unknown]' }
    $spoolWriters[$partition].WriteLine(([ordered]@{Ticks=$e.Ticks;TimeUtc=$e.TimeUtc;Computer=$e.Computer;Scope=$scope;
        EventId=$e.Id;Account=$account;Source=$source;Fingerprint=$e.Fingerprint;FindingId=$FindingId;
        File=$file.FullName;RecordId=$e.RecordId;Status=$e.F['Status'];SubStatus=$e.F['SubStatus']} | ConvertTo-Json -Compress))
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
        Write-Row $script:RdpWriter @('StartEvent','EndEvent','File','Computer','Account','LogonId','Source','Start','End','Seconds','Duration','Status','Reason','StartRecord','EndRecord','StartFinding','EndFinding','DataSource')
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
# Excel layout: sheet order, numeric columns, widths, wrapping, hidden technical
# columns and priority colors. Kept separate from COM so SelfTest can check it.
$script:NumericHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Оценка риска','Связанных уникальных событий','Сценариев','Количество','Событий в окне','Разных УЗ',
    'Сеансов (пар)','Суммарная длительность, сек','Длительность, сек','Номер','Находок','Прочитано подходящих событий','Ошибок разбора','Нет описания Windows','Размер, байт','Время обработки, сек'))
$script:WideHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Хронология','Основание связи','Почему выделено','Что проверить','УЗ / объект / IP','Ссылки на находки и EVTX (до 10)',
    'Комментарий','Что это означает / что запросить','Что делать','Ограничения','Ошибка','Этапы (тактики)','Данные события','Описание Windows','Командная строка'))
$script:MediumHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Сценарий','Тактика','MITRE ATT&CK','Учетные записи','IP источника','IP источников','Компьютер','Событие','Категория',
    'Цепочка атаки','Инициатор','Целевая УЗ','Учетная запись','Файл источника','Папка источника','Полный путь','Процесс','Имя угрозы','Ресурс / путь'))
$script:HiddenFindingHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Папка источника','Полный путь','Канал','Уровень Windows','Статус описания','SHA256 XML события','Восстановление XML','Правило'))
function Read-CsvHeader([string]$Path) {
    $reader=New-Object IO.StreamReader($Path,[Text.Encoding]::UTF8,$true)
    try { $line=$reader.ReadLine() } finally { $reader.Dispose() }
    if (-not $line) { return @() }
    $quote='"'
    return @($line.Trim().Trim($quote) -split [regex]::Escape($quote+[string]$Delimiter+$quote))
}
function Get-ExcelSheetPlan([string]$WorkPath) {
    $plan=New-Object 'System.Collections.Generic.List[object]'
    $add={ param([string]$Name,[string]$Path,[string]$Kind)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $headers=Read-CsvHeader $Path
        $types=New-Object 'System.Collections.Generic.List[int]'; $widths=New-Object 'System.Collections.Generic.List[double]'
        $wrap=New-Object 'System.Collections.Generic.List[int]'; $hidden=New-Object 'System.Collections.Generic.List[int]'
        $priority=0
        for ($c=0; $c -lt $headers.Count; $c++) {
            $h=$headers[$c]
            if ($script:NumericHeaders.Contains($h)) { $types.Add(1) } else { $types.Add(2) }
            if ($script:WideHeaders.Contains($h)) { $widths.Add(60); $wrap.Add($c+1) } elseif ($script:MediumHeaders.Contains($h)) { $widths.Add(30) } else { $widths.Add(0) }
            if ($Kind -eq 'Findings' -and ($script:HiddenFindingHeaders.Contains($h) -or ($h -eq 'Описание Windows' -and -not $script:FormatMessages))) { $hidden.Add($c+1) }
            if ($h -eq 'Приоритет' -and $priority -eq 0) { $priority=$c+1 }
        }
        $plan.Add([pscustomobject]@{Name=$Name;Path=$Path;Kind=$Kind;Headers=$headers;Types=$types.ToArray();Widths=$widths.ToArray();Wrap=$wrap.ToArray();Hidden=$hidden.ToArray();PriorityColumn=$priority})
    }
    & $add 'Инциденты' (Join-Path $WorkPath 'Incidents.csv') 'Priority'
    & $add 'Приоритетные' (Join-Path $WorkPath 'Triage.csv') 'Priority'
    & $add 'Подбор_пароля' (Join-Path $WorkPath 'AuthBursts.csv') 'Severity'
    & $add 'RDP_итоги' (Join-Path $WorkPath 'RdpTotals.csv') 'Plain'
    & $add 'RDP_сеансы' (Join-Path $WorkPath 'RdpIntervals.csv') 'Plain'
    $parts=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'Findings-*.csv' -File | Sort-Object Name)
    for ($i=0; $i -lt $parts.Count; $i++) {
        $name='Находки'; if ($parts.Count -gt 1) { $name='Находки_'+($i+1) }
        & $add $name $parts[$i].FullName 'Findings'
    }
    & $add 'Сводка' (Join-Path $WorkPath 'Summary.csv') 'Severity'
    & $add 'Файлы' (Join-Path $WorkPath 'Files.csv') 'Plain'
    & $add 'Качество_выгрузки' (Join-Path $WorkPath 'Coverage.csv') 'Plain'
    & $add 'Ошибки' (Join-Path $WorkPath 'Errors.csv') 'Plain'
    $runSummary=New-RunSummaryCsv $WorkPath
    if ($runSummary) { & $add 'Запуск' $runSummary 'Plain' }
    return ,$plan
}
function Get-ColumnLetter([int]$Index) {
    $letters=''
    while ($Index -gt 0) { $m=($Index-1)%26; $letters=[char](65+$m)+$letters; $Index=[int][Math]::Floor(($Index-1)/26) }
    return $letters
}
function Add-ExcelPriorityColors($Sheet,$Item,[int]$Rows,[int]$Columns) {
    # Excel colors are BGR integers. Light red / light amber fills, dark text.
    $missing=[Reflection.Missing]::Value
    $col=Get-ColumnLetter $Item.PriorityColumn
    if ($Item.Kind -eq 'Priority') {
        $range=$Sheet.Range(('A2:'+(Get-ColumnLetter $Columns)+$Rows))
        foreach ($rule in @(@($script:P1,13551615,393372),@($script:P2,10284031,26012))) {
            $fc=$range.FormatConditions.Add(2,$missing,('=$'+$col+'2="'+$rule[0]+'"'))
            $fc.Interior.Color=$rule[1]; $fc.Font.Color=$rule[2]
        }
    } else {
        $range=$Sheet.Range(($col+'2:'+$col+$Rows))
        foreach ($rule in @(@((Ru-Severity 'High'),13551615,393372),@((Ru-Severity 'Medium'),10284031,26012))) {
            $fc=$range.FormatConditions.Add(1,3,('="'+$rule[0]+'"'))
            $fc.Interior.Color=$rule[1]; $fc.Font.Color=$rule[2]
        }
    }
}
function Export-ReportsToExcel([string]$WorkPath,[string]$XlsxPath) {
    $reports=Get-ExcelSheetPlan $WorkPath
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
            $item=$reports[$i]
            $sheet=$null; $cell=$null; $qt=$null; $used=$null
            try {
                $sheet=$book.Worksheets.Item($i+1)
                $sheet.Name=[string]$item.Name
                $cell=$sheet.Range('A1')
                $qt=$sheet.QueryTables.Add(('TEXT;'+[string]$item.Path),$cell)
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
                try { $qt.TextFileDecimalSeparator='.' } catch { }
                # Counts and scores are numbers (sortable, summable); everything else stays text.
                $types=@($item.Types); if ($types.Count -eq 0) { $types=@(2) }
                $qt.TextFileColumnDataTypes=[object[]]$types
                [void]$qt.Refresh($false)
                $qt.Delete()
                $qt=$null
                $used=$sheet.UsedRange
                $rowCount=[int]($used.Rows.Count); $colCount=[int]($used.Columns.Count)
                try {
                    $header=$sheet.Rows.Item(1)
                    $header.Font.Bold=$true; $header.WrapText=$true
                    $headerRange=$sheet.Range(('A1:'+(Get-ColumnLetter $colCount)+'1'))
                    $headerRange.Interior.Color=7949855; $headerRange.Font.Color=16777215
                } catch { }
                if ($rowCount -gt 0 -and $colCount -gt 0) {
                    try { [void]$used.AutoFilter() } catch { }
                    if ($rowCount -le 1000) { try { [void]$used.Columns.AutoFit() } catch { } }
                    for ($c=1; $c -le [Math]::Min($colCount,$item.Widths.Count); $c++) {
                        try {
                            $column=$sheet.Columns.Item($c)
                            $width=$item.Widths[$c-1]
                            if ($width -gt 0) { $column.ColumnWidth=$width }
                            elseif ($rowCount -gt 1000) { $column.ColumnWidth=16 }
                            elseif ($column.ColumnWidth -gt 40) { $column.ColumnWidth=40 }
                        } catch { }
                    }
                    if ($item.Kind -eq 'Priority' -and $rowCount -le 5000) {
                        foreach ($c in $item.Wrap) { try { $sheet.Columns.Item($c).WrapText=$true } catch { } }
                        try { $used.VerticalAlignment=-4160; [void]$used.Rows.AutoFit() } catch { } # xlTop
                    }
                    foreach ($c in $item.Hidden) { try { $sheet.Columns.Item($c).Hidden=$true } catch { } }
                    if ($item.PriorityColumn -gt 0 -and $rowCount -gt 1) { try { Add-ExcelPriorityColors $sheet $item $rowCount $colCount } catch { } }
                }
                try {
                    if ($item.Name -eq 'Инциденты') { $sheet.Tab.Color=255 } elseif ($item.Name -eq 'Приоритетные') { $sheet.Tab.Color=39423 }
                } catch { }
                try {
                    $sheet.Activate()
                    $excel.ActiveWindow.SplitColumn=0
                    if ($item.Kind -eq 'Priority') { $excel.ActiveWindow.SplitColumn=3 }
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
        $incidentPath=Join-Path $WorkPath 'Incidents.csv'
        if (Test-Path -LiteralPath $incidentPath) {
            foreach ($r in (Import-Csv -LiteralPath $incidentPath -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @(('Инцидент '+$r.'КИ'),$r.'Event ID',$r.'Приоритет',('Оценка '+$r.'Оценка риска'+'; '+$r.'Этапы (тактики)'),$r.'Компьютер',$r.'Начало UTC',$r.'Конец UTC',$r.'Учетные записи',$r.'IP источников','',$r.'Сценариев',$r.'Цепочка атаки',$r.'Папка источника',($r.'Хронология'+' | '+$r.'Что делать'))
            }
        }
        $triagePath=Join-Path $WorkPath 'Triage.csv'
        if (Test-Path -LiteralPath $triagePath) {
            Import-Csv -LiteralPath $triagePath -Delimiter $Delimiter -Encoding UTF8 | ForEach-Object {
                $r=$_
                Write-Row $w @(('Приоритетная находка '+$r.'КИ'),$r.'Event ID',$r.'Приоритет',($r.'Сценарий'+' ['+$r.'Оценка риска'+'; '+$r.'MITRE ATT&CK'+']'),$r.'Компьютер',$r.'Первое время UTC',$r.'Последнее время UTC',$r.'Учетные записи',$r.'IP источника','',$r.'Связанных уникальных событий','Кандидат',$r.'Папка источника',($r.'УЗ / объект / IP'+' | '+$r.'Основание связи'+' '+$r.'Почему выделено'+' '+$r.'Что проверить'+' '+$r.'Ссылки на находки и EVTX (до 10)'+' '+$r.'Ограничения'))
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
        $path=Join-Path $WorkPath 'RdpTotals.csv'
        if (Test-Path -LiteralPath $path) {
            foreach ($row in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('RDP итог','','Инфо','Суммарное время RDP',$row.'Компьютер',$row.'Первое подключение UTC',$row.'Последнее отключение UTC',$row.'Учетная запись',$row.'IP источника','',$row.'Сеансов (пар)','',$row.'Источник данных',('Суммарно: '+$row.'Суммарная длительность (ч:мм:сс)'+'; максимум: '+$row.'Максимальный сеанс (ч:мм:сс)'))
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
# v9.2 scenario catalog: risk score 0..100, tactic and MITRE ATT&CK technique.
# Priority is derived from the score: P1 >= 80, P2 >= 50, P3 below.
$script:P1='P1 — сначала'; $script:P2='P2 — проверить'; $script:P3='P3 — к сведению'
$script:ScenarioCatalog=@{}
foreach ($line in @(
    'Очистка журнала|90|Сокрытие следов|T1070.001 Clear Windows Event Logs|Очистка уничтожает предшествующие события; одна из типовых операций после компрометации.',
    'Потеря или переполнение журналирования|55|Сокрытие следов|T1562.002 Disable Windows Event Logging|Часть событий не записана; интервал неполноты нужно учитывать при расследовании.',
    'Журналирование остановлено без перезагрузки|75|Сокрытие следов|T1562.002 Disable Windows Event Logging|Служба журнала остановлена, а система продолжила работу: так отключают запись событий.',
    'Добавление в привилегированную группу|85|Повышение привилегий|T1098 Account Manipulation|Членство в административной группе дает полный контроль над системой или доменом.',
    'Выдан удаленный доступ (группа RDP/WinRM)|60|Закрепление|T1098 Account Manipulation|Добавление в Remote Desktop/Remote Management Users открывает удаленный вход.',
    'Изменение механизма аудита или политики безопасности|70|Обход защиты|T1562.002 Disable Windows Event Logging|Изменение аудита может скрыть последующие действия.',
    'Изменение политики аудита|65|Обход защиты|T1562.002 Disable Windows Event Logging|Отключение категорий аудита скрывает последующие действия.',
    'Служба удаленного выполнения (PsExec/Impacket)|95|Выполнение / боковое перемещение|T1569.002 Service Execution; T1021.002 SMB/Admin Shares|Служба запускает командный интерпретатор или пишет в административный общий ресурс — типичный след PsExec, Impacket smbexec/psexec, Cobalt Strike.',
    'Служба с нетипичными параметрами|65|Закрепление|T1543.003 Windows Service|Служба из нестандартного пути или с нетипичными параметрами — частый способ закрепления.',
    'Задание с рискованной командой|75|Закрепление / выполнение|T1053.005 Scheduled Task|Задание запускает интерпретатор или закодированную команду.',
    'Изменение SID History|90|Повышение привилегий|T1134.005 SID-History Injection|SID History позволяет получить права другой УЗ, в том числе администратора домена.',
    'Назначено опасное право пользователя|70|Повышение привилегий|T1134 Access Token Manipulation|Право позволяет обойти контроль доступа (отладка, резервное копирование, загрузка драйверов и т.п.).',
    'Выдано право входа по RDP|60|Закрепление|T1098 Account Manipulation|Право SeRemoteInteractiveLogonRight разрешает вход по RDP.',
    'Обнаружение угрозы Defender|75|Вредоносное ПО|T1204 User Execution|Defender обнаружил вредоносный объект; нужно убедиться, что угроза устранена и не запускалась.',
    'Ошибка устранения угрозы Defender|90|Вредоносное ПО|T1204 User Execution|Угроза обнаружена, но не устранена — объект может оставаться активным.',
    'Отключение компонентов защиты Defender|85|Обход защиты|T1562.001 Disable or Modify Tools|Отключение защиты в реальном времени — типовой шаг перед запуском ВПО.',
    'Добавлено исключение Defender|85|Обход защиты|T1562.001 Disable or Modify Tools|Исключение позволяет хранить и запускать ВПО без проверки.',
    'Попытка изменить Defender заблокирована|70|Обход защиты|T1562.001 Disable or Modify Tools|Tamper Protection остановила изменение настроек: кто-то пытался ослабить защиту.',
    'ASR заблокировал операцию|65|Выполнение|T1204 User Execution|Правило Attack Surface Reduction остановило подозрительное действие процесса.',
    'Отключение службы защиты или журналирования|85|Обход защиты|T1562.001 Disable or Modify Tools|Служба защиты или журналирования переведена в состояние «Отключена».',
    'Аварийная остановка службы защиты или журналирования|55|Обход защиты|T1562.001 Disable or Modify Tools|Неожиданная остановка службы защиты может быть сбоем или принудительным завершением.',
    'Sysmon: вмешательство в процесс|90|Обход защиты|T1055 Process Injection|Подмена образа процесса (Process Hollowing/Herpaderping) характерна для ВПО.',
    'Изменение конфигурации Sysmon|60|Обход защиты|T1562.001 Disable or Modify Tools|Изменение фильтров Sysmon может скрыть активность.',
    'Сторонний антивирус: признаки угрозы|70|Вредоносное ПО|T1204 User Execution|Продукт защиты сообщил об угрозе.',
    'Значительное изменение времени пользователем|60|Сокрытие следов|T1070.006 Timestomp|Перевод часов искажает хронологию событий.',
    'Потенциально опасная команда|75|Выполнение|T1059 Command and Scripting Interpreter|Команда удаляет следы, ослабляет защиту или загружает и исполняет код.',
    'RDP-вход с внешнего IP|70|Первоначальный доступ|T1133 External Remote Services; T1021.001 Remote Desktop Protocol|Успешный RDP-вход с публичного адреса: RDP опубликован в интернет или используется внешний доступ.',
    'Подбор пароля к УЗ|55|Доступ к учетным данным|T1110.001 Password Guessing|Серия отказов для одной УЗ с одного источника; бывает и из-за сохраненного старого пароля.',
    'Password spraying с одного источника|80|Доступ к учетным данным|T1110.003 Password Spraying|Отказы для многих разных УЗ с одного источника — признак перебора паролей.',
    'Массовая блокировка УЗ|80|Доступ к учетным данным|T1110.003 Password Spraying|Много разных УЗ заблокировано за короткое время — признак перебора паролей.',
    'Отказы RDP с неверным паролем → успешный вход|95|Первоначальный доступ|T1110 Brute Force → T1021.001 Remote Desktop Protocol|После серии неверных паролей с того же IP выполнен успешный RDP-вход — возможный успешный подбор.',
    'Новая УЗ получила привилегии|90|Закрепление / повышение привилегий|T1136.001 Create Local Account → T1098 Account Manipulation|Только что созданная УЗ сразу получила административные права.',
    'Новая УЗ → RDP-вход|85|Закрепление|T1136 Create Account → T1021.001 Remote Desktop Protocol|Только что созданная УЗ сразу использована для RDP-входа.',
    'Включение/сброс УЗ → RDP-вход|85|Закрепление / боковое перемещение|T1098 Account Manipulation → T1021.001 Remote Desktop Protocol|УЗ включена или ей сброшен пароль, после чего под ней сразу выполнен RDP-вход.',
    'Временная УЗ: создана и удалена|80|Закрепление / сокрытие следов|T1136 Create Account; T1070 Indicator Removal|УЗ существовала недолго — типично для временной УЗ злоумышленника.',
    'Изменение аудита → потеря/очистка журналирования|95|Сокрытие следов|T1562.002 → T1070.001|Та же сессия изменила аудит и затем очистила или потеряла журнал.',
    'Обнаружение угрозы → отключение защиты|95|Обход защиты|T1562.001 Disable or Modify Tools|После обнаружения угрозы защита на том же компьютере ослаблена.',
    'Локально добавлено правило Firewall|40|Обход защиты|T1562.004 Disable or Modify System Firewall|Новое правило может открыть порт; часто создается установщиками ПО.'
)) {
    $p=$line.Split('|')
    $script:ScenarioCatalog[$p[0]]=[pscustomobject]@{Score=[int]$p[1];Tactic=$p[2];Mitre=$p[3];Why=$p[4]}
}
# RDP session actions: Event ID -> text and score.
$script:RdpImpact=@{4697=@('создание службы',90);4698=@('создание задания',90);4702=@('изменение задания',85);4719=@('изменение политики аудита',90);
    4904=@('регистрация источника Security',85);4905=@('отмена источника Security',85);4906=@('изменение CrashOnAuditFail',85);4907=@('изменение параметров аудита объекта',85);
    4715=@('изменение SACL политики аудита',85);4739=@('изменение доменной политики',85);4946=@('добавление правила Firewall',70);4947=@('изменение правила Firewall',70);
    4948=@('удаление правила Firewall',70);4720=@('создание УЗ',90);4722=@('включение УЗ',85);4724=@('сброс пароля',85);4726=@('удаление УЗ',85);
    4728=@('добавление в глобальную группу',85);4732=@('добавление в локальную группу',85);4756=@('добавление в универсальную группу',85);
    4704=@('назначение права',85);4765=@('добавление SID History',95);4616=@('изменение времени',75);4648=@('вход с явными учетными данными',60);
    1102=@('очистка журнала Security',95);104=@('очистка журнала',95)}
function Get-PriorityFromScore([int]$Score) {
    if ($Score -ge 80) { return $script:P1 }
    if ($Score -ge 50) { return $script:P2 }
    return $script:P3
}
function Triage-IsPublicIp([string]$Ip) {
    # Public = globally routable. Private, loopback, link-local, CGNAT and documentation ranges are not.
    $value=Triage-NormalIp $Ip
    $addr=$null
    if (-not $value -or -not [Net.IPAddress]::TryParse($value,[ref]$addr)) { return $false }
    $b=$addr.GetAddressBytes()
    if ($b.Length -eq 4) {
        if ($b[0] -in @(0,10,127) -or $b[0] -ge 224) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
        if (($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 2) -or ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) { return $false }
        if ($b[0] -eq 198 -and $b[1] -in @(18,19)) { return $false }
        return $true
    }
    # IPv6: only global unicast 2000::/3, excluding documentation 2001:db8::/32.
    if (($b[0] -band 0xE0) -ne 0x20) { return $false }
    if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0d -and $b[3] -eq 0xb8) { return $false }
    return $true
}
function Add-Triage {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][hashtable]$Groups,
        [Parameter(Mandatory=$true)][string]$Priority,
        [Parameter(Mandatory=$true)][string]$Scenario,
        [Parameter(Mandatory=$true)][string]$Evidence,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Why,
        [Parameter(Mandatory=$true)][string]$Check,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Object,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][object[]]$Rows,
        [int]$Score=0,
        [string]$Tactic='',
        [string]$Mitre='',
        [string]$LastTime='',
        [long]$EventCount=0
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
    $catalog=$script:ScenarioCatalog[$Scenario]
    if ($catalog) {
        if ($Score -le 0) { $Score=$catalog.Score }
        if (-not $Tactic) { $Tactic=$catalog.Tactic }
        if (-not $Mitre) { $Mitre=$catalog.Mitre }
        if (-not $Why -or $Why -ceq $Evidence) { $Why=$catalog.Why }
    }
    if ($Score -gt 0) { $Score=[Math]::Min(100,$Score); $Priority=Get-PriorityFromScore $Score }
    $scope=Triage-Scope $firstRow
    $key=$Scenario+'|'+$scope+'|'+$Object
    if (-not $Groups.ContainsKey($key)) {
        $Groups[$key]=[pscustomobject]@{
            Priority=$Priority; Score=$Score; Tactic=$Tactic; Mitre=$Mitre; Scenario=$Scenario; Evidence=$Evidence; Why=$Why; Check=$Check; Object=$Object
            Computer=(Triage-Value $firstRow 'Компьютер'); Scope=(Triage-Value $firstRow 'Папка источника')
            First=''; Last=''; Seen=(New-Object 'System.Collections.Generic.HashSet[string]')
            Ids=(New-Object 'System.Collections.Generic.HashSet[string]'); Refs=(New-Object 'System.Collections.Generic.List[string]')
            Accounts=(New-Object 'System.Collections.Generic.List[string]'); Ips=(New-Object 'System.Collections.Generic.List[string]')
            Recovered=$false; EventCount=[long]0; Incident=''
        }
    }
    $g=$Groups[$key]
    if ($Score -gt $g.Score) { $g.Score=$Score; $g.Priority=$Priority }
    $g.EventCount+=$EventCount
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if (-not $g.Seen.Add((Triage-Key $r))) { continue }
        $time=Triage-Value $r 'Время UTC'
        if (-not $g.First -or [string]::CompareOrdinal($time,$g.First) -lt 0) { $g.First=$time }
        if (-not $g.Last -or [string]::CompareOrdinal($time,$g.Last) -gt 0) { $g.Last=$time }
        [void]$g.Ids.Add((Triage-Value $r 'Event ID'))
        if ($g.Refs.Count -lt 10) { [void]$g.Refs.Add(('Находка '+(Triage-Value $r 'Номер')+'; '+(Triage-Value $r 'Полный путь')+'; Record ID='+(Triage-Value $r 'Record ID'))) }
        if (Triage-Value $r 'Восстановление XML') { $g.Recovered=$true }
        $account=Triage-Value $r 'Целевая УЗ'
        if (-not $account) { $account=Triage-Value $r 'Инициатор' }
        foreach ($a in ($account -split ' \| ')) { if ($a -and $g.Accounts.Count -lt 10 -and -not $g.Accounts.Contains($a)) { $g.Accounts.Add($a) } }
        $ip=Triage-NormalIp (Triage-Value $r 'IP источника')
        if ((Triage-IsRemoteIp $ip) -and $g.Ips.Count -lt 10 -and -not $g.Ips.Contains($ip)) { $g.Ips.Add($ip) }
    }
    if ($LastTime -and [string]::CompareOrdinal($LastTime,$g.Last) -gt 0) { $g.Last=$LastTime }
}
$script:ProtectionServiceKeys='(?i)^(WinDefend|Sense|WdNisSvc|WdBoot|WdFilter|MpsSvc|EventLog|wscsvc|SecurityHealthService|Sysmon|Sysmon64|SysmonDrv)$'
$script:ProtectionServiceNames='(?i)(defender|антивирусн|event ?log|журнал(а)? событий|firewall|брандмауэр|security center|центр обеспечения безопасности|sysmon|sense)'
$script:DangerousPrivileges='(?i)(SeDebugPrivilege|SeTcbPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege|SeLoadDriverPrivilege|SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeCreateTokenPrivilege|SeEnableDelegationPrivilege|SeSecurityPrivilege|SeManageVolumePrivilege)'
$script:RemoteExecService='(?i)(%COMSPEC%|\bcmd(\.exe)?["'']?\s+/[ckqr]\b|\bpowershell|\bpwsh\b|\\\\127\.0\.0\.1\\|\\\\localhost\\|\\ADMIN\$|\\C\$\\|\\__output|\bPSEXESVC\b|\bRemComSvc\b|\bcsexec|\bwinexesvc\b|\brundll32\b|\bmshta\b|\bregsvr32\b|frombase64string|-enc(odedcommand)?\s)'
function Add-SingleTriage($Groups,$r) {
    $id=[int](Triage-Value $r 'Event ID'); $provider=Triage-Value $r 'Провайдер'
    $security=$provider -eq 'Microsoft-Windows-Security-Auditing'
    if ($security -and (Triage-Value $r 'Результат аудита') -eq (Ru-AuditOutcome 'Failure')) { return }
    $target=Triage-Value $r 'Целевая УЗ'; $data=Triage-Value $r 'Данные события'
    if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(1102,104)) {
        Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Очистка журнала' -Evidence 'Факт: EventLog зафиксировал очистку журнала.' -Why 'Факт: EventLog зафиксировал очистку журнала.' -Check 'Установить инициатора, очищенный журнал, основание, соседние операции и полноту выгрузки.' -Object ((Triage-Value $r 'Инициатор')+' | '+$data) -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(1101,1104,1108)) {
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Потеря или переполнение журналирования' -Evidence 'Факт: EventLog сообщил о потере, заполнении или ошибке приема событий.' -Why 'Факт: EventLog сообщил о потере, заполнении или ошибке приема событий.' -Check 'Определить интервал неполноты, причину, размер журналов и наличие централизованной копии.' -Object ((Triage-Value $r 'Событие')+' | '+$data) -Rows @($r)
    }
    if ($security -and $id -in @(4728,4732,4756)) {
        $groupSid=Triage-Value $r 'SID целевой УЗ'
        if (Is-PrivilegedGroup $groupSid) {
            Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Добавление в привилегированную группу' -Evidence 'Факт: SID группы относится к известной административной группе.' -Why 'Факт: SID группы относится к известной административной группе.' -Check 'Проверить заявку, инициатора, SID участника и последующие действия этой УЗ.' -Object ((Triage-Value $r 'SID участника')+' -> '+$groupSid) -Rows @($r)
        } elseif ($groupSid -in @('S-1-5-32-555','S-1-5-32-580')) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Выдан удаленный доступ (группа RDP/WinRM)' -Evidence 'Факт: участник добавлен в Remote Desktop Users (S-1-5-32-555) или Remote Management Users (S-1-5-32-580).' -Why '' -Check 'Проверить заявку, инициатора, участника и последующие удаленные входы этой УЗ.' -Object ((Triage-Value $r 'SID участника')+' -> '+$groupSid) -Rows @($r)
        }
    }
    if ($security -and $id -in @(4904,4905,4906,4907,4739,4715)) {
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Изменение механизма аудита или политики безопасности' -Evidence 'Факт: зарегистрировано изменение источника Security, CrashOnAuditFail, SACL политики аудита, параметров аудита объекта или доменной политики.' -Why 'Факт: зарегистрировано изменение источника Security, CrashOnAuditFail, SACL политики аудита, параметров аудита объекта или доменной политики.' -Check 'Проверить инициатора, точное старое/новое значение, заявку и последующие потери журналов.' -Object ((Triage-Value $r 'Инициатор')+' | '+$data) -Rows @($r)
    }
    if ($security -and $id -eq 4719) {
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Изменение политики аудита' -Evidence 'Факт: Windows сообщает об изменении политики аудита; само по себе оно может быть плановым.' -Why 'Факт: Windows сообщает об изменении политики аудита; само по себе оно может быть плановым.' -Check 'Проверить категорию/подкатегорию, Success/Failure, инициатора, Logon ID и основание изменения.' -Object ((Triage-Value $r 'Инициатор')+' | '+$data) -Rows @($r)
    }
    if ($security -and $id -eq 4946) {
        Add-Triage -Groups $Groups -Priority $script:P3 -Scenario 'Локально добавлено правило Firewall' -Evidence 'Факт: это локальное добавление правила; событие 4946 не возникает при добавлении через GPO.' -Why '' -Check 'Проверить имя правила, профиль, направление, адреса/порты и согласование.' -Object (Triage-DataValue $r @('RuleName','RuleId')) -Rows @($r)
    }
    if ((($security -and $id -eq 4697) -or ($provider -eq 'Service Control Manager' -and $id -eq 7045))) {
        $image=Triage-DataValue $r @('ServiceFileName','ImagePath','BinaryPathName')
        $serviceName=Triage-DataValue $r @('ServiceName')
        if (($image+' '+$serviceName) -match $script:RemoteExecService) {
            Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Служба удаленного выполнения (PsExec/Impacket)' -Evidence ('Факт: путь службы содержит «'+$Matches[0]+'».') -Why '' -Check 'Установить, с какого узла и под какой УЗ создана служба (соседние 4624 тип 3 / 4648), что исполнялось, и проверить узел-источник.' -Object ($serviceName+' | '+$image) -Rows @($r)
        } else {
            $risk=Get-ServiceRisk $r
            if ($risk.HasRisk) {
                Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Служба с нетипичными параметрами' -Evidence ('Эвристика по полям службы: '+$risk.Evidence+'.') -Why ('Эвристика по полям службы: '+$risk.Evidence+'.') -Check 'Проверить путь, подпись, тип и запуск службы, учетную запись, владельца ПО и заявку.' -Object $risk.Object -Rows @($r)
            }
        }
    }
    if ((($security -and $id -in @(4698,4702)) -or ($provider -eq 'Microsoft-Windows-TaskScheduler' -and $id -in @(106,140)))) {
        $risk=Get-TaskRisk $r
        if ($risk.HasRisk) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Задание с рискованной командой' -Evidence ('Эвристика по содержимому задания: '+$risk.Evidence+'.') -Why ('Эвристика по содержимому задания: '+$risk.Evidence+'.') -Check 'Открыть полное XML задания, проверить команду, триггер, учетную запись выполнения, путь и заявку.' -Object $risk.Object -Rows @($r)
        }
    }
    if ($security -and $id -in @(4765,4766)) {
        Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Изменение SID History' -Evidence ('Факт: событие '+$id+' — добавление SID History (4766 — неудачная попытка).') -Why '' -Check 'Проверить целевую УЗ, добавляемый SID, инициатора; SID History вне миграции домена почти всегда злонамерен.' -Object ($target+' | '+(Triage-DataValue $r @('SidHistory','SourceSid'))) -Rows @($r)
    }
    if ($security -and $id -eq 4704) {
        $privileges=Triage-Value $r 'Привилегии'
        if ($privileges -match $script:DangerousPrivileges) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Назначено опасное право пользователя' -Evidence ('Факт: назначено право '+$Matches[0]+'.') -Why '' -Check 'Проверить, кому выдано право (TargetSid), инициатора и основание изменения.' -Object ((Triage-Value $r 'SID целевой УЗ')+' | '+$privileges) -Rows @($r)
        }
    }
    if ($security -and $id -eq 4717 -and (Triage-Value $r 'Привилегии') -match 'SeRemoteInteractiveLogonRight') {
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Выдано право входа по RDP' -Evidence 'Факт: учетной записи предоставлено SeRemoteInteractiveLogonRight.' -Why '' -Check 'Проверить, кому выдано право, инициатора и последующие RDP-входы.' -Object (Triage-Value $r 'SID целевой УЗ') -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Windows Defender') {
        if ($id -in @(1006,1015,1116,1008,1118,1119,5001,5010,5012)) {
            $scenario='Обнаружение угрозы Defender'
            if ($id -in @(1008,1118,1119)) { $scenario='Ошибка устранения угрозы Defender' }
            if ($id -in @(5001,5010,5012)) { $scenario='Отключение компонентов защиты Defender' }
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario $scenario -Evidence ('Факт: Defender, событие '+$id+'.') -Why '' -Check 'Сопоставить обнаружение с действием, проверить объект, процесс, пользователя, исключения и состояние защиты.' -Object ((Triage-Value $r 'Имя угрозы')+' | '+(Triage-Value $r 'Ресурс / путь')) -Rows @($r)
        }
        if ($id -eq 5007) {
            $newValue=Triage-DataValue $r @('New Value','NewValue')
            if ($newValue -match '(?i)\\Exclusions\\') {
                Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Добавлено исключение Defender' -Evidence 'Факт: в настройках Defender появилось исключение (путь, расширение или процесс).' -Why '' -Check 'Проверить исключенный объект, кто и когда его добавил (GPO/Intune/локально), и что находится по этому пути.' -Object $newValue -Rows @($r)
            } elseif ($newValue -match '(?i)\\(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableOnAccessProtection|DisableScanOnRealtimeEnable|DisableAntiSpyware|DisableAntiVirus)\s*=\s*0x0*1\b') {
                Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Отключение компонентов защиты Defender' -Evidence ('Факт: параметр '+$Matches[1]+' включен (защита выключена).') -Why '' -Check 'Проверить, кто изменил параметр (GPO/локально), длительность и действия в этот период.' -Object $newValue -Rows @($r)
            }
        }
        if ($id -eq 5013) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Попытка изменить Defender заблокирована' -Evidence 'Факт: Tamper Protection заблокировала изменение настройки Defender.' -Why '' -Check 'Установить процесс и пользователя, пытавшихся изменить настройку, и что происходило рядом по времени.' -Object $data -Rows @($r)
        }
        if ($id -eq 1121) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'ASR заблокировал операцию' -Evidence 'Факт: правило Attack Surface Reduction заблокировало операцию.' -Why '' -Check 'Проверить правило (ID), процесс, путь и пользователя; ложные срабатывания на легитимном ПО возможны.' -Object ((Triage-DataValue $r @('Process Name','ProcessName'))+' | '+(Triage-DataValue $r @('Path'))) -Rows @($r)
        }
    }
    if ($provider -eq 'Service Control Manager' -and $id -eq 7040) {
        $key=Triage-DataValue $r @('param4'); $display=Triage-DataValue $r @('param1'); $newType=Triage-DataValue $r @('param3')
        if ($newType -match '(?i)disabled|отключ' -and ($key -match $script:ProtectionServiceKeys -or $display -match $script:ProtectionServiceNames)) {
            Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Отключение службы защиты или журналирования' -Evidence ('Факт: тип запуска службы «'+$display+'» изменен на «'+$newType+'».') -Why '' -Check 'Установить инициатора (соседние события, 4624/4688), вернуть службу и проверить период, когда она была отключена.' -Object ($display+' | '+$key) -Rows @($r)
        }
    }
    if ($provider -eq 'Service Control Manager' -and $id -in @(7031,7034)) {
        $display=Triage-DataValue $r @('param1')
        if ($display -match $script:ProtectionServiceNames) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Аварийная остановка службы защиты или журналирования' -Evidence ('Факт: служба «'+$display+'» неожиданно завершилась.') -Why '' -Check 'Проверить повторяемость, соседние ошибки и действия пользователей рядом по времени.' -Object $display -Rows @($r)
        }
    }
    if ($provider -eq 'Microsoft-Windows-Sysmon' -and $id -eq 25) {
        Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Sysmon: вмешательство в процесс' -Evidence 'Факт: Sysmon сообщил о ProcessTampering; событие ориентировано на техники скрытия/изменения процесса.' -Why 'Факт: Sysmon сообщил о ProcessTampering; событие ориентировано на техники скрытия/изменения процесса.' -Check 'Проверить исходный и целевой процессы, подписи, хеши, родителя и контекст EDR.' -Object ((Triage-DataValue $r @('Image','SourceImage'))+' -> '+(Triage-DataValue $r @('TargetImage'))) -Rows @($r)
    }
    if ($provider -eq 'Microsoft-Windows-Sysmon' -and $id -eq 16) {
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Изменение конфигурации Sysmon' -Evidence 'Факт: Sysmon сообщил об изменении собственной конфигурации.' -Why 'Факт: Sysmon сообщил об изменении собственной конфигурации.' -Check 'Сверить конфигурацию, инициатора и изменения фильтров с эталоном и заявкой.' -Object (Triage-DataValue $r @('Configuration','ConfigurationFileHash')) -Rows @($r)
    }
    if ((Triage-Value $r 'Правило') -eq 'AV-VENDOR-THREAT') {
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Сторонний антивирус: признаки угрозы' -Evidence 'Эвристика нашла признаки угрозы в XML/описании; это не подтверждение заражения.' -Why 'Эвристика нашла признаки угрозы в XML/описании; это не подтверждение заражения.' -Check 'Проверить точный смысл события продукта, объект и результат лечения в полном описании.' -Object ((Triage-Value $r 'Провайдер')+' | '+(Triage-Value $r 'Имя угрозы')+' | '+(Triage-Value $r 'Ресурс / путь')) -Rows @($r)
    }
    if ($security -and $id -eq 4616) {
        $delta=0.0; $sid=Triage-Value $r 'SID инициатора'
        if ($sid -and -not (Triage-IsServiceSid $sid) -and [double]::TryParse((Triage-Value $r 'Сдвиг времени, сек'),[Globalization.NumberStyles]::Float,$script:Invariant,[ref]$delta) -and [Math]::Abs($delta) -ge 300) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Значительное изменение времени пользователем' -Evidence 'Факт: сдвиг не менее 5 минут; инициатор не служебная УЗ.' -Why 'Факт: сдвиг не менее 5 минут; инициатор не служебная УЗ.' -Check 'Проверить старое и новое время, процесс и согласованную корректировку часов.' -Object (Triage-Value $r 'Инициатор') -Rows @($r)
        }
    }
    if ((Triage-Value $r 'Правило') -eq 'HEURISTIC-COMMAND') {
        $command=(Triage-Value $r 'Командная строка')+' '+$data
        if ($command -match '(?i)(wevtutil\s+(cl|clear-log)\b|Clear-EventLog\b|vssadmin\s+delete\s+shadows|Set-MpPreference\b.{0,120}-Disable\w+\s+\$true|Add-MpPreference\b.{0,120}-Exclusion)' -or ($command -match '(?i)DownloadString' -and $command -match '(?i)\b(IEX|Invoke-Expression)\b')) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Потенциально опасная команда' -Evidence 'Эвристика: признаки удаления следов, ослабления защиты либо загрузки и исполнения кода. Текст мог быть цитатой.' -Why 'Эвристика: признаки удаления следов, ослабления защиты либо загрузки и исполнения кода. Текст мог быть цитатой.' -Check 'Прочитать команду и полный ScriptBlock в EVTX; установить родительский процесс, автора и результат исполнения.' -Object ((Triage-Value $r 'Инициатор')+' | '+(Triage-Value $r 'Процесс')) -Rows @($r)
        }
    }
    # Successful RDP from a globally routable address (Security 4624 type 10 or RemoteConnectionManager 1149).
    $rdpLogon=($security -and $id -eq 4624 -and (Triage-Value $r 'Тип входа') -eq '10') -or ($provider -eq 'Microsoft-Windows-TerminalServices-RemoteConnectionManager' -and $id -eq 1149)
    if ($rdpLogon) {
        $ip=Triage-NormalIp (Triage-Value $r 'IP источника')
        if (Triage-IsPublicIp $ip) {
            $who=$target; if (-not $who) { $who=Triage-DataValue $r @('Param1','User') }
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'RDP-вход с внешнего IP' -Evidence ('Факт: успешная RDP-аутентификация/вход с публичного адреса '+$ip+'.') -Why '' -Check 'Проверить владельца IP (whois/геолокация), ожидаемость удаленного доступа для этой УЗ, VPN/шлюз и действия в сеансе (лист RDP_сеансы).' -Object ($who+' | '+$ip) -Rows @($r)
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
    $lockouts=New-Object 'System.Collections.Generic.Queue[object]'; $lastLockoutAlert=[long]0
    $lastThreat=$null; $logStop=$null
    $windowTicks=[long]$TriageWindowMinutes*[TimeSpan]::TicksPerMinute
    $failureWindowTicks=[long]$WindowMinutes*[TimeSpan]::TicksPerMinute
    $dayTicks=[TimeSpan]::TicksPerDay
    $orderedRows=@($Rows | Sort-Object @{Expression={[DateTimeOffset]::Parse($_.'Время UTC',$script:Invariant).UtcDateTime.Ticks}},@{Expression={$_.'Полный путь'}},@{Expression={[long]$_.'Record ID'}})
    Add-PasswordSuccessTriage $Groups $orderedRows
    foreach ($r in $orderedRows) {
        $id=[int]$r.'Event ID'; $provider=$r.'Провайдер'; $time=[DateTimeOffset]::Parse($r.'Время UTC',$script:Invariant)
        $ticks=$time.UtcDateTime.Ticks
        $isSecurity=$provider -eq 'Microsoft-Windows-Security-Auditing'
        # Boot markers: a log-service stop followed by a boot is a normal shutdown.
        if (($isSecurity -and $id -eq 4608) -or ($provider -eq 'EventLog' -and $id -in @(6005,6006))) { $logStop=$null }
        if ($isSecurity -and $id -in @(4608,4616)) { $created.Clear(); $opened.Clear(); $rdp.Clear(); $audit.Clear(); continue }
        # WMI correlation remains disabled as previously agreed. Raw Sysmon
        # 19/20/21 findings are retained for manual review.
        if ($provider -eq 'Microsoft-Windows-Sysmon') { continue }
        if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -eq 1100) { $logStop=$r; continue }
        if ($null -ne $logStop -and $isSecurity) {
            $gap=$ticks-[DateTimeOffset]::Parse($logStop.'Время UTC',$script:Invariant).UtcDateTime.Ticks
            if ($gap -ge 0 -and $gap -le $windowTicks) {
                Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Журналирование остановлено без перезагрузки' -Evidence ('Связь: после 1100 (служба журнала остановлена) через '+[Math]::Round($gap/[TimeSpan]::TicksPerSecond)+' сек. записано событие '+$id+' без события загрузки 4608/6005.') -Why '' -Check 'Проверить, была ли перезагрузка (System.evtx: 6005/6006/6008, Kernel-General 12/13), кто остановил службу и что происходило в промежутке.' -Object ($logStop.'Record ID') -Rows @($logStop,$r)
            }
            $logStop=$null
        }
        if ($provider -eq 'Microsoft-Windows-Windows Defender') {
            if ($id -in @(1006,1015,1116,1117)) { $lastThreat=$r; continue }
            $weakened=$id -in @(5001,5010,5012)
            if ($id -eq 5007) { $weakened=(Triage-DataValue $r @('New Value','NewValue')) -match '(?i)\\Exclusions\\|\\Disable\w+\s*=\s*0x0*1\b' }
            if ($weakened -and $null -ne $lastThreat) {
                $delta=($time-[DateTimeOffset]::Parse($lastThreat.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -ge 0 -and $delta -le [Math]::Max($TriageWindowMinutes,60)) {
                    Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Обнаружение угрозы → отключение защиты' -Evidence ('Связь: обнаружение Defender, затем через '+[Math]::Round($delta,1)+' мин. ослабление защиты (событие '+$id+') на том же компьютере.') -Why '' -Check 'Проверить угрозу, кто отключил защиту или добавил исключение, и запускался ли обнаруженный объект.' -Object ((Triage-Value $lastThreat 'Имя угрозы')+' | '+$lastThreat.'Record ID') -Rows @($lastThreat,$r)
                }
            }
            continue
        }
        if ($isSecurity -and $r.'Результат аудита' -ne (Ru-AuditOutcome 'Success')) { continue }
        if ($isSecurity) {
            if ($id -eq 4720 -and (Triage-ValidSid $r.'SID целевой УЗ')) { $created[$r.'SID целевой УЗ']=$r }
            if ($id -in @(4722,4724) -and (Triage-ValidSid $r.'SID целевой УЗ')) { $opened[$r.'SID целевой УЗ']=$r }
            if ($id -eq 4726 -and (Triage-ValidSid $r.'SID целевой УЗ') -and $created.ContainsKey($r.'SID целевой УЗ')) {
                $start=$created[$r.'SID целевой УЗ']; $life=$ticks-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant).UtcDateTime.Ticks
                if ($life -ge 0 -and $life -le $dayTicks) {
                    Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Временная УЗ: создана и удалена' -Evidence ('Строго: SID созданной и удаленной УЗ совпал; УЗ существовала '+(Format-Duration ($life/[TimeSpan]::TicksPerSecond))+'.') -Why '' -Check 'Установить, кто создал и удалил УЗ, и все действия этой УЗ между созданием и удалением (входы, RDP, службы, задания).' -Object ($r.'SID целевой УЗ'+' | '+$r.'Целевая УЗ') -Rows @($start,$r)
                }
            }
            if ($id -eq 4740) {
                $lockouts.Enqueue($r)
                while ($lockouts.Count -gt 0 -and [DateTimeOffset]::Parse($lockouts.Peek().'Время UTC',$script:Invariant).UtcDateTime.Ticks -lt ($ticks-$failureWindowTicks)) { [void]$lockouts.Dequeue() }
                $accounts=@($lockouts.ToArray() | ForEach-Object { ([string]$_.'Целевая УЗ').ToLowerInvariant() } | Select-Object -Unique)
                if ($accounts.Count -ge $SprayUserThreshold -and ($lastLockoutAlert -eq 0 -or ($ticks-$lastLockoutAlert) -ge $failureWindowTicks)) {
                    $lastLockoutAlert=$ticks
                    Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Массовая блокировка УЗ' -Evidence ('Связь: заблокировано '+$accounts.Count+' разных УЗ за '+$WindowMinutes+' мин.') -Why '' -Check 'Найти источник блокировок (поле Caller Computer Name / рабочая станция в 4740 и отказы 4625/4771/4776), проверить его и сбросить пароли затронутых УЗ.' -Object ('Блокировки с '+[DateTimeOffset]::Parse($lockouts.Peek().'Время UTC',$script:Invariant).UtcDateTime.ToString('yyyy-MM-dd HH:mm',$script:Invariant)) -Rows $lockouts.ToArray()
                }
                continue
            }
            if ($id -in @(4728,4732,4756) -and (Is-PrivilegedGroup $r.'SID целевой УЗ') -and $r.'SID участника' -and $created.ContainsKey($r.'SID участника')) {
                $start=$created[$r.'SID участника']; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -gt 0 -and $delta -le $TriageWindowMinutes) {
                    Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Новая УЗ получила привилегии' -Evidence ('Строго: SID созданной УЗ совпал с SID участника группы; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: SID созданной УЗ совпал с SID участника группы; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить, согласованы ли создание и выдача прав. Это цепочка действий, не доказательство атаки.' -Object ($r.'SID участника'+' | '+$start.'Record ID') -Rows @($start,$r)
                }
            }
            if ($id -in @(4634,4647)) {
                $ended=Triage-LogonId $r 'Logon ID цели'
                if ($ended) { $rdp.Remove($ended) }
                continue
            }
            $logon=Triage-LogonId $r 'Logon ID цели'
            if ($id -eq 4624 -and $r.'Тип входа' -eq '10' -and $logon) {
                $rdp[$logon]=$r
                $sid=$r.'SID целевой УЗ'
                if ((Triage-ValidSid $sid) -and $opened.ContainsKey($sid)) {
                    $start=$opened[$sid]; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                    if ($delta -ge 0 -and $delta -le $TriageWindowMinutes) {
                        Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Включение/сброс УЗ → RDP-вход' -Evidence ('Строго: SID УЗ совпал; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: SID УЗ совпал; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить законность включения/сброса, владельца УЗ, источник RDP и последующие действия.' -Object ($sid+' | '+$start.'Record ID') -Rows @($start,$r)
                    }
                }
                if ((Triage-ValidSid $sid) -and $created.ContainsKey($sid)) {
                    $start=$created[$sid]; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                    if ($delta -ge 0 -and $delta -le $TriageWindowMinutes) {
                        Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Новая УЗ → RDP-вход' -Evidence ('Строго: SID созданной УЗ совпал с SID RDP-входа; интервал '+[Math]::Round($delta,1)+' мин.') -Why '' -Check 'Проверить, кто создал УЗ, источник RDP (IP) и действия в сеансе.' -Object ($sid+' | '+$start.'Record ID') -Rows @($start,$r)
                    }
                }
            }
            if ($id -in @(4719,4904,4905,4906,4907,4739,4715)) {
                $actor=Triage-ActorKey $r
                if ($actor) { $audit[$actor]=$r }
            }
        }
        # Action performed inside a live RDP session (same Logon ID and SID as 4624 type 10).
        if ($script:RdpImpact.ContainsKey($id) -and ($isSecurity -or ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1102)))) {
            $actorLogon=Triage-LogonId $r 'Logon ID инициатора'
            if ($actorLogon -and $rdp.ContainsKey($actorLogon)) {
                $start=$rdp[$actorLogon]; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -gt 0 -and $delta -le $TriageWindowMinutes -and (Triage-ValidSid $start.'SID целевой УЗ') -and $start.'SID целевой УЗ' -eq $r.'SID инициатора') {
                    $impact=$script:RdpImpact[$id]
                    Add-Triage -Groups $Groups -Priority $script:P1 -Scenario ('RDP-сеанс: '+$impact[0]) -Evidence ('Строго: успешный RDP типа 10 связан с действием по одному Logon ID и SID; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: успешный RDP типа 10 связан с действием по одному Logon ID и SID; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить источник RDP, владельца УЗ, объект изменения, заявку и полную временную линию сеанса.' -Object ($actorLogon+' | '+$id) -Rows @($start,$r) -Score $impact[1] -Tactic 'Удаленный доступ → действие в сеансе' -Mitre 'T1021.001 Remote Desktop Protocol'
                }
            }
        }
        if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1101,1102,1104,1108)) {
            $actor=Triage-ActorKey $r
            if ($actor -and $audit.ContainsKey($actor)) {
                $start=$audit[$actor]; $delta=($time-[DateTimeOffset]::Parse($start.'Время UTC',$script:Invariant)).TotalMinutes
                if ($delta -ge 0 -and $delta -le $TriageWindowMinutes) {
                    Add-Triage -Groups $Groups -Priority $script:P1 -Scenario 'Изменение аудита → потеря/очистка журналирования' -Evidence ('Строго: одинаковые SID и Logon ID; интервал до '+$TriageWindowMinutes+' мин.') -Why ('Строго: одинаковые SID и Logon ID; интервал до '+$TriageWindowMinutes+' мин.') -Check 'Проверить точные параметры аудита, очищенный/переполненный журнал, инициатора, причину и внешнюю копию логов.' -Object ($actor+' | '+$start.'Record ID') -Rows @($start,$r)
                }
            }
        }
        if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1102)) { $created.Clear(); $opened.Clear(); $rdp.Clear(); $audit.Clear() }
    }
}
function Test-TriageCandidate($r) {
    $id=[int]$r.'Event ID'; $provider=$r.'Провайдер'
    if ($provider -eq 'Microsoft-Windows-Security-Auditing' -and $id -in @(4608,4616,4624,4625,4634,4647,4648,4715,4697,4698,4702,4704,4719,4720,4722,4723,4724,4726,4728,4732,4739,4740,4756,4765,4904,4905,4906,4907,4946,4947,4948,4950,4954)) { return $true }
    if ($provider -eq 'Microsoft-Windows-Eventlog' -and $id -in @(104,1100,1101,1102,1104,1108)) { return $true }
    if ($provider -eq 'EventLog' -and $id -in @(6005,6006)) { return $true }
    if ($provider -eq 'Microsoft-Windows-Windows Defender' -and $id -in @(1006,1015,1116,1117,5001,5007,5010,5012)) { return $true }
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
function Format-UtcText([string]$Iso) {
    if (-not $Iso) { return '' }
    try { return [DateTimeOffset]::Parse($Iso,$script:Invariant).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss',$script:Invariant) } catch { return $Iso }
}
function Format-LocalText([string]$Iso) {
    if (-not $Iso) { return '' }
    try { return [TimeZoneInfo]::ConvertTimeFromUtc([DateTimeOffset]::Parse($Iso,$script:Invariant).UtcDateTime,$script:DisplayTz).ToString('yyyy-MM-dd HH:mm:ss',$script:Invariant) } catch { return '' }
}
function Get-IsoTicks([string]$Iso) {
    if (-not $Iso) { return [long]0 }
    return [DateTimeOffset]::Parse($Iso,$script:Invariant).UtcDateTime.Ticks
}
function Build-Incidents($Groups) {
    # Incident = priority rows of one folder+computer whose time ranges are within
    # -IncidentGapHours of each other. Several different scenarios on one host in a
    # short time are typical of an attack chain, so such incidents are escalated.
    $gapTicks=[long]$IncidentGapHours*[TimeSpan]::TicksPerHour
    $incidents=New-Object 'System.Collections.Generic.List[object]'
    $byScope=@{}
    foreach ($g in @($Groups.Values)) {
        $scope=($g.Scope+'|'+$g.Computer).ToLowerInvariant()
        if (-not $byScope.ContainsKey($scope)) { $byScope[$scope]=New-Object 'System.Collections.Generic.List[object]' }
        $byScope[$scope].Add($g)
    }
    foreach ($scope in ($byScope.Keys | Sort-Object)) {
        $current=$null
        foreach ($g in ($byScope[$scope] | Sort-Object @{Expression={Get-IsoTicks $_.First}},Scenario)) {
            $first=Get-IsoTicks $g.First; $last=Get-IsoTicks $g.Last
            if ($null -eq $current -or $first -gt ($current.LastTicks+$gapTicks)) {
                $current=[pscustomobject]@{Id='';Groups=(New-Object 'System.Collections.Generic.List[object]');FirstTicks=$first;LastTicks=$last;First=$g.First;Last=$g.Last;Computer=$g.Computer;Scope=$g.Scope;Score=0;Priority=$script:P3;Chain=$false}
                $incidents.Add($current)
            }
            $current.Groups.Add($g)
            if ($last -gt $current.LastTicks) { $current.LastTicks=$last; $current.Last=$g.Last }
        }
    }
    foreach ($inc in $incidents) {
        $max=0; $tactics=New-Object 'System.Collections.Generic.HashSet[string]'; $significant=0
        foreach ($g in $inc.Groups) {
            if ($g.Score -gt $max) { $max=$g.Score }
            if ($g.Score -ge 50) { $significant++; if ($g.Tactic) { [void]$tactics.Add($g.Tactic) } }
        }
        $score=$max
        # Two or more significant scenarios from different tactics on one host = probable chain.
        if ($significant -ge 2 -and $tactics.Count -ge 2) { $score=[Math]::Min(100,[Math]::Max($max,80)+5*($tactics.Count-1)); $inc.Chain=$true }
        $inc.Score=$score; $inc.Priority=Get-PriorityFromScore $score
    }
    $n=0
    foreach ($inc in ($incidents | Sort-Object @{Expression={$_.Score};Descending=$true},@{Expression={$_.FirstTicks}})) {
        $n++; $inc.Id=('КИ-{0:D3}' -f $n)
        foreach ($g in $inc.Groups) { $g.Incident=$inc.Id }
    }
    return ,@($incidents | Sort-Object Id)
}
function Write-IncidentReport([string]$WorkPath,$Incidents) {
    $w=New-Writer (Join-Path $WorkPath 'Incidents.csv')
    try {
        Write-Row $w @('КИ','Приоритет','Оценка риска','Компьютер','Начало UTC','Конец UTC','Начало (местное)','Длительность','Сценариев','Цепочка атаки','Этапы (тактики)','Хронология','Учетные записи','IP источников','Event ID','Папка источника','Что делать')
        foreach ($inc in $Incidents) {
            $ordered=@($inc.Groups | Sort-Object @{Expression={Get-IsoTicks $_.First}},Scenario)
            $timeline=New-Object 'System.Collections.Generic.List[string]'
            $tactics=New-Object 'System.Collections.Generic.List[string]'
            $accounts=New-Object 'System.Collections.Generic.List[string]'; $ips=New-Object 'System.Collections.Generic.List[string]'
            $ids=New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($g in $ordered) {
                if ($timeline.Count -lt 20) { $timeline.Add(((Format-UtcText $g.First)+' ['+$g.Priority.Substring(0,2)+'] '+$g.Scenario)) }
                if ($g.Tactic -and -not $tactics.Contains($g.Tactic)) { $tactics.Add($g.Tactic) }
                foreach ($a in $g.Accounts) { if ($accounts.Count -lt 10 -and -not $accounts.Contains($a)) { $accounts.Add($a) } }
                foreach ($ip in $g.Ips) { if ($ips.Count -lt 10 -and -not $ips.Contains($ip)) { $ips.Add($ip) } }
                foreach ($i in $g.Ids) { [void]$ids.Add($i) }
            }
            if ($ordered.Count -gt 20) { $timeline.Add('… еще '+($ordered.Count-20)+' строк на листе Приоритетные') }
            $chain=''; if ($inc.Chain) { $chain='Да: несколько значимых сценариев разных тактик на одном компьютере' }
            $todo='Отфильтровать лист «Приоритетные» по столбцу КИ = '+$inc.Id+' и пройти строки по времени.'
            if ($inc.Priority -eq $script:P1) { $todo='Срочно: '+$todo+' Подтвердить или опровергнуть; при подтверждении — изолировать компьютер, сменить пароли затронутых УЗ, сохранить журналы.' }
            $duration=Format-Duration (($inc.LastTicks-$inc.FirstTicks)/[TimeSpan]::TicksPerSecond)
            Write-Row $w @($inc.Id,$inc.Priority,$inc.Score,$inc.Computer,(Format-UtcText $inc.First),(Format-UtcText $inc.Last),(Format-LocalText $inc.First),$duration,$ordered.Count,$chain,
                ($tactics.ToArray() -join ' → '),($timeline.ToArray() -join ' → '),($accounts.ToArray() -join ' | '),($ips.ToArray() -join ' | '),
                ((@($ids) | Sort-Object {[int]$_}) -join ', '),$inc.Scope,$todo)
        }
    } finally { Close-Writer $w }
}
function Write-TriageReport([string]$WorkPath,$Groups,[int]$ScopeCount,[int]$BlockedCount,[int]$RowFailures,[int]$ChainFailures,[string]$BuildNote) {
    # Writing the report is isolated from correlation.  Thus a malformed
    # individual record can never remove the entire "Приоритетные" sheet.
    $incidents=@()
    try { $incidents=Build-Incidents $Groups; Write-IncidentReport $WorkPath $incidents }
    catch { Log-Issue 'Triage' $WorkPath '' ('Не сформирован лист Инциденты: '+(Get-TriageErrorText $_)) }
    $w=New-Writer (Join-Path $WorkPath 'Triage.csv')
    try {
        Write-Row $w @('КИ','Приоритет','Оценка риска','Первое время UTC','Последнее время UTC','Первое время (местное)','Компьютер','Сценарий','Тактика','MITRE ATT&CK','Учетные записи','IP источника','УЗ / объект / IP','Основание связи','Почему выделено','Что проверить','Event ID','Связанных уникальных событий','Ссылки на находки и EVTX (до 10)','Папка источника','Ограничения')
        foreach ($g in (@($Groups.Values) | Sort-Object @{Expression={$_.Score};Descending=$true},@{Expression={$_.Incident}},@{Expression={$_.First}},Scenario)) {
            $note='Кандидат для проверки, не подтвержденный инцидент. Повторы объединены; диапазон времени не является длительностью атаки.'
            if ($g.Recovered) { $note+=' Есть восстановленный XML: перепроверить исходную запись.' }
            $ids=@($g.Ids | Sort-Object {[int]$_}) -join ', '
            $count=[long]$g.Seen.Count; if ($g.EventCount -gt $count) { $count=$g.EventCount }
            Write-Row $w @($g.Incident,$g.Priority,$g.Score,(Format-UtcText $g.First),(Format-UtcText $g.Last),(Format-LocalText $g.First),$g.Computer,$g.Scenario,$g.Tactic,$g.Mitre,
                ($g.Accounts.ToArray() -join ' | '),($g.Ips.ToArray() -join ' | '),$g.Object,$g.Evidence,$g.Why,$g.Check,$ids,$count,($g.Refs.ToArray() -join ' || '),$g.Scope,$note)
        }
        $limits=New-Object 'System.Collections.Generic.List[string]'
        if ($RowFailures -gt 0) { [void]$limits.Add('Строк с ошибкой приоритизации: '+$RowFailures+'. Они перечислены на листе Ошибки (этап «Приоритизация: строка»).') }
        if ($ChainFailures -gt 0) { [void]$limits.Add('Областей со сбойной связкой: '+$ChainFailures+'. Остальные области обработаны.') }
        if ($BuildNote) { [void]$limits.Add($BuildNote) }
        if ($limits.Count -gt 0) {
            Write-Row $w @('','Справка','','','','','','Приоритизация выполнена с ограничениями','','','','','',($limits.ToArray() -join ' '),'Это не отменяет уже сформированные строки; проверить лист Ошибки и исходный EVTX.','После устранения причины повторить запуск на неизменяемой копии.','','','','',$null)
        }
        Write-Row $w @('','Справка','','','','','','Границы анализа','','','','','','Связки не строятся через ошибки чтения, восстановленный XML, изменение времени/загрузку ОС и между разными папками либо компьютерами.','Оценка риска: P1 ≥ 80, P2 ≥ 50, P3 — к сведению. Одиночные отказы входа и обычные системные ошибки сюда не включаются.','Также просмотреть листы Инциденты, Подбор_пароля, RDP_итоги, Качество_выгрузки и Ошибки.','','','','',('Областей с кандидатами цепочек: '+$ScopeCount+'; областей с запретом цепочек: '+$BlockedCount+'. Окно цепочек: '+$TriageWindowMinutes+' мин.; окно отказов: '+$WindowMinutes+' мин.; объединение в КИ: '+$IncidentGapHours+' ч.'))
    } finally { Close-Writer $w }
}
function Add-BurstTriage($Groups,[string]$WorkPath) {
    # Password guessing / spraying windows from the AuthBursts sheet become priority rows.
    $path=Join-Path $WorkPath 'AuthBursts.csv'
    if (-not (Test-Path -LiteralPath $path)) { return }
    $n=0
    foreach ($b in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
        $n++
        $spray=$b.'Событие' -match 'spraying'
        $source=$b.'Источник'
        $refs=[string]$b.'Файлы и Record ID (пример)'
        $firstRef=($refs -split ' \| ')[0]
        $row=[pscustomobject]@{'Номер'=$b.'Номера находок (пример)';'Event ID'=$b.'Event ID';'Record ID'=($firstRef -replace '^.*#','');'Время UTC'=$b.'Окно: начало UTC';
            'Папка источника'=$b.'Папка источника';'Полный путь'=($firstRef -replace '#[^#]*$','');'Компьютер'=$b.'Компьютер';'Целевая УЗ'=$b.'Учетные записи';
            'IP источника'=$source;'SHA256 XML события'=('burst|'+$n+'|'+$b.'Окно: начало UTC'+'|'+$source);'Восстановление XML'=''}
        $scenario='Подбор пароля к УЗ'; $object=$source+' → '+$b.'Учетные записи'
        if ($spray) { $scenario='Password spraying с одного источника'; $object=$source }
        $score=$script:ScenarioCatalog[$scenario].Score
        $public=Triage-IsPublicIp $source
        if ($public) { $score+=10 }
        # Kerberos/NTLM bursts for one account from an internal host are usually a stale saved password.
        elseif (-not $spray -and $b.'Event ID' -in @('4771','4776')) { $score=45 }
        $evidence='Связь: '+$b.'Событий в окне'+' отказов (Event ID '+$b.'Event ID'+') за '+$WindowMinutes+' мин. с источника '+$source+'; разных УЗ: '+$b.'Разных УЗ'+'. Коды: '+$b.'Коды статуса'+'.'
        if ($public) { $evidence+=' Источник — публичный IP.' }
        Add-Triage -Groups $Groups -Priority $script:P2 -Scenario $scenario -Evidence $evidence -Why '' -Check 'Проверить источник (владелец IP/узла), коды отказов (0xC000006A — неверный пароль, 0xC0000064 — нет такой УЗ), был ли успешный вход с этого источника после серии, и блокировки 4740.' -Object $object -Rows @($row) -Score $score -LastTime $b.'Окно: конец UTC' -EventCount ([long]$b.'Событий в окне')
    }
}
function Write-TriageFallback([string]$WorkPath,[string]$Reason) {
    $emptyGroups=@{}
    Write-TriageReport $WorkPath $emptyGroups 0 0 0 0 ('Не удалось полностью сформировать приоритеты: '+$Reason)
}
# Provider|Event ID pairs that Add-SingleTriage can act on; other rows skip the call.
$script:SingleTriageKeys=New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($k in @('Microsoft-Windows-Eventlog|104','Microsoft-Windows-Eventlog|1102','Microsoft-Windows-Eventlog|1101','Microsoft-Windows-Eventlog|1104','Microsoft-Windows-Eventlog|1108',
    'Service Control Manager|7045','Service Control Manager|7040','Service Control Manager|7031','Service Control Manager|7034',
    'Microsoft-Windows-TaskScheduler|106','Microsoft-Windows-TaskScheduler|140','Microsoft-Windows-Sysmon|16','Microsoft-Windows-Sysmon|25',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager|1149')) { [void]$script:SingleTriageKeys.Add($k) }
foreach ($i in @(4616,4624,4697,4698,4702,4704,4715,4717,4719,4728,4732,4739,4756,4765,4766,4904,4905,4906,4907,4946)) { [void]$script:SingleTriageKeys.Add('Microsoft-Windows-Security-Auditing|'+$i) }
foreach ($i in @(1006,1008,1015,1116,1118,1119,1121,5001,5007,5010,5012,5013)) { [void]$script:SingleTriageKeys.Add('Microsoft-Windows-Windows Defender|'+$i) }
$script:TriageColumns=@('Номер','Event ID','Record ID','Время UTC','Папка источника','Полный путь','Компьютер','Провайдер','Результат аудита','SID целевой УЗ','SID участника','SID инициатора','Logon ID цели','Logon ID инициатора','Тип входа','Целевая УЗ','IP источника','Status','SubStatus','Данные события','Командная строка','Процесс','SHA256 XML события','Восстановление XML','Инициатор','Имя угрозы')
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
                    if ($script:SingleTriageKeys.Contains($r.'Провайдер'+'|'+$r.'Event ID') -or (Triage-Value $r 'Правило') -in @('AV-VENDOR-THREAT','HEURISTIC-COMMAND')) { Add-SingleTriage $groups $r }
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
    try { Add-BurstTriage $groups $WorkPath }
    catch {
        $script:TriageIncomplete=$true; $script:TriageHasErrors=$true
        $errorText=Get-TriageErrorText $_
        if ($buildNote) { $buildNote+=' | ' }
        $buildNote+='Не удалось перенести серии подбора пароля: '+$errorText
        Log-Issue 'Triage' $WorkPath '' $errorText
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
        Assert-True ($null -ne (Match-Event $serviceLogon $false)) 'v8 user 4672 retained'
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
    # Required event list (v9.1).
    $required=@('Microsoft-Windows-Security-Auditing|4616','Microsoft-Windows-Kernel-General|1','Microsoft-Windows-Kernel-General|24',
        'Microsoft-Windows-Security-Auditing|4724','Microsoft-Windows-Security-Auditing|4720','Microsoft-Windows-Security-Auditing|4726','Microsoft-Windows-Security-Auditing|4725',
        'Microsoft-Windows-Security-Auditing|4738','Microsoft-Windows-Security-Auditing|4781','Microsoft-Windows-Security-Auditing|4741','Microsoft-Windows-Security-Auditing|4743',
        'Microsoft-Windows-Security-Auditing|4765','Microsoft-Windows-Security-Auditing|4766','Microsoft-Windows-Security-Auditing|4704',
        'Microsoft-Windows-Security-Auditing|4728','Microsoft-Windows-Security-Auditing|4732','Microsoft-Windows-Security-Auditing|4756',
        'Microsoft-Windows-Security-Auditing|4729','Microsoft-Windows-Security-Auditing|4733','Microsoft-Windows-Security-Auditing|4757',
        'Microsoft-Windows-Security-Auditing|4672','Microsoft-Windows-Security-Auditing|4964',
        'Microsoft-Windows-Eventlog|1102','Microsoft-Windows-Eventlog|104','Microsoft-Windows-Eventlog|1100',
        'Microsoft-Windows-Security-Auditing|4719','Microsoft-Windows-Security-Auditing|4907','Microsoft-Windows-Security-Auditing|4715',
        'Microsoft-Windows-Security-Auditing|4624','Microsoft-Windows-Security-Auditing|4648','Microsoft-Windows-Security-Auditing|4778','Microsoft-Windows-Security-Auditing|4779',
        'Microsoft-Windows-Security-Auditing|4625','Microsoft-Windows-Security-Auditing|4634','Microsoft-Windows-Security-Auditing|4647',
        'Microsoft-Windows-TerminalServices-LocalSessionManager|22','Microsoft-Windows-TerminalServices-LocalSessionManager|23',
        'Microsoft-Windows-TerminalServices-LocalSessionManager|24','Microsoft-Windows-TerminalServices-LocalSessionManager|25',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager|1149',
        'Microsoft-Windows-Windows Defender|1116','Microsoft-Windows-Windows Defender|1117','Microsoft-Windows-Windows Defender|1118','Microsoft-Windows-Windows Defender|1119',
        'Microsoft-Windows-Windows Defender|1006','Microsoft-Windows-Windows Defender|5007','Microsoft-Windows-Windows Defender|5010','Microsoft-Windows-Windows Defender|1008',
        'Microsoft-Windows-Windows Defender|1015','Microsoft-Windows-Windows Defender|1121','Microsoft-Windows-Windows Defender|5001','Microsoft-Windows-Windows Defender|2012',
        'Microsoft-Windows-Windows Defender|5013','Microsoft-Windows-Security-Auditing|4771','Microsoft-Windows-Security-Auditing|4776',
        'Microsoft-Windows-Kernel-Power|41','EventLog|6008','EventLog|6005','EventLog|6006','User32|1074','Service Control Manager|7031','Service Control Manager|7034')
    foreach ($k in $required) {
        if ([int]$k.Split('|')[1] -gt $MaxEventId) { continue }
        Assert-True ($script:Rules.ContainsKey($k)) ('v9.1 required rule present: '+$k)
    }
    $e=Parse-Event (Test-Xml 4648 $sec '<EventData><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="TargetUserName">bob</Data></EventData>')
    Assert-True (($null -eq (Match-Event $e $false)) -eq (-not $IncludeNoise)) 'v9.1 4648 by SYSTEM filtered unless -IncludeNoise'
    $e.Data['SubjectUserSid']='S-1-5-21-1-2-3-1001'
    Assert-True ($null -ne (Match-Event $e $false)) 'v9.1 4648 by user retained'
    if (-not $IncludeNoise) {
        Assert-True (@($selects | Where-Object { $_ -like "*EventID=4648*SubjectUserSid']!='S-1-5-18'*" }).Count -eq 1) 'v9.1 4648 system accounts filtered by Windows API'
        Assert-True (@($selects | Where-Object { $_ -like "*EventID=4672*SubjectUserSid']!='S-1-5-18'*" }).Count -eq 1) 'v9.1 4672 system accounts filtered by Windows API'
    }
    # RDP sessions: 4624 -> 4647 pairing, trailing 4634 suppressed, LSM sessions, totals.
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-V91-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tmp)
    try {
        $script:RdpCount=0; $script:RdpClosed=@{}; $script:RdpTotals=@{}
        $script:RdpWriter=New-Writer (Join-Path $tmp 'rdp.csv')
        Write-Row $script:RdpWriter @('StartEvent','EndEvent','File','Computer','Account','LogonId','Source','Start','End','Seconds','Duration','Status','Reason','StartRecord','EndRecord','StartFinding','EndFinding','DataSource')
        $state=@{}
        $base=[DateTimeOffset]::Parse('2026-01-01T10:00:00Z')
        $mk={ param([int]$Id,[string]$Provider,[string]$Payload,[int]$Minutes)
            $x=Parse-Event (Test-Xml $Id $Provider $Payload)
            $t=$base.AddMinutes($Minutes); $x.Ticks=$t.UtcDateTime.Ticks; $x.TimeUtc=$t.UtcDateTime.ToString('o')
            return $x }
        $logon='<EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">LAB</Data><Data Name="TargetLogonId">0x1a2</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">192.0.2.9</Data></EventData>'
        Handle-Rdp (& $mk 4624 $sec $logon 0) $state 'Security.evtx' 1
        Handle-Rdp (& $mk 4647 $sec '<EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">LAB</Data><Data Name="TargetLogonId">0x1a2</Data></EventData>' 90) $state 'Security.evtx' 2
        Handle-Rdp (& $mk 4634 $sec '<EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">LAB</Data><Data Name="TargetLogonId">0x1a2</Data><Data Name="LogonType">10</Data></EventData>' 91) $state 'Security.evtx' 3
        Handle-Rdp (& $mk 4647 $sec '<EventData><Data Name="TargetUserName">carol</Data><Data Name="TargetLogonId">0x999</Data></EventData>' 92) $state 'Security.evtx' 4
        Assert-True ($state.Count -eq 0 -and $script:RdpCount -eq 1) 'v9.1 RDP 4624 -> 4647 paired; trailing 4634 and local 4647 add no rows'
        $lsm=$script:LsmProvider
        $ud={ param([string]$Inner) return '<UserData><EventXML xmlns="Event_NS">'+$Inner+'</EventXML></UserData>' }
        Handle-Rdp (& $mk 21 $lsm (& $ud '<User>LAB\bob</User><SessionID>3</SessionID><Address>192.0.2.20</Address>') 0) $state 'LSM.evtx' 5
        Handle-Rdp (& $mk 24 $lsm (& $ud '<User>LAB\bob</User><SessionID>3</SessionID><Address>192.0.2.20</Address>') 30) $state 'LSM.evtx' 6
        Handle-Rdp (& $mk 25 $lsm (& $ud '<User>LAB\bob</User><SessionID>3</SessionID><Address>192.0.2.20</Address>') 60) $state 'LSM.evtx' 7
        Handle-Rdp (& $mk 23 $lsm (& $ud '<User>LAB\bob</User><SessionID>3</SessionID>') 75) $state 'LSM.evtx' 8
        Handle-Rdp (& $mk 24 $lsm (& $ud '<User>LAB\bob</User><SessionID>3</SessionID><Address>192.0.2.20</Address>') 76) $state 'LSM.evtx' 9
        Handle-Rdp (& $mk 21 $lsm (& $ud '<User>LAB\local</User><SessionID>1</SessionID><Address>LOCAL</Address>') 0) $state 'LSM.evtx' 10
        Handle-Rdp (& $mk 23 $lsm (& $ud '<User>LAB\local</User><SessionID>1</SessionID>') 5) $state 'LSM.evtx' 11
        Assert-True ($state.Count -eq 0 -and $script:RdpCount -eq 3) 'v9.1 LSM 21->24 and 25->23 paired; trailing 24 and console session ignored'
        Close-Writer $script:RdpWriter
        $rdp=@(Import-Csv -LiteralPath (Join-Path $tmp 'rdp.csv') -Delimiter $Delimiter)
        Assert-True ($rdp[0].Seconds -eq '5400' -and $rdp[0].Duration -eq '1:30:00' -and $rdp[0].Source -eq '192.0.2.9' -and $rdp[0].DataSource -eq 'Security') 'v9.1 RDP duration seconds, h:mm:ss, IP and data source'
        Assert-True ($rdp[1].Duration -eq '0:30:00' -and $rdp[2].Duration -eq '0:15:00' -and $rdp[2].Source -eq '192.0.2.20' -and $rdp[1].Account -eq 'LAB\bob') 'v9.1 LSM intervals keep user and address'
        Write-RdpTotals (Join-Path $tmp 'totals.csv')
        $totals=@(Import-Csv -LiteralPath (Join-Path $tmp 'totals.csv') -Delimiter $Delimiter -Encoding UTF8)
        $bob=@($totals | Where-Object { $_.'Учетная запись' -eq 'LAB\bob' })
        Assert-True ($totals.Count -eq 2 -and $bob.Count -eq 1 -and $bob[0].'Сеансов (пар)' -eq '2' -and $bob[0].'Суммарная длительность (ч:мм:сс)' -eq '0:45:00' -and $bob[0].'Максимальный сеанс (ч:мм:сс)' -eq '0:30:00') 'v9.1 RDP totals per computer/account/IP'
    } finally {
        Close-Writer $script:RdpWriter
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    Write-Host 'V9 SelfTest OK'
}
function Test-V92Parse {
    $sec='Microsoft-Windows-Security-Auditing'
    $ns='http://schemas.microsoft.com/win/2004/08/events/event'
    # Windows ToXml() shape: single quotes, Qualifiers, Security/Execution elements, Binary.
    $win="<Event xmlns='$ns'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-03-01T08:09:10.1234567Z'/><EventRecordID>123456</EventRecordID><Correlation ActivityID='{11111111-2222-3333-4444-555555555555}'/><Execution ProcessID='700' ThreadID='800'/><Channel>Security</Channel><Computer>srv01.lab.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SRV01$</Data><Data Name='SubjectDomainName'>LAB</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='TargetLogonId'>0x1a2b</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>203.0.113.5</Data><Data Name='IpPort'>51234</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='Empty'></Data><Data Name='Dash'>-</Data><Data Name='SelfClosed'/><Data Name='Ent'>a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos; &amp;lt;</Data><Data>unnamed</Data><Data Name='LogonType'>dup</Data></EventData></Event>"
    $samples=@(
        $win,
        $win.Replace("<Data Name='Empty'></Data>","<Data Name='Empty'></Data><Binary>0A0B</Binary>"),
        (Test-Xml 4625 $sec '<EventData><Data Name="TargetUserName">a</Data><Data Name="Status">0xc000006d</Data></EventData>' '0x8010000000000000'),
        (Test-Xml 7045 'Service Control Manager' '<EventData><Data Name="ServiceName">x</Data><Data Name="ImagePath">%COMSPEC% /c echo 1 &gt; \\127.0.0.1\C$\o</Data></EventData>'),
        (Test-Xml 1102 'Microsoft-Windows-Eventlog' '<UserData><LogFileCleared xmlns="urn:t"><SubjectUserName>alice</SubjectUserName></LogFileCleared></UserData>'),
        (Test-Xml 1000 'Application Error' ('<EventData><Data Name="V">A'+[char]16+'B</Data></EventData>')),
        (Test-Xml 1000 'Application Error' "<EventData><Data Name=`"V`">line1`r`nline2</Data></EventData>"),
        (Test-Xml 1000 'Application Error' '<EventData><Data Name="V">&#x41;</Data></EventData>'),
        (Test-Xml 1000 'Application Error' '<EventData><Data Name="V"><![CDATA[x]]></Data></EventData>'),
        (Test-Xml 1000 'Application Error' '<EventData><Data Name="V"><Sub>x</Sub></Data></EventData>'),
        (Test-Xml 1000 'Application Error' '<EventData Name="x"><Data Name="V">1</Data></EventData>'),
        (Test-Xml 1000 'Application Error' '<EventData><Data Name="V">1</Data><ComplexData>2</ComplexData></EventData>'),
        (Test-Xml 1000 'Application Error' '')
    )
    $fastCount=0
    foreach ($xmlText in $samples) {
        $dom=Parse-EventDom $xmlText; $fast=Parse-EventFast $xmlText
        if ($null -eq $fast) { $fast=Parse-Event $xmlText } else { $fastCount++ }
        $same=$true
        foreach ($p in $dom.PSObject.Properties) {
            if ($p.Name -in @('Data','F')) { continue }
            if ([string]$fast.($p.Name) -cne [string]$p.Value) { $same=$false; Write-Host ('  differs: '+$p.Name) }
        }
        if ((@($fast.Data.Keys) -join '|') -cne (@($dom.Data.Keys) -join '|') -or (@($fast.Data.Values) -join '|') -cne (@($dom.Data.Values) -join '|')) { $same=$false; Write-Host '  differs: Data' }
        foreach ($spec in $script:FieldSpecs) { $k=$spec[0]; if ([string]$fast.F[$k] -cne [string]$dom.F[$k]) { $same=$false; Write-Host ('  differs: F.'+$k) } }
        foreach ($spec in $script:FieldSpecs) { if ([string]$dom.F[$spec[0]] -cne (Field $dom.Data ([string[]]($spec | Select-Object -Skip 1)))) { $same=$false; Write-Host ('  F differs from Field: '+$spec[0]) } }
        Assert-True $same ('v9.2 fast parser equals XML parser: '+$dom.Provider+'/'+$dom.Id+' '+$dom.Data.Count+' fields')
    }
    Assert-True ($fastCount -eq 5) ('v9.2 simple events use the fast path, unusual ones the XML parser (fast='+$fastCount+')')
    $rejected=$false
    try { $null=Parse-Event ((Test-Xml 1000 'Application Error' '<EventData><Data Name="V">ok</Data></EventData>').Replace('</EventData>','')) } catch { $rejected=$true }
    Assert-True $rejected 'v9.2 malformed XML still rejected'
}
function Test-V92Triage {
    $sec='Microsoft-Windows-Security-Auditing'
    Assert-True ((Triage-IsPublicIp '45.10.20.30') -and (Triage-IsPublicIp '::ffff:8.8.8.8') -and (Triage-IsPublicIp '2a00:1450::1')) 'v9.2 public IP detection'
    Assert-True (-not (Triage-IsPublicIp '10.1.2.3') -and -not (Triage-IsPublicIp '172.20.0.1') -and -not (Triage-IsPublicIp '192.168.1.1') -and -not (Triage-IsPublicIp '100.64.0.1') -and -not (Triage-IsPublicIp '192.0.2.5') -and -not (Triage-IsPublicIp 'fe80::1') -and -not (Triage-IsPublicIp 'LOCAL') -and -not (Triage-IsPublicIp '-')) 'v9.2 private/reserved IP not public'
    $alice='S-1-5-21-1-2-3-1001'; $backdoor='S-1-5-21-1-2-3-2001'; $ip='45.10.20.30'
    $mk={ param([int]$Id,[string]$Provider,[string]$Time,[int]$Record,[hashtable]$Values)
        $v=@{'Правило'='';'Компьютер'='PC01'}; foreach ($k in $Values.Keys) { $v[$k]=$Values[$k] }
        return New-V7TestRow $Id $Provider $Time ([string]$Record) $v }
    $rows=New-Object 'System.Collections.Generic.List[object]'
    for ($i=0;$i -lt $FailureThreshold;$i++) {
        $rows.Add((& $mk 4625 $sec ('2026-01-01T10:00:{0:D2}.0000000Z' -f $i) (100+$i) @{'Результат аудита'='Отказ';'Тип входа'='10';'IP источника'=$ip;'SubStatus'='0xc000006a';'SID целевой УЗ'='S-1-0-0'}))
    }
    $rows.Add((& $mk 4624 $sec '2026-01-01T10:01:00.0000000Z' 200 @{'Тип входа'='10';'IP источника'=$ip;'Logon ID цели'='0xa1';'SID целевой УЗ'=$alice}))
    $actor=@{'SID инициатора'=$alice;'Logon ID инициатора'='0xa1';'Инициатор'='LAB\alice'}
    $v=@{'SID целевой УЗ'=$backdoor;'Целевая УЗ'='PC01\backdoor'}; foreach ($k in $actor.Keys) { $v[$k]=$actor[$k] }
    $rows.Add((& $mk 4720 $sec '2026-01-01T10:05:00.0000000Z' 201 $v))
    $v=@{'SID целевой УЗ'='S-1-5-32-544';'SID участника'=$backdoor;'Целевая УЗ'='Administrators'}; foreach ($k in $actor.Keys) { $v[$k]=$actor[$k] }
    $rows.Add((& $mk 4732 $sec '2026-01-01T10:06:00.0000000Z' 202 $v))
    $rows.Add((& $mk 7045 'Service Control Manager' '2026-01-01T10:10:00.0000000Z' 203 @{'Данные события'='ServiceName=BTOBTO | ImagePath=%COMSPEC% /Q /c echo whoami ^> \\127.0.0.1\C$\__output 2^>^&1 | ServiceType=user mode service | StartType=demand start | AccountName=LocalSystem'}))
    $rows.Add((& $mk 1116 'Microsoft-Windows-Windows Defender' '2026-01-01T10:12:00.0000000Z' 204 @{'Имя угрозы'='HackTool:Win32/Mimikatz';'Ресурс / путь'='C:\Users\Public\m.exe'}))
    $rows.Add((& $mk 5001 'Microsoft-Windows-Windows Defender' '2026-01-01T10:15:00.0000000Z' 205 @{}))
    $rows.Add((& $mk 5007 'Microsoft-Windows-Windows Defender' '2026-01-01T10:16:00.0000000Z' 206 @{'Данные события'='Old Value= | New Value=HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0'}))
    $rows.Add((& $mk 7040 'Service Control Manager' '2026-01-01T10:17:00.0000000Z' 207 @{'Данные события'='param1=Антивирусная программа Microsoft Defender | param2=Автоматически | param3=Отключена | param4=WinDefend'}))
    $v=@{'SID целевой УЗ'=$backdoor;'Целевая УЗ'='PC01\backdoor'}; foreach ($k in $actor.Keys) { $v[$k]=$actor[$k] }
    $rows.Add((& $mk 4726 $sec '2026-01-01T10:18:00.0000000Z' 208 $v))
    $rows.Add((& $mk 1102 'Microsoft-Windows-Eventlog' '2026-01-01T10:20:00.0000000Z' 209 $actor))
    # Benign computer: internal RDP, ordinary group change, own password change.
    $rows.Add((& $mk 4624 $sec '2026-01-01T09:00:00.0000000Z' 300 @{'Компьютер'='PC02';'Тип входа'='10';'IP источника'='10.0.0.5';'Logon ID цели'='0xb2'}))
    $rows.Add((& $mk 4732 $sec '2026-01-01T09:05:00.0000000Z' 301 @{'Компьютер'='PC02';'SID целевой УЗ'='S-1-5-32-545';'SID участника'=$alice}))
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-V92-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tmp)
    $script:IssueCount=0; $script:WarningCount=0
    try {
        $rows | Export-Csv -LiteralPath (Join-Path $tmp 'Findings-0001.csv') -Delimiter $Delimiter -Encoding UTF8 -NoTypeInformation
        $bw=New-Writer (Join-Path $tmp 'AuthBursts.csv')
        Write-Row $bw @('Приоритет','Event ID','Событие','Папка источника','Компьютер','Источник','Окно: начало UTC','Окно: конец UTC','Событий в окне','Разных УЗ','Учетные записи','Номера находок (пример)','Файлы и Record ID (пример)','Коды статуса','Комментарий')
        Write-Row $bw @('Высокий','4625','Отказы для нескольких УЗ с одного источника: возможный password spraying','C:\test','PC01',$ip,'2026-01-01T09:50:00.0000000Z','2026-01-01T09:58:00.0000000Z','25','8','LAB\a | LAB\b | LAB\c','1 | 2','C:\test\Security.evtx#11 | C:\test\Security.evtx#12','0xc000006d/0xc0000064','x')
        Close-Writer $bw
        $script:ErrorWriter=New-Writer (Join-Path $tmp 'Errors.csv')
        Write-Row $script:ErrorWriter @('Время UTC','Этап','Файл источника','Record ID','Ошибка')
        Build-Triage $tmp
        $script:ErrorWriter.Flush()
        Assert-True (-not $script:TriageHasErrors) 'v9.2 attack scenario: triage without errors'
        $out=@(Import-Csv -LiteralPath (Join-Path $tmp 'Triage.csv') -Delimiter $Delimiter -Encoding UTF8 | Where-Object { $_.'Приоритет' -ne 'Справка' })
        $scenarios=@($out | ForEach-Object { $_.'Сценарий' })
        foreach ($expected in @('Password spraying с одного источника','Отказы RDP с неверным паролем → успешный вход','RDP-вход с внешнего IP','RDP-сеанс: создание УЗ',
            'Новая УЗ получила привилегии','Добавление в привилегированную группу','Служба удаленного выполнения (PsExec/Impacket)','Обнаружение угрозы Defender',
            'Отключение компонентов защиты Defender','Обнаружение угрозы → отключение защиты','Добавлено исключение Defender','Отключение службы защиты или журналирования',
            'Временная УЗ: создана и удалена','Очистка журнала','RDP-сеанс: очистка журнала Security')) {
            Assert-True ($expected -in $scenarios) ('v9.2 attack scenario detected: '+$expected)
        }
        Assert-True (@($out | Where-Object { $_.'Компьютер' -eq 'PC02' }).Count -eq 0) 'v9.2 benign computer has no priority rows'
        $scores=@($out | ForEach-Object { [int]$_.'Оценка риска' })
        $sorted=$true; for ($i=1;$i -lt $scores.Count;$i++) { if ($scores[$i] -gt $scores[$i-1]) { $sorted=$false } }
        Assert-True ($sorted -and $scores[0] -ge 90) 'v9.2 priority sheet sorted by risk score'
        $spray=@($out | Where-Object { $_.'Сценарий' -eq 'Password spraying с одного источника' })[0]
        Assert-True ($spray.'Связанных уникальных событий' -eq '25' -and [int]$spray.'Оценка риска' -eq 90 -and $spray.'IP источника' -eq $ip -and $spray.'Последнее время UTC' -eq '2026-01-01 09:58:00') 'v9.2 spraying window: count, public-IP boost, IP and end time'
        $p1=@($out | Where-Object { $_.'Сценарий' -eq 'Служба удаленного выполнения (PsExec/Impacket)' })[0]
        Assert-True ($p1.'Приоритет' -eq $script:P1 -and $p1.'MITRE ATT&CK' -like 'T1569.002*' -and $p1.'Тактика' -and $p1.'Почему выделено' -notlike 'Факт:*') 'v9.2 catalog fills priority, MITRE, tactic and why'
        $inc=@(Import-Csv -LiteralPath (Join-Path $tmp 'Incidents.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($inc.Count -eq 1 -and $inc[0].'КИ' -eq 'КИ-001' -and $inc[0].'Приоритет' -eq $script:P1 -and $inc[0].'Цепочка атаки' -like 'Да*' -and [int]$inc[0].'Оценка риска' -ge 95) 'v9.2 one P1 incident with attack chain'
        Assert-True ($inc[0].'Хронология' -like '2026-01-01 09:50:00 `[P1`] Password spraying*' -and $inc[0].'IP источников' -like "*$ip*" -and $inc[0].'Учетные записи' -like '*backdoor*') 'v9.2 incident timeline, IPs and accounts'
        Assert-True (@($out | Where-Object { $_.'КИ' -ne 'КИ-001' }).Count -eq 0) 'v9.2 every priority row linked to its incident'
        $plan=Get-ExcelSheetPlan $tmp
        $names=@($plan | ForEach-Object { $_.Name })
        Assert-True ($names[0] -eq 'Инциденты' -and $names[1] -eq 'Приоритетные' -and $names[2] -eq 'Подбор_пароля') 'v9.2 Excel sheet order'
        $triagePlan=$plan[1]
        $scoreIndex=[array]::IndexOf([string[]]$triagePlan.Headers,'Оценка риска')
        Assert-True ($triagePlan.Types[$scoreIndex] -eq 1 -and $triagePlan.Types[[array]::IndexOf([string[]]$triagePlan.Headers,'Event ID')] -eq 2 -and $triagePlan.PriorityColumn -eq 2 -and $triagePlan.Wrap.Count -ge 4) 'v9.2 Excel plan: numeric score, text IDs, priority colors, wrapping'
        $findPlan=@($plan | Where-Object { $_.Kind -eq 'Findings' })[0]
        Assert-True ($findPlan.Hidden -contains ([array]::IndexOf([string[]]$findPlan.Headers,'SHA256 XML события')+1)) 'v9.2 Excel plan hides technical finding columns'
        Assert-True ((Get-ColumnLetter 1) -eq 'A' -and (Get-ColumnLetter 26) -eq 'Z' -and (Get-ColumnLetter 27) -eq 'AA' -and (Get-ColumnLetter 46) -eq 'AT') 'v9.2 Excel column letters'
        New-FallbackOverview $tmp (Join-Path $tmp 'overview.csv')
        $overview=@(Import-Csv -LiteralPath (Join-Path $tmp 'overview.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($overview[0].'Тип строки' -eq 'Инцидент КИ-001' -and @($overview | Where-Object { $_.'Тип строки' -like 'Приоритетная находка КИ-*' }).Count -eq $out.Count) 'v9.2 CSV fallback starts with incidents'
    } finally {
        Close-Writer $script:ErrorWriter
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    if (-not $IncludeNoise) {
        $e=Parse-Event (Test-Xml 4672 $sec '<EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1500</Data><Data Name="SubjectUserName">DC01$</Data></EventData>')
        Assert-True ($null -eq (Match-Event $e $false)) 'v9.2 4672 of computer account filtered'
        Assert-True (-not $script:Rules.ContainsKey('Microsoft-Windows-Security-Auditing|4723') -and -not $script:Rules.ContainsKey('Microsoft-Windows-Security-Auditing|4946')) 'v9.2 4723 and firewall rule events are noise'
    }
}
function Test-V92Pipeline {
    if ($MaxEventId -lt 7045) { Write-Host 'v9.2 pipeline test skipped: -MaxEventId excludes fixture events'; return }
    # Real code path except the EVTX reader: XML -> Parse-Event -> Match-Event -> Save-Finding /
    # Save-Failure -> Correlate-Failures -> Build-Triage. Verifies column wiring end to end.
    $sec='Microsoft-Windows-Security-Auditing'; $ns='http://schemas.microsoft.com/win/2004/08/events/event'
    $alice='S-1-5-21-1-2-3-1001'; $backdoor='S-1-5-21-1-2-3-2001'; $ip='45.10.20.30'
    $rid=0
    $xml={ param([int]$Id,[string]$Provider,[string]$Time,[string]$Payload,[string]$Keywords='0x8020000000000000',[string]$Channel='Security')
        $script:V92Rid++
        return "<Event xmlns='$ns'><System><Provider Name='$Provider'/><EventID>$Id</EventID><Level>0</Level><Keywords>$Keywords</Keywords><TimeCreated SystemTime='$Time'/><EventRecordID>$($script:V92Rid)</EventRecordID><Channel>$Channel</Channel><Computer>WS01.lab.local</Computer></System>$Payload</Event>" }
    $d={ param([hashtable]$H) $sb='<EventData>'; foreach ($k in $H.Keys) { $sb+="<Data Name='$k'>"+[Security.SecurityElement]::Escape([string]$H[$k])+'</Data>' }; return $sb+'</EventData>' }
    $script:V92Rid=0
    $events=New-Object 'System.Collections.Generic.List[string]'
    $users=@('alice','alice','alice','alice','alice','alice','alice','alice','alice','alice','bob','carol','dave','erin','frank','admin')
    for ($i=0; $i -lt $users.Count; $i++) {
        $events.Add((& $xml 4625 $sec ('2026-02-01T10:00:{0:D2}.0000000Z' -f $i) (& $d ([ordered]@{SubjectUserSid='S-1-5-18';TargetUserSid='S-1-0-0';TargetUserName=$users[$i];TargetDomainName='LAB';Status='0xc000006d';SubStatus='0xc000006a';LogonType='10';IpAddress=$ip;IpPort='0'})) '0x8010000000000000'))
    }
    $events.Add((& $xml 4624 $sec '2026-02-01T10:01:00.0000000Z' (& $d ([ordered]@{TargetUserSid=$alice;TargetUserName='alice';TargetDomainName='LAB';TargetLogonId='0xa1';LogonType='10';IpAddress=$ip}))))
    $events.Add((& $xml 4672 $sec '2026-02-01T10:01:00.0000000Z' (& $d ([ordered]@{SubjectUserSid='S-1-5-21-1-2-3-1500';SubjectUserName='WS01$';SubjectDomainName='LAB';PrivilegeList='SeDebugPrivilege'}))))
    $events.Add((& $xml 4720 $sec '2026-02-01T10:05:00.0000000Z' (& $d ([ordered]@{TargetSid=$backdoor;TargetUserName='backdoor';TargetDomainName='WS01';SubjectUserSid=$alice;SubjectUserName='alice';SubjectDomainName='LAB';SubjectLogonId='0xa1'}))))
    $events.Add((& $xml 4732 $sec '2026-02-01T10:06:00.0000000Z' (& $d ([ordered]@{MemberName='-';MemberSid=$backdoor;TargetUserName='Administrators';TargetDomainName='Builtin';TargetSid='S-1-5-32-544';SubjectUserSid=$alice;SubjectUserName='alice';SubjectDomainName='LAB';SubjectLogonId='0xa1'}))))
    $events.Add((& $xml 7045 'Service Control Manager' '2026-02-01T10:10:00.0000000Z' (& $d ([ordered]@{ServiceName='PSEXESVC';ImagePath='%SystemRoot%\PSEXESVC.exe';ServiceType='user mode service';StartType='demand start';AccountName='LocalSystem'})) '0x8080000000000000' 'System'))
    $events.Add((& $xml 1116 'Microsoft-Windows-Windows Defender' '2026-02-01T10:12:00.0000000Z' (& $d ([ordered]@{'Threat Name'='HackTool:Win32/Mimikatz';Path='file:_C:\Users\Public\m.exe'})) '0x8000000000000000' 'Microsoft-Windows-Windows Defender/Operational'))
    $events.Add((& $xml 5007 'Microsoft-Windows-Windows Defender' '2026-02-01T10:14:00.0000000Z' (& $d ([ordered]@{'Old Value'='';'New Value'='HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0'})) '0x8000000000000000' 'Microsoft-Windows-Windows Defender/Operational'))
    $events.Add((& $xml 1102 'Microsoft-Windows-Eventlog' '2026-02-01T10:20:00.0000000Z' "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>$alice</SubjectUserSid><SubjectUserName>alice</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName><SubjectLogonId>0xa1</SubjectLogonId></LogFileCleared></UserData>" '0x4020000000000000'))
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-V92P-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($tmp)
    $saved=@{}
    foreach ($name in @('RunPath','SpoolPath','FindingHeaders','Part','Summary','FindingCount','BurstCount')) { $saved[$name]=Get-Variable -Scope Script -Name $name -ValueOnly -ErrorAction SilentlyContinue }
    try {
        $script:RunPath=$tmp; $script:SpoolPath=Join-Path $tmp 'spool'; [void][IO.Directory]::CreateDirectory($script:SpoolPath)
        $script:FindingHeaders=@('Номер','Event ID','Record ID','Приоритет','Категория','Событие','Что проверить','Время UTC','Компьютер','Папка источника','Файл журнала','Полный путь','Канал','Провайдер','Уровень Windows','Результат аудита','Инициатор','SID инициатора','Целевая УЗ','SID целевой УЗ','Участник группы','SID участника','IP источника','Порт источника','Рабочая станция','Тип входа','Logon ID цели','Logon ID инициатора','Session ID','Имя сеанса','Status','SubStatus','Процесс','Командная строка','Привилегии','Имя угрозы','Ресурс / путь','Старое время','Новое время','Сдвиг времени, сек','Данные события','Описание Windows','Статус описания','Правило','SHA256 XML события','Восстановление XML')
        $script:Part=0; $script:Summary=@{}; $script:FindingCount=[long]0; $script:BurstCount=0; $script:EvidenceWriter=$null; $script:FindingWriter=$null
        $script:ErrorWriter=New-Writer (Join-Path $tmp 'Errors.csv'); Write-Row $script:ErrorWriter @('Время UTC','Этап','Файл источника','Record ID','Ошибка')
        $script:BurstWriter=New-Writer (Join-Path $tmp 'AuthBursts.csv')
        Write-Row $script:BurstWriter @('Приоритет','Event ID','Событие','Папка источника','Компьютер','Источник','Окно: начало UTC','Окно: конец UTC','Событий в окне','Разных УЗ','Учетные записи','Номера находок (пример)','Файлы и Record ID (пример)','Коды статуса','Комментарий')
        New-FindingFile
        $file=New-Object IO.FileInfo((Join-Path $tmp 'logs\Security.evtx'))
        $spool=@{}
        foreach ($x in $events) {
            $e=Parse-Event $x; $r=Match-Event $e $false
            if ($r) { $e.Fingerprint=Hash-Text $e.Xml; $id=Save-Finding $e $r $file ''; if ($e.Id -in $script:FailureIds) { Save-Failure $e $file $id $spool } }
        }
        foreach ($w in $spool.Values) { Close-Writer $w }
        Close-Writer $script:FindingWriter
        foreach ($sp in (Get-ChildItem -LiteralPath $script:SpoolPath -Filter '*.jsonl' -File)) { Correlate-Failures $sp.FullName }
        Close-Writer $script:BurstWriter
        $expectedFindings=$events.Count; if (-not $IncludeNoise) { $expectedFindings-- }
        Assert-True ($script:FindingCount -eq $expectedFindings) 'v9.2 pipeline: computer-account 4672 filtered unless -IncludeNoise, other events are findings'
        Build-Triage $tmp
        $script:ErrorWriter.Flush()
        Assert-True (-not $script:TriageHasErrors) 'v9.2 pipeline: triage without errors'
        $out=@(Import-Csv -LiteralPath (Join-Path $tmp 'Triage.csv') -Delimiter $Delimiter -Encoding UTF8)
        $scenarios=@($out | ForEach-Object { $_.'Сценарий' })
        foreach ($expected in @('Password spraying с одного источника','Подбор пароля к УЗ','Отказы RDP с неверным паролем → успешный вход','RDP-вход с внешнего IP','RDP-сеанс: создание УЗ',
            'Новая УЗ получила привилегии','Служба удаленного выполнения (PsExec/Impacket)','Добавлено исключение Defender','Обнаружение угрозы → отключение защиты','RDP-сеанс: очистка журнала Security','Очистка журнала')) {
            Assert-True ($expected -in $scenarios) ('v9.2 pipeline detects: '+$expected)
        }
        $inc=@(Import-Csv -LiteralPath (Join-Path $tmp 'Incidents.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($inc.Count -eq 1 -and $inc[0].'Компьютер' -eq 'WS01.lab.local' -and $inc[0].'Приоритет' -eq $script:P1) 'v9.2 pipeline: one P1 incident'
    } finally {
        foreach ($k in $saved.Keys) { Set-Variable -Scope Script -Name $k -Value $saved[$k] }
        Close-Writer $script:ErrorWriter
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
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
    Test-V92Parse
    Test-V92Triage
    Test-V92Pipeline
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
Write-Row $script:RdpWriter @('Event ID начала','Event ID конца','Файл источника','Компьютер','Учетная запись','Logon ID / Session ID','IP источника','Начало UTC','Окончание UTC','Длительность, сек','Длительность (ч:мм:сс)','Статус','Комментарий','Record ID начала','Record ID конца','Номер находки начала','Номер находки конца','Источник данных')
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
        $first=''; $last=''; $reader=$null; $state=@{}; $spoolWriters=@{}; $lastTimes=@{}; $script:RdpClosed=@{}
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
    Write-RdpTotals (Join-Path $script:RunPath 'RdpTotals.csv')
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
