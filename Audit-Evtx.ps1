#requires -Version 5.1
<#
.SYNOPSIS
Офлайн-анализ выгрузок журналов Windows (EVTX) для аудита объектов КИИ / АСУ ТП.

.DESCRIPTION
Читает переданные .evtx (Windows PowerShell 5.1, только встроенный .NET), отбирает
значимые для ИБ события фильтром Windows (XPath), ищет инциденты и цепочки атак
(эвристики и правила Sigma, включая корреляции Sigma v2), строит RDP-сеансы, серии
подбора пароля, перечень съемных носителей, изменений ПО и входов, карточки хостов
и сохраняет книгу Excel (или CSV, если Excel не установлен).
Журналы, учетные записи, политику аудита и политику исполнения скрипт не изменяет.
Горячий путь обработки компилируется из встроенного C# (Add-Type); если компиляция
недоступна, используется совместимый режим на PowerShell (без Sigma).

.PARAMETER InputPath
Файл .evtx или папка (обходится рекурсивно; удобно по подпапке на компьютер).

.PARAMETER OutputPath
Папка для отчета. По умолчанию Документы\Evtx-Audit.

.PARAMETER StartTime
Начало периода анализа (локальное время). Фильтр применяется в запросе Windows.

.PARAMETER EndTime
Конец периода анализа (локальное время).

.PARAMETER SigmaRulesPath
Папки или файлы .yml с дополнительными правилами Sigma (например, SigmaHQ
rules/windows/builtin). Поддерживаемое подмножество описано в README.md.

.PARAMETER NoSigma
Не применять правила Sigma.

.PARAMETER NoCompiledEngine
Не компилировать C#-ядро (совместимый режим на PowerShell, медленнее, без Sigma).

.PARAMETER IncludeNoise
Вернуть шумные события, исключенные по умолчанию.

.PARAMETER SelfTest
Только самопроверка (журналы не читаются).

.EXAMPLE
& .\Audit-Evtx.ps1 -SelfTest

.EXAMPLE
& .\Audit-Evtx.ps1 -InputPath D:\Выгрузки -OutputPath D:\Отчеты -StartTime '2026-09-01'

.EXAMPLE
& .\Audit-Evtx.ps1 -InputPath D:\Выгрузки -SigmaRulesPath D:\sigma\rules\windows\builtin

.NOTES
См. README.md: семантика, ограничения и статус проверки.
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
    [string[]]$SigmaRulesPath,
    [switch]$NoSigma,
    [switch]$NoCompiledEngine,
    [string]$ExtraAvFilePattern = '(?i)(doctor[ ._-]*web|dr[ ._-]*web|kaspersky|eset|symantec|sophos|mcafee|trend.?micro)',
    [switch]$SelfTest
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Version = '10.0.0'
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
Microsoft-Windows-Security-Auditing	6416	Съемные носители	Low	Распознано новое внешнее устройство	Аудит Plug and Play: проверить устройство (DeviceId, класс), время и пользователя; сверить с учетом машинных носителей.
Microsoft-Windows-Security-Auditing	6419	Съемные носители	Low	Запрос на отключение устройства	Изменение состояния устройства; проверить инициатора.
Microsoft-Windows-Security-Auditing	6420	Съемные носители	Low	Устройство отключено	Изменение состояния устройства; проверить инициатора.
Microsoft-Windows-Security-Auditing	6421	Съемные носители	Low	Запрос на включение устройства	Изменение состояния устройства; проверить инициатора.
Microsoft-Windows-Security-Auditing	6422	Съемные носители	Low	Устройство включено	Изменение состояния устройства; проверить инициатора.
Microsoft-Windows-Security-Auditing	6423	Съемные носители	Medium	Установка устройства запрещена политикой	Попытка подключить запрещенное устройство; проверить устройство, пользователя и время.
Microsoft-Windows-Security-Auditing	6424	Съемные носители	Medium	Установка устройства разрешена после запрета	Ранее запрещенное устройство установлено; проверить основание изменения политики.
Microsoft-Windows-Kernel-PnP	400	Съемные носители	Low	Настроено устройство (Kernel-PnP)	Подключение USB-накопителя или WPD-устройства; сверить серийный номер с учетом машинных носителей.
Microsoft-Windows-Kernel-PnP	410	Съемные носители	Low	Запущено устройство (Kernel-PnP)	Подключение USB-накопителя или WPD-устройства; сверить серийный номер с учетом машинных носителей.
Microsoft-Windows-Partition	1006	Съемные носители	Low	Подключен диск USB/SD (Partition)	Производитель, модель и серийный номер носителя; сверить с учетом машинных носителей.
Microsoft-Windows-UserPnp	20001	Съемные носители	Low	Установлен драйвер устройства (UserPnp)	Первое подключение устройства к компьютеру (Windows 7/2008 R2); сверить с учетом носителей.
Microsoft-Windows-UserPnp	20003	Съемные носители	Low	Добавлена служба устройства (UserPnp)	Первое подключение устройства к компьютеру (Windows 7/2008 R2); сверить с учетом носителей.
MsiInstaller	1033	Изменения ПО	Low	Установлен продукт (Windows Installer)	Сопоставить с перечнем разрешенного ПО и заявками на изменение конфигурации.
MsiInstaller	1034	Изменения ПО	Low	Удален продукт (Windows Installer)	Сопоставить с перечнем разрешенного ПО и заявками на изменение конфигурации.
MsiInstaller	1035	Изменения ПО	Info	Переконфигурирован продукт (Windows Installer)	Изменение установленного продукта; сопоставить с заявками.
MsiInstaller	1022	Изменения ПО	Info	Установлено обновление продукта (Windows Installer)	Обновление установленного продукта; сопоставить с заявками.
Microsoft-Windows-WindowsUpdateClient	19	Изменения ПО	Info	Установлено обновление Windows	Сведения об установке обновлений безопасности.
Microsoft-Windows-WindowsUpdateClient	20	Изменения ПО	Low	Ошибка установки обновления Windows	Обновление не установлено; проверить актуальность защиты.
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
$script:SigmaSelectors=New-Object 'System.Collections.Generic.List[string]'
$script:FormatMessages=[bool]$IncludeMessages
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
$script:ResultSuccess=Ru-AuditOutcome 'Success'; $script:ResultFailure=Ru-AuditOutcome 'Failure'
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
    if ($Value -eq 'Report') { return 'Формирование листа' }
    if ($Value -eq 'Sigma') { return 'Правила Sigma' }
    if ($Value -eq 'Engine') { return 'C#-ядро' }
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
function New-EventRecord([string]$Provider,[string]$IdText,[string]$Channel,[string]$Computer,[string]$RecordId,[string]$LevelText,[string]$SystemTime,[string]$Keywords,$Data,[string]$XmlText,[string]$Recovery,[string]$SecurityUserId='') {
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
    # System/Security/@UserID: who triggered System/Application events (service or MSI install).
    if ($SecurityUserId) { $f['SecurityUserID']=$SecurityUserId }
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
$script:RxSysItem=New-Object Text.RegularExpressions.Regex('<(Provider|EventID|Level|Keywords|TimeCreated|EventRecordID|Channel|Computer|Security)\b([^>]*?)(?:/>|>([^<]*)</\1>)',$script:RxOpt)
$script:RxAttrUser=New-Object Text.RegularExpressions.Regex('\sUserID=(?:''([^'']*)''|"([^"]*)")',$script:RxOpt)
$script:XmlWs=[char[]]@(' ',"`t","`n","`r")
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
            # XmlDocument drops whitespace-only text nodes; keep the same value.
            if ($v.Length -gt 0 -and $v.Trim($script:XmlWs).Length -eq 0) { $v='' }
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
    $securityUser=''
    if ($items.ContainsKey('Security')) { $um=$script:RxAttrUser.Match($items['Security'].Groups[2].Value); if ($um.Success) { $securityUser=$um.Groups[1].Value+$um.Groups[2].Value } }
    return New-EventRecord $provider $items['EventID'].Groups[3].Value $channel $computer $rid $level ($tm.Groups[1].Value+$tm.Groups[2].Value) $items['Keywords'].Groups[3].Value $data $XmlText '' $securityUser
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
    $securityUser=''; $securityNode=$sys.SelectSingleNode('e:Security',$ns)
    if ($securityNode) { $securityUser=$securityNode.GetAttribute('UserID') }
    return New-EventRecord $provider $idText $channel $computer $rid $level $systemTime $keywords $data $XmlText $recovery $securityUser
}
$script:UsbDeviceRx='^(USBSTOR\\|SWD\\WPDBUSENUM\\)'
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
            if ($null -eq $r) { return }
            $lt=$e.LogonType
            if ($lt -eq '10') { $r.Title += ' (RemoteInteractive, тип 10)' }
            elseif ($IncludeNetworkLogons -and $e.Id -eq 4624 -and $lt -in @('3','8')) {
                $r.Title = 'Сетевой вход, тип ' + $lt
                $r.Note = 'Сетевой доступ: возможны SMB, WinRM, службы и другие механизмы; не доказательство RDP.'
            } elseif ($e.Id -eq 4624 -and $lt -in @('2','11')) {
                $r.Title = 'Интерактивный вход (тип '+$lt+')'
                $r.Note = 'Вход за консолью компьютера (тип 2) или по кэшированным учетным данным (тип 11). Проверить, кто и когда работал за АРМ/сервером.'
            } elseif ($e.Id -eq 4624 -and $lt -eq '9') {
                $r.Severity = 'Medium'
                $r.Title = 'Вход с новыми учетными данными (тип 9)'
                $r.Note = 'runas /netonly или подстановка учетных данных. LogonProcessName seclogo с пакетом Negotiate характерен для Pass-the-Hash / Overpass-the-Hash.'
            } elseif ($e.Id -eq 4624 -and $lt -eq '8') {
                $r.Severity = 'Medium'
                $r.Title = 'Вход с паролем в открытом виде (тип 8)'
                $r.Note = 'NetworkCleartext: пароль передан серверу в открытом виде (IIS Basic, отдельные скрипты). Проверить источник и необходимость.'
            } else { return }
        }
        if ($r -and $e.Id -in @(4672,4648) -and (Field $d @('SubjectUserSid')) -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
            if (-not $IncludeNoise) { return }
            $r.Severity = 'Info'; $r.Note += ' Встроенная служебная учетная запись.'
        }
        # Computer accounts (NAME$) and Window Manager / font driver sessions (S-1-5-90-*, S-1-5-96-*) are not people.
        if ($r -and $e.Id -in @(4672,4648) -and -not $IncludeNoise -and ((Field $d @('SubjectUserName')).EndsWith('$') -or (Field $d @('SubjectUserSid')) -match '^S-1-5-(90|96)-')) { return }
        if ($r -and $e.Id -in @(4728,4732,4756)) {
            $sid = Field $d @('TargetSid')
            if ($sid -match '^S-1-5-32-(544|548|549|550|551)$|^S-1-5-21-\d+-\d+-\d+-(512|518|519)$') {
                $r.Severity = 'High'; $r.Title += ': привилегированная группа по SID'
                $r.Note = 'Зафиксировано добавление в известную привилегированную группу; проверить MemberSid и согласование. Проверка не вычисляет все эффективные права.'
            } elseif ($sid -eq 'S-1-5-32-555') { $r.Note += ' Группа Remote Desktop Users: предоставление возможности RDP.' }
            elseif ($sid -eq 'S-1-5-32-580') { $r.Note += ' Группа Remote Management Users: возможен удаленный доступ через средства управления/WinRM в зависимости от конфигурации.' }
        }
        # Removable media: only storage / portable devices, not every Plug and Play device.
        if ($r -and $e.Id -eq 6416) {
            $class=Field $d @('ClassName')
            if ((Field $d @('DeviceId')) -notmatch $script:UsbDeviceRx -and $class -notin @('DiskDrive','WPD','CDROM')) { return }
        }
    }
    if ($r -and $e.Provider -eq 'Microsoft-Windows-Kernel-PnP' -and $e.Id -in @(400,410) -and (Field $d @('DeviceInstanceId')) -notmatch $script:UsbDeviceRx) { return }
    if ($r -and $e.Provider -eq 'Microsoft-Windows-Partition' -and $e.Id -eq 1006 -and (Field $d @('BusType')) -notin @('7','12','13')) { return }
    if ($r -and $e.Provider -eq 'Microsoft-Windows-UserPnp' -and $e.Id -in @(20001,20003) -and $e.Xml -notmatch 'USBSTOR|WPDBUSENUM') { return }
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
function Build-Query([string]$Path, [bool]$VendorFile, [bool]$SkipSigma=$false) {
    $queryKey=([string]$VendorFile)+'|'+([string]$SkipSigma)+'|'+$IncludeNoise+'|'+$IncludeNetworkLogons+'|'+$DeepScriptScan+'|'+$IncludeProcessCreation+'|'+$script:GenericErrors+'|'+$MaxEventId+'|'+$script:StartTicks+'|'+$script:EndTicks+'|'+$script:SigmaSelectors.Count
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
        $ids = @($g.Group | Where-Object { ($_.Provider -ne 'Microsoft-Windows-Security-Auditing' -or [int]$_.Id -notin $excludedSecurityIds) -and -not ($_.Provider -eq 'Microsoft-Windows-Partition' -and $_.Id -eq '1006') } | ForEach-Object { [int]$_.Id })
        # Short selectors keep each XPath below Windows Event Log complexity limits.
        for ($i=0; $i -lt $ids.Count; $i+=8) {
            $last = [Math]::Min($i+7,$ids.Count-1)
            $parts = @($ids[$i..$last] | ForEach-Object { 'EventID=' + $_ })
            $selectors.Add("*[System[Provider[@Name='$($g.Name)'] and ($($parts -join ' or '))$time]]")
        }
    }
    $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4634)$time] and EventData[Data[@Name='LogonType']='10']]")
    # Console (2), cached (11), new credentials (9) and cleartext (8) logons: few events, key for "who worked on the host".
    $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4624$time] and EventData[(Data[@Name='LogonType']='2' or Data[@Name='LogonType']='11' or Data[@Name='LogonType']='9' or Data[@Name='LogonType']='8')]]")
    if ($script:Rules.ContainsKey('Microsoft-Windows-Partition|1006')) {
        # Partition/Diagnostic 1006 is logged for every disk at boot; only USB (7), SD (12) and MMC (13) buses matter.
        $selectors.Add("*[System[Provider[@Name='Microsoft-Windows-Partition'] and EventID=1006$time] and EventData[(Data[@Name='BusType']='7' or Data[@Name='BusType']='12' or Data[@Name='BusType']='13')]]")
    }
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
    # Events required by Sigma rules (built by the compiled engine; {TIME} = period filter).
    foreach ($sigmaSelector in $script:SigmaSelectors) {
        if ($SkipSigma) { break }
        $selector=$sigmaSelector.Replace('{TIME}',$time)
        if (-not $selectors.Contains($selector)) { $selectors.Add($selector) }
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
$script:FindingHeaders=@('Номер','Event ID','Record ID','Приоритет','Категория','Событие','Что проверить','Время UTC','Компьютер','Папка источника','Файл журнала','Полный путь','Канал','Провайдер','Уровень Windows','Результат аудита','Инициатор','SID инициатора','Целевая УЗ','SID целевой УЗ','Участник группы','SID участника','IP источника','Порт источника','Рабочая станция','Тип входа','Logon ID цели','Logon ID инициатора','Session ID','Имя сеанса','Status','SubStatus','Процесс','Командная строка','Привилегии','Имя угрозы','Ресурс / путь','Старое время','Новое время','Сдвиг времени, сек','Данные события','Описание Windows','Статус описания','Правило','SHA256 XML события','Восстановление XML')
function New-FindingFile {
    if ($script:FindingWriter) { Close-Writer $script:FindingWriter }
    $script:Part++
    $script:PartRows=0
    $script:FindingWriter=New-Writer (Join-Path $script:RunPath ('Findings-{0:D4}.csv' -f $script:Part))
    Write-Row $script:FindingWriter $script:FindingHeaders
}
# Rows that the priority layer and the media/software/account sheets use go to a
# small TriageInput.csv, so Build-Triage never re-reads every finding.
function Test-TriageInputRow($e,$r) {
    if ($r.RuleId -in @('AV-VENDOR-THREAT','HEURISTIC-COMMAND')) { return $true }
    if (-not $script:TriageInputKeys.Contains($e.Provider+'|'+$e.Id)) { return $false }
    if ($e.Id -eq 4625 -and $e.Provider -eq 'Microsoft-Windows-Security-Auditing') {
        return ($e.LogonType -eq '10' -and (([string]$e.F['SubStatus']) -match '^(0x)?c000006a$' -or ([string]$e.F['Status']) -match '^(0x)?c000006a$'))
    }
    return $true
}
# Same aggregation as LogonSummary.Add in the compiled engine.
$script:LogonAgg=@{}
# Set in the main section (PowerShell mode); Save-Finding also runs in SelfTest.
$script:TriageWriter=$null
function Add-LogonSummary($e) {
    if ($e.Provider -ne 'Microsoft-Windows-Security-Auditing') { return }
    $ip=([string]$e.SourceIP).Trim()
    if ($ip.StartsWith('::ffff:',[StringComparison]::OrdinalIgnoreCase)) { $ip=$ip.Substring(7) }
    if ($ip -eq '-') { $ip='' }
    $source=$ip; if (-not $source) { $source=[string]$e.F['Workstation'] }
    $code=''
    switch ($e.Id) {
        4624 { $result=$script:ResultSuccess; $type=$e.LogonType }
        4625 { $result=$script:ResultFailure; $type=$e.LogonType; $code=([string]$e.F['Status'])+'/'+([string]$e.F['SubStatus']) }
        4771 { $result=$script:ResultFailure; $type='Kerberos'; $code=[string]$e.F['Status'] }
        4776 { $result=$script:ResultFailure; $type='NTLM'; $source=[string]$e.F['Workstation']; $code=[string]$e.F['Status'] }
        default { return }
    }
    $key=($e.Computer+'|'+$e.Target+'|'+$result+'|'+$type+'|'+$source+'|'+$e.Id).ToLowerInvariant()
    $row=$script:LogonAgg[$key]
    if ($null -eq $row) {
        $row=[pscustomobject]@{Computer=$e.Computer;Account=$e.Target;Result=$result;LogonType=$type;Source=$source;EventId=[string]$e.Id;Count=[long]0;First=$e.TimeUtc;Last=$e.TimeUtc;Codes='';FirstTicks=$e.Ticks;LastTicks=$e.Ticks;CodeList=(New-Object 'System.Collections.Generic.List[string]')}
        $script:LogonAgg[$key]=$row
    }
    $row.Count++
    if ($e.Ticks -lt $row.FirstTicks) { $row.FirstTicks=$e.Ticks; $row.First=$e.TimeUtc }
    if ($e.Ticks -gt $row.LastTicks) { $row.LastTicks=$e.Ticks; $row.Last=$e.TimeUtc }
    if ($code -and $code -ne '/' -and $row.CodeList.Count -lt 5) {
        $known=$false; foreach ($c in $row.CodeList) { if ($c -eq $code) { $known=$true; break } }
        if (-not $known) { $row.CodeList.Add($code); $row.Codes=$row.CodeList.ToArray() -join ' | ' }
    }
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
    $actorSid=$f['SubjectUserSid']; if (-not $actorSid) { $actorSid=$f['SecurityUserID'] }
    $values=@($id,$e.Id,$e.RecordId,$sevText,$r.Category,$r.Title,$r.Note,$e.TimeUtc,$e.Computer,
        $file.DirectoryName,$file.Name,$file.FullName,$e.Channel,$e.Provider,$e.Level,$auditText,
        $e.Subject,$actorSid,$e.Target,$f['TargetSid'],
        $f['MemberName'],$f['MemberSid'],$e.SourceIP,$f['Port'],
        $f['Workstation'],$e.LogonType,$e.LogonId,
        $f['SubjectLogonId'],$f['SessionID'],$e.SessionName,
        $f['Status'],$f['SubStatus'],$f['Process'],
        $f['CommandLine'],$f['Privileges'],
        $f['Threat'],$f['Path'],
        $old,$new,$delta,$details,$message,$msgText,$r.RuleId,$e.Fingerprint,$e.XmlRecovery)
    Write-Row $script:FindingWriter $values
    if ($script:TriageWriter -and (Test-TriageInputRow $e $r)) { Write-Row $script:TriageWriter $values }
    if ($e.Id -in @(4624,4625,4771,4776)) { Add-LogonSummary $e }
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
$script:RdpHeaders=@('Event ID начала','Event ID конца','Файл источника','Компьютер','Учетная запись','Logon ID / Session ID','IP источника','Начало UTC','Окончание UTC','Длительность, сек','Длительность (ч:мм:сс)','Статус','Комментарий','Record ID начала','Record ID конца','Номер находки начала','Номер находки конца','Источник данных')
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
# ============================================================== compiled engine
# C# source of the hot path (parsing, rules, findings, failure correlation, logon
# summary) and of the Sigma engine. Compiled once per PowerShell session with
# Add-Type; the namespace contains a hash of the source, so an edited script never
# reuses an outdated type. If compilation is impossible the PowerShell path is used.
$script:EngineSource=@'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

// Compiled hot path of Audit-Evtx.ps1. C# 5 / .NET Framework 4.x compatible
// (Windows PowerShell 5.1 Add-Type). Semantics mirror the PowerShell functions
// Parse-Event, Match-Event, Save-Finding, Save-Failure and Correlate-Failures;
// SelfTest compares both implementations on the same events.
namespace __NS__
{
    internal static class U
    {
        internal static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        internal static readonly char[] XmlWs = new char[] { ' ', '\t', '\n', '\r' };
        static readonly SHA256 Sha = SHA256.Create();
        static readonly char[] HexDigits = "0123456789abcdef".ToCharArray();
        internal static bool EqI(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
        internal static string N(string s) { return s ?? ""; }
        internal static int PsInt(string s)
        {
            if (s == null) return 0;
            s = s.Trim();
            if (s.Length == 0) return 0;
            return int.Parse(s, NumberStyles.Integer, Inv);
        }
        internal static string DecodeEntities(string v)
        {
            if (v.IndexOf('&') < 0) return v;
            return v.Replace("&lt;", "<").Replace("&gt;", ">").Replace("&quot;", "\"").Replace("&apos;", "'").Replace("&amp;", "&");
        }
        // XmlDocument drops whitespace-only text nodes; the fast parsers do the same.
        internal static string NormalizeLeaf(string v)
        {
            if (v.Length > 0 && v.Trim(XmlWs).Length == 0) return "";
            return v;
        }
        internal static string Hash(string text)
        {
            byte[] h;
            lock (Sha) { h = Sha.ComputeHash(Encoding.UTF8.GetBytes(text ?? "")); }
            char[] hex = new char[h.Length * 2];
            for (int i = 0; i < h.Length; i++) { hex[2 * i] = HexDigits[h[i] >> 4]; hex[2 * i + 1] = HexDigits[h[i] & 15]; }
            return new string(hex);
        }
        internal static string Join(string sep, IList<string> items)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < items.Count; i++) { if (i > 0) sb.Append(sep); sb.Append(items[i]); }
            return sb.ToString();
        }
        internal static void AddUnique(List<string> list, string value, int limit, bool ignoreCase)
        {
            if (string.IsNullOrEmpty(value) || list.Count >= limit) return;
            foreach (string s in list) { if (ignoreCase ? EqI(s, value) : string.Equals(s, value, StringComparison.Ordinal)) return; }
            list.Add(value);
        }
        internal static string NormalIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return "";
            string v = ip.Trim();
            if (v.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase)) v = v.Substring(7);
            return v;
        }
        internal static bool IsRemoteIp(string ip)
        {
            string v = NormalIp(ip).ToLowerInvariant();
            return v.Length > 0 && v != "-" && v != "localhost" && v != "127.0.0.1" && v != "::1" && v != "0.0.0.0" && v != "local";
        }
        internal static string UtcText(long ticks)
        {
            return new DateTime(ticks, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss", Inv);
        }
        internal static string Duration(long ticks)
        {
            TimeSpan ts = TimeSpan.FromSeconds(Math.Round(ticks / (double)TimeSpan.TicksPerSecond));
            return ((int)Math.Floor(ts.TotalHours)).ToString(Inv) + ":" + ts.Minutes.ToString("00", Inv) + ":" + ts.Seconds.ToString("00", Inv);
        }
    }

    internal static class Csv
    {
        static readonly Regex Invalid = new Regex(@"[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]");
        const string Truncated = " [обрезано; см. исходный EVTX или Technical Evidence]";
        internal static string Cell(string s, bool safe)
        {
            if (s == null) s = "";
            // Fast path: nothing to escape (most cells). Same result as the slow path.
            bool plain = true;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c < 0x20 || c == '"' || c == '\uFFFE' || c == '\uFFFF') { plain = false; break; }
            }
            if (plain && (!safe || (s.Length <= 30000 && !IsFormula(s)))) return "\"" + s + "\"";
            if (Invalid.IsMatch(s)) s = Invalid.Replace(s, delegate(Match m) { return "[U+" + ((int)m.Value[0]).ToString("X4", U.Inv) + "]"; });
            s = s.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
            if (safe && s.Length > 30000) s = s.Substring(0, 30000) + Truncated;
            if (safe && IsFormula(s)) s = "'" + s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }
        // Same as Regex ^\s*[=+@-]: .NET \s and char.IsWhiteSpace cover the same characters.
        static bool IsFormula(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (char.IsWhiteSpace(c)) continue;
                return c == '=' || c == '+' || c == '@' || c == '-';
            }
            return false;
        }
        internal static void Row(TextWriter w, string delimiter, IList<string> values)
        {
            StringBuilder sb = new StringBuilder(512);
            for (int i = 0; i < values.Count; i++) { if (i > 0) sb.Append(delimiter); sb.Append(Cell(values[i], true)); }
            w.WriteLine(sb.ToString());
        }
    }

    public sealed class RuleDef
    {
        public string Category, Severity, Title, Note, RuleId;
        public RuleDef Clone() { return (RuleDef)MemberwiseClone(); }
    }

    // Parsed event. Field names match the PowerShell event object so the RDP code
    // in PowerShell can use either implementation.
    public sealed class EvtEvent
    {
        public string Provider = "";
        public int Id;
        public string Channel = "";
        public string Computer = "";
        public string RecordId = "";
        public int Level;
        public string TimeUtc = "";
        public long Ticks;
        public string AuditOutcome = "";
        public string Xml = "";
        public string XmlRecovery = "";
        public string Subject = "";
        public string Target = "";
        public string SourceIP = "";
        public string LogonType = "";
        public string LogonId = "";
        public string SessionName = "";
        public string Message = "";
        public string MessageStatus = "NotRequested";
        public string Fingerprint = "";
        public string SecurityUserId = "";
        public string KeywordsText = "";
        public readonly List<string> Keys = new List<string>();
        public readonly List<string> Values = new List<string>();
        public readonly Hashtable F = new Hashtable(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, int> index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        public string GetData(string name)
        {
            int i;
            return index.TryGetValue(name, out i) ? Values[i] : null;
        }
        public bool HasData(string name) { return index.ContainsKey(name); }
        // Same semantics as the PowerShell Field function.
        public string FieldValue(params string[] names)
        {
            foreach (string n in names)
            {
                string v = GetData(n);
                if (v != null && !string.IsNullOrWhiteSpace(v) && v != "-") return v;
            }
            return "";
        }
        public string Get(string key) { object o = F[key]; return o == null ? "" : (string)o; }
        internal void AddRaw(string name, string value)
        {
            index[name] = Keys.Count;
            Keys.Add(name);
            Values.Add(value);
        }
        internal void AddEventData(string rawName, string value, ref int i)
        {
            string name = rawName;
            if (string.IsNullOrEmpty(name)) name = "Data" + i.ToString(U.Inv);
            if (index.ContainsKey(name)) name = name + "#" + i.ToString(U.Inv);
            AddRaw(name, value);
            i++;
        }
        internal void AddUserData(string localName, string value, ref int i)
        {
            string name = localName;
            if (index.ContainsKey(name)) name = "UserData." + name + "#" + i.ToString(U.Inv);
            AddRaw(name, value);
            i++;
        }
        internal void Complete(Engine eng, string idText, string levelText, string systemTime, string keywords)
        {
            DateTimeOffset time = DateTimeOffset.Parse(systemTime, U.Inv);
            DateTime utc = time.UtcDateTime;
            TimeUtc = utc.ToString("o", U.Inv);
            Ticks = utc.Ticks;
            Id = U.PsInt(idText);
            Level = U.PsInt(levelText);
            KeywordsText = keywords ?? "";
            AuditOutcome = "";
            if (!string.IsNullOrEmpty(keywords))
            {
                string k = keywords;
                if (k.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) k = k.Substring(2);
                ulong kw = Convert.ToUInt64(k, 16);
                if ((kw & 4503599627370496UL) != 0) AuditOutcome = "Failure";
                else if ((kw & 9007199254740992UL) != 0) AuditOutcome = "Success";
            }
            FillFields(eng);
        }
        internal void FillFields(Engine eng)
        {
            Dictionary<string, int> rank = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < Keys.Count; i++)
            {
                List<KeyValuePair<string, int>> targets;
                if (!eng.FieldIndex.TryGetValue(Keys[i], out targets)) continue;
                string v = Values[i];
                if (string.IsNullOrWhiteSpace(v) || v == "-") continue;
                foreach (KeyValuePair<string, int> t in targets)
                {
                    int r;
                    if (!rank.TryGetValue(t.Key, out r) || t.Value < r) { F[t.Key] = v; rank[t.Key] = t.Value; }
                }
            }
            if (!string.IsNullOrEmpty(SecurityUserId)) F["SecurityUserID"] = SecurityUserId;
            string su = Get("SubjectUserName"), sd = Get("SubjectDomainName");
            Subject = su.Length == 0 ? "" : (sd.Length > 0 ? sd + "\\" + su : su);
            string tu = Get("TargetUser"), td = Get("TargetDomain");
            Target = tu.Length == 0 ? "" : (td.Length > 0 ? td + "\\" + tu : tu);
            SourceIP = Get("SourceIP");
            LogonType = Get("LogonType");
            LogonId = Get("LogonId");
            SessionName = Get("SessionName");
        }
    }

    // Regex fast path for the XML that Windows renders. Returns null for anything
    // unusual; PowerShell then uses the full XmlDocument parser.
    internal static class FastParser
    {
        // Compiled once per process: these run for every selected event.
        const RegexOptions Opt = RegexOptions.CultureInvariant | RegexOptions.Compiled;
        static readonly Regex RxHead = new Regex(@"^<Event xmlns=(['""])http://schemas\.microsoft\.com/win/2004/08/events/event\1>", Opt);
        static readonly Regex RxAttrName = new Regex(@"\sName=(?:'([^']*)'|""([^""]*)"")", Opt);
        static readonly Regex RxAttrTime = new Regex(@"\sSystemTime=(?:'([^']*)'|""([^""]*)"")", Opt);
        static readonly Regex RxAttrUser = new Regex(@"\sUserID=(?:'([^']*)'|""([^""]*)"")", Opt);
        static readonly Regex RxDataRest = new Regex(@"^(?:<Binary>[0-9A-Fa-f]*</Binary>)?$", Opt);
        static readonly Regex RxTag = new Regex(@"<(/?)([A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*)((?:\s+[^\s=/>]+\s*=\s*(?:'[^']*'|""[^""]*""))*)\s*(/?)>|([^<]+)", Opt);

        sealed class Frame { public string Qualified; public string Local; public bool HasChild; public StringBuilder Text = new StringBuilder(); }
        // <Name attrs/> or <Name attrs>text</Name> inside System.
        sealed class SysItem { public string Attrs = ""; public string Text = ""; }
        static readonly Dictionary<string, bool> SysNames = NewSet("Provider", "EventID", "Level", "Keywords", "TimeCreated", "EventRecordID", "Channel", "Computer", "Security");
        static Dictionary<string, bool> NewSet(params string[] names)
        {
            Dictionary<string, bool> d = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (string n in names) d[n] = true;
            return d;
        }

        internal static EvtEvent TryParse(string xml, Engine eng)
        {
            if (xml == null || !RxHead.IsMatch(xml) || HasUnsafe(xml)) return null;
            int sysStart = xml.IndexOf("<System>", StringComparison.Ordinal);
            int sysEnd = xml.IndexOf("</System>", StringComparison.Ordinal);
            if (sysStart < 0 || sysEnd < sysStart || xml.IndexOf("<System>", sysStart + 8, StringComparison.Ordinal) >= 0) return null;
            string sys = xml.Substring(sysStart + 8, sysEnd - sysStart - 8);
            if (sys.IndexOf('&') >= 0) return null;
            Dictionary<string, SysItem> items = ScanSystem(sys);
            if (!items.ContainsKey("Provider") || !items.ContainsKey("EventID") || !items.ContainsKey("TimeCreated") || !items.ContainsKey("Keywords")) return null;
            Match pm = RxAttrName.Match(items["Provider"].Attrs);
            if (!pm.Success) return null;
            Match tm = RxAttrTime.Match(items["TimeCreated"].Attrs);
            if (!tm.Success) return null;
            EvtEvent e = new EvtEvent();
            e.Xml = xml;
            e.Provider = pm.Groups[1].Value + pm.Groups[2].Value;
            int i = 0;
            int edStart = xml.IndexOf("<EventData>", StringComparison.Ordinal);
            if (edStart >= 0)
            {
                int edEnd = xml.IndexOf("</EventData>", edStart, StringComparison.Ordinal);
                if (edEnd < 0 || xml.IndexOf("<EventData>", edEnd, StringComparison.Ordinal) >= 0) return null;
                string body = xml.Substring(edStart + 11, edEnd - edStart - 11);
                // Text between the Data elements must be empty or one <Binary> element.
                StringBuilder rest = null;
                int pos = 0, at = 0;
                while ((at = body.IndexOf('<', at)) >= 0)
                {
                    string dataName, dataValue; int end;
                    if (!TryData(body, at, out dataName, out dataValue, out end)) { at++; continue; }
                    if (at > pos) { if (rest == null) rest = new StringBuilder(); rest.Append(body, pos, at - pos); }
                    pos = end; at = end;
                    e.AddEventData(dataName, U.NormalizeLeaf(U.DecodeEntities(dataValue)), ref i);
                }
                if (pos < body.Length) { if (rest == null) rest = new StringBuilder(); rest.Append(body, pos, body.Length - pos); }
                if (rest != null && !RxDataRest.IsMatch(rest.ToString())) return null;
            }
            int udStart = xml.IndexOf("<UserData>", StringComparison.Ordinal);
            if (udStart >= 0)
            {
                int udEnd = xml.IndexOf("</UserData>", udStart, StringComparison.Ordinal);
                if (udEnd < 0 || xml.IndexOf("<UserData>", udEnd, StringComparison.Ordinal) >= 0) return null;
                if (!ParseUserData(xml.Substring(udStart + 10, udEnd - udStart - 10), e, ref i)) return null;
            }
            string level = "0", channel = "", computer = "", rid = "";
            SysItem it;
            if (items.TryGetValue("Level", out it)) { level = it.Text; if (level.Length == 0) level = "0"; }
            if (items.TryGetValue("Channel", out it)) channel = it.Text;
            if (items.TryGetValue("Computer", out it)) computer = it.Text;
            if (items.TryGetValue("EventRecordID", out it)) rid = it.Text;
            if (items.TryGetValue("Security", out it))
            {
                Match um = RxAttrUser.Match(it.Attrs);
                if (um.Success) e.SecurityUserId = um.Groups[1].Value + um.Groups[2].Value;
            }
            e.Channel = channel; e.Computer = computer; e.RecordId = rid;
            e.Complete(eng, items["EventID"].Text, level, tm.Groups[1].Value + tm.Groups[2].Value, items["Keywords"].Text);
            return e;
        }

        // Characters and constructs the regex path does not handle (same set as the former
        // regex [\x00-\x08\x0B\x0C\x0E-\x1F\r\uFFFE\uFFFF]|<!|&#|<\?|<EventData[ /]|<UserData[ /]|&(?!(lt|gt|amp|quot|apos);)).
        static bool HasUnsafe(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c < 0x20) { if (c != '\t' && c != '\n') return true; continue; }
                if (c == '\uFFFE' || c == '\uFFFF') return true;
                if (c == '<')
                {
                    if (i + 1 < s.Length && (s[i + 1] == '!' || s[i + 1] == '?')) return true;
                    if (At(s, i, "<EventData ") || At(s, i, "<EventData/") || At(s, i, "<UserData ") || At(s, i, "<UserData/")) return true;
                }
                else if (c == '&')
                {
                    if (!(At(s, i, "&lt;") || At(s, i, "&gt;") || At(s, i, "&amp;") || At(s, i, "&quot;") || At(s, i, "&apos;"))) return true;
                }
            }
            return false;
        }
        static bool At(string s, int i, string token) { return string.CompareOrdinal(s, i, token, 0, token.Length) == 0; }
        static bool IsWord(char c) { return char.IsLetterOrDigit(c) || c == '_'; }

        // Hand-written equivalent of the former regex, first match per element name:
        // <(Provider|EventID|...|Security)\b([^>]*?)(?:/>|>([^<]*)</\1>)
        static Dictionary<string, SysItem> ScanSystem(string sys)
        {
            Dictionary<string, SysItem> items = new Dictionary<string, SysItem>(StringComparer.Ordinal);
            int i = 0;
            while ((i = sys.IndexOf('<', i)) >= 0)
            {
                int p = i + 1;
                while (p < sys.Length && IsWord(sys[p])) p++;
                string name = sys.Substring(i + 1, p - i - 1);
                int gt = SysNames.ContainsKey(name) ? sys.IndexOf('>', p) : -1;
                if (gt < 0) { i++; continue; }
                SysItem item = new SysItem();
                int end;
                if (gt > p && sys[gt - 1] == '/') { item.Attrs = sys.Substring(p, gt - 1 - p); end = gt + 1; }
                else
                {
                    int lt = sys.IndexOf('<', gt + 1);
                    if (lt < 0 || !At(sys, lt, "</" + name + ">")) { i++; continue; }
                    item.Attrs = sys.Substring(p, gt - p); item.Text = sys.Substring(gt + 1, lt - gt - 1);
                    end = lt + name.Length + 3;
                }
                if (!items.ContainsKey(name)) items[name] = item;
                i = end;
            }
            return items;
        }
        // Hand-written equivalent of <Data(?: Name=(?:'([^']*)'|"([^"]*)"))?\s*(?:/>|>([^<]*)</Data>) at position at.
        static bool TryData(string s, int at, out string name, out string value, out int end)
        {
            name = ""; value = ""; end = at;
            if (!At(s, at, "<Data")) return false;
            int p = at + 5;
            if (At(s, p, " Name=") && p + 6 < s.Length && (s[p + 6] == '\'' || s[p + 6] == '"'))
            {
                int close = s.IndexOf(s[p + 6], p + 7);
                if (close < 0) return false;
                name = s.Substring(p + 7, close - p - 7);
                p = close + 1;
            }
            while (p < s.Length && char.IsWhiteSpace(s[p])) p++;
            if (At(s, p, "/>")) { end = p + 2; return true; }
            if (p >= s.Length || s[p] != '>') return false;
            int lt = s.IndexOf('<', p + 1);
            if (lt < 0 || !At(s, lt, "</Data>")) return false;
            value = s.Substring(p + 1, lt - p - 1);
            end = lt + 7;
            return true;
        }

        // Leaf elements of UserData in document order, as XPath //*[not(*)] returns them.
        static bool ParseUserData(string body, EvtEvent e, ref int i)
        {
            List<Frame> stack = new List<Frame>();
            int p = 0;
            while (p < body.Length)
            {
                Match m = RxTag.Match(body, p);
                if (!m.Success || m.Index != p) return false;
                p += m.Length;
                if (m.Groups[6].Success)
                {
                    if (stack.Count > 0) stack[stack.Count - 1].Text.Append(m.Groups[6].Value);
                    continue;
                }
                string qualified = m.Groups[2].Value + m.Groups[3].Value;
                bool closing = m.Groups[1].Value == "/";
                bool selfClosing = m.Groups[5].Value == "/";
                if (closing)
                {
                    if (selfClosing || m.Groups[4].Value.Trim().Length != 0) return false;
                    if (stack.Count == 0 || stack[stack.Count - 1].Qualified != qualified) return false;
                    Frame f = stack[stack.Count - 1];
                    stack.RemoveAt(stack.Count - 1);
                    if (!f.HasChild) e.AddUserData(f.Local, U.NormalizeLeaf(U.DecodeEntities(f.Text.ToString())), ref i);
                }
                else if (selfClosing)
                {
                    if (stack.Count > 0) stack[stack.Count - 1].HasChild = true;
                    e.AddUserData(m.Groups[3].Value, "", ref i);
                }
                else
                {
                    if (stack.Count > 0) stack[stack.Count - 1].HasChild = true;
                    Frame f = new Frame();
                    f.Qualified = qualified; f.Local = m.Groups[3].Value;
                    stack.Add(f);
                }
            }
            return stack.Count == 0;
        }
    }

    public sealed class SummaryRow
    {
        public string Severity { get; set; }
        public string Category { get; set; }
        public string Computer { get; set; }
        public long Count { get; set; }
    }

    public sealed class LogonRow
    {
        public string Computer { get; set; }
        public string Account { get; set; }
        public string Result { get; set; }
        public string LogonType { get; set; }
        public string Source { get; set; }
        public string EventId { get; set; }
        public long Count { get; set; }
        public string First { get; set; }
        public string Last { get; set; }
        public string Codes { get; set; }
        internal long FirstTicks, LastTicks;
        internal List<string> CodeList = new List<string>();
    }

    public sealed class FileResult
    {
        public string[] Channels { get; set; }
        public string[] Computers { get; set; }
    }

    sealed class FailureRec
    {
        public long Ticks; public string TimeUtc, Computer, Scope, Account, Source, Fingerprint, File, RecordId, Status, SubStatus;
        public int EventId; public long FindingId;
    }

    sealed class FailureGroup
    {
        public readonly Queue<FailureRec> Queue = new Queue<FailureRec>();
        public long LastAlert;
        public readonly Dictionary<string, int> UserCounts = new Dictionary<string, int>(StringComparer.Ordinal);
    }

    // Logon aggregation shared by both engines (PowerShell has the same rules in Add-LogonSummary).
    internal static class LogonSummary
    {
        internal static void Add(Dictionary<string, LogonRow> agg, EvtEvent e, string resultSuccess, string resultFailure)
        {
            if (!U.EqI(e.Provider, "Microsoft-Windows-Security-Auditing")) return;
            string result, type, account = e.Target, source;
            string ip = U.NormalIp(e.SourceIP);
            if (ip == "-") ip = "";
            source = ip.Length > 0 ? ip : e.Get("Workstation");
            string code = "";
            switch (e.Id)
            {
                case 4624: result = resultSuccess; type = e.LogonType; break;
                case 4625: result = resultFailure; type = e.LogonType; code = e.Get("Status") + "/" + e.Get("SubStatus"); break;
                case 4771: result = resultFailure; type = "Kerberos"; code = e.Get("Status"); break;
                case 4776: result = resultFailure; type = "NTLM"; source = e.Get("Workstation"); code = e.Get("Status"); break;
                default: return;
            }
            string key = (e.Computer + "|" + account + "|" + result + "|" + type + "|" + source + "|" + e.Id.ToString(U.Inv)).ToLowerInvariant();
            LogonRow row;
            if (!agg.TryGetValue(key, out row))
            {
                row = new LogonRow();
                row.Computer = e.Computer; row.Account = account; row.Result = result; row.LogonType = type; row.Source = source;
                row.EventId = e.Id.ToString(U.Inv); row.FirstTicks = e.Ticks; row.LastTicks = e.Ticks; row.First = e.TimeUtc; row.Last = e.TimeUtc;
                agg[key] = row;
            }
            row.Count++;
            if (e.Ticks < row.FirstTicks) { row.FirstTicks = e.Ticks; row.First = e.TimeUtc; }
            if (e.Ticks > row.LastTicks) { row.LastTicks = e.Ticks; row.Last = e.TimeUtc; }
            if (code.Length > 0 && code != "/") U.AddUnique(row.CodeList, code, 5, true);
            row.Codes = U.Join(" | ", row.CodeList);
        }
    }

    public sealed class Engine : IDisposable
    {
        public const string Version = "10.0.0";
        // Configuration (set by PowerShell before Open()).
        public bool IncludeNoise, IncludeNetworkLogons, DeepScriptScan, IncludeProcessCreation, IncludeAllAntivirusEvents, GenericErrors, SkipCorrelation, KeepEvidence;
        public int MaxEventId = 10000, FailureThreshold = 10, WindowMinutes = 10, SprayUserThreshold = 5, RowsPerCsv = 500000;
        public bool HasStart, HasEnd;
        public long StartTicks, EndTicks;
        public string Delimiter = ";";
        public string RunPath = "";
        public string[] FindingHeaders = new string[0];
        public string ResultSuccess = "Success", ResultFailure = "Failure";
        public SigmaEngine Sigma;

        // State.
        public long FindingCount;
        public long LastFindingId;
        public double LastRollbackSeconds;
        public int BurstCount;
        internal readonly Dictionary<string, List<KeyValuePair<string, int>>> FieldIndex = new Dictionary<string, List<KeyValuePair<string, int>>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, RuleDef> rules = new Dictionary<string, RuleDef>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, string> sevMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, string> auditMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, string> msgMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, bool> triageKeys = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, bool> rdpKeys = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, SummaryRow> summary = new Dictionary<string, SummaryRow>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, LogonRow> logons = new Dictionary<string, LogonRow>(StringComparer.Ordinal);
        readonly Dictionary<string, List<FailureRec>> failures = new Dictionary<string, List<FailureRec>>(StringComparer.Ordinal);
        StreamWriter findingWriter, triageWriter, evidenceWriter;
        int part, partRows;
        long seq;
        // Current file.
        string fileFull = "", fileDir = "", fileName = "";
        bool vendorFile;
        readonly Dictionary<string, long> lastTimes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> channels = new List<string>();
        readonly List<string> computers = new List<string>();
        readonly Dictionary<string, bool> channelSet = new Dictionary<string, bool>(StringComparer.Ordinal);
        readonly Dictionary<string, bool> computerSet = new Dictionary<string, bool>(StringComparer.Ordinal);

        static readonly Regex ZeroStatus = new Regex("^(0x)?0+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex PrivilegedGroup = new Regex(@"^S-1-5-32-(544|548|549|550|551)$|^S-1-5-21-\d+-\d+-\d+-(512|518|519)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex DwmUmfd = new Regex("^S-1-5-(90|96)-", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex UsbDevice = new Regex(@"^(USBSTOR\\|SWD\\WPDBUSENUM\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex UsbText = new Regex("USBSTOR|WPDBUSENUM", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex BadPassword = new Regex("^(0x)?c000006a$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex Ffff = new Regex("^::ffff:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex CommandHeuristic = new Regex(@"(?i)(-(enc|encodedcommand)\s|FromBase64String|DownloadString|Invoke-Expression|\biex\s|wevtutil\s+(cl|clear-log)\b|Clear-EventLog|vssadmin\s+delete\s+shadows|Set-MpPreference.+Disable|Add-MpPreference.+Exclusion)", RegexOptions.CultureInvariant);
        static readonly Regex VendorNegative = new Regex("(?i)(no\\s+threats?\\s+(were\\s+)?found|no\\s+malware\\s+(was\\s+)?found|угроз\\s+не\\s+обнаружено|вредоносн\\w*\\s+не\\s+обнаружено|заражени\\w*\\s+не\\s+обнаружено)", RegexOptions.CultureInvariant);
        static readonly Regex VendorThreat = new Regex("(?i)(infected|infection|malware|trojan|ransomware|virus|threat\\s+(was\\s+)?detected|quarantin|угроз|заражен|вредонос|троян|вирус|обнаружен\\w*\\s+угроз|карантин)", RegexOptions.CultureInvariant);
        const string Security = "Microsoft-Windows-Security-Auditing";
        const string Cut = " [обрезано; полный текст смотрите в исходном EVTX или техническом Evidence при -KeepTechnicalFiles]";

        public void SetFieldSpecs(object[] specs)
        {
            FieldIndex.Clear();
            foreach (object o in specs)
            {
                object[] spec = (object[])o;
                string key = (string)spec[0];
                for (int n = 1; n < spec.Length; n++)
                {
                    string name = (string)spec[n];
                    List<KeyValuePair<string, int>> l;
                    if (!FieldIndex.TryGetValue(name, out l)) { l = new List<KeyValuePair<string, int>>(); FieldIndex[name] = l; }
                    l.Add(new KeyValuePair<string, int>(key, n));
                }
            }
        }
        public void AddRule(string provider, string id, string category, string severity, string title, string note)
        {
            RuleDef r = new RuleDef();
            r.Category = category; r.Severity = severity; r.Title = title; r.Note = note;
            rules[provider + "|" + id] = r;
        }
        public void SetMap(string map, string key, string value)
        {
            if (map == "Severity") sevMap[key] = value;
            else if (map == "Audit") auditMap[key] = value;
            else if (map == "Message") msgMap[key] = value;
        }
        public void AddTriageKey(string key) { triageKeys[key] = true; }
        public void AddRdpKey(string key) { rdpKeys[key] = true; }

        public void Open()
        {
            NewFindingFile();
            triageWriter = NewWriter(Path.Combine(RunPath, "TriageInput.csv"));
            Csv.Row(triageWriter, Delimiter, FindingHeaders);
        }
        StreamWriter NewWriter(string path)
        {
            return new StreamWriter(path, false, new UTF8Encoding(true), 65536);
        }
        void NewFindingFile()
        {
            if (findingWriter != null) findingWriter.Dispose();
            part++;
            partRows = 0;
            findingWriter = NewWriter(Path.Combine(RunPath, "Findings-" + part.ToString("D4", U.Inv) + ".csv"));
            Csv.Row(findingWriter, Delimiter, FindingHeaders);
        }
        public void Flush()
        {
            if (findingWriter != null) findingWriter.Flush();
            if (triageWriter != null) triageWriter.Flush();
            if (evidenceWriter != null) evidenceWriter.Flush();
        }

        public void BeginFile(string fullName, string dirName, string name, bool vendor, string evidencePath)
        {
            fileFull = fullName ?? ""; fileDir = dirName ?? ""; fileName = name ?? ""; vendorFile = vendor;
            lastTimes.Clear(); channels.Clear(); computers.Clear(); channelSet.Clear(); computerSet.Clear();
            if (evidenceWriter != null) { evidenceWriter.Dispose(); evidenceWriter = null; }
            if (KeepEvidence && !string.IsNullOrEmpty(evidencePath)) evidenceWriter = NewWriter(evidencePath);
        }
        public FileResult EndFile()
        {
            if (evidenceWriter != null) { evidenceWriter.Dispose(); evidenceWriter = null; }
            Flush();
            FileResult r = new FileResult();
            r.Channels = channels.ToArray();
            r.Computers = computers.ToArray();
            return r;
        }

        public EvtEvent Parse(string xml) { return FastParser.TryParse(xml, this); }
        // Event already parsed by the PowerShell XmlDocument path (unusual or recovered XML).
        public EvtEvent FromPs(string provider, int id, string channel, string computer, string recordId, int level, string timeUtc, long ticks,
            string audit, string[] keys, string[] values, string xml, string recovery, string securityUserId)
        {
            EvtEvent e = new EvtEvent();
            e.Provider = provider ?? ""; e.Id = id; e.Channel = channel ?? ""; e.Computer = computer ?? ""; e.RecordId = recordId ?? ""; e.Level = level;
            e.TimeUtc = timeUtc ?? ""; e.Ticks = ticks; e.AuditOutcome = audit ?? ""; e.Xml = xml ?? ""; e.XmlRecovery = recovery ?? ""; e.SecurityUserId = securityUserId ?? "";
            for (int i = 0; i < keys.Length; i++) e.AddRaw(keys[i], values[i] ?? "");
            e.FillFields(this);
            return e;
        }
        public bool WantsMessage(EvtEvent e) { return vendorFile || Match(e) != null; }

        // Flags: 1 = RDP-relevant, 2 = clock rollback >= 5 minutes, 4 = outside -StartTime/-EndTime.
        public int Commit(EvtEvent e)
        {
            LastFindingId = 0;
            if (!channelSet.ContainsKey(e.Channel)) { channelSet[e.Channel] = true; channels.Add(e.Channel); }
            if (!computerSet.ContainsKey(e.Computer)) { computerSet[e.Computer] = true; computers.Add(e.Computer); }
            if ((HasStart && e.Ticks < StartTicks) || (HasEnd && e.Ticks > EndTicks)) return 4;
            int flags = 0;
            long previous;
            if (lastTimes.TryGetValue(e.Computer, out previous) && e.Ticks < previous)
            {
                double seconds = Math.Round((previous - e.Ticks) / (double)TimeSpan.TicksPerSecond, 3);
                if (seconds >= 300) { flags |= 2; LastRollbackSeconds = seconds; }
            }
            lastTimes[e.Computer] = e.Ticks;
            seq++;
            RuleDef r = Match(e);
            List<SigmaRule> sigmaHits = Sigma != null ? Sigma.Evaluate(e) : null;
            if (r == null && sigmaHits != null) r = Sigma.FindingRule(sigmaHits);
            long id = 0;
            if (r != null)
            {
                e.Fingerprint = U.Hash(e.Xml);
                id = WriteFinding(e, r);
                if (!SkipCorrelation && e.Id >= 4625 && (e.Id == 4625 || e.Id == 4771 || e.Id == 4776)) AddFailure(e, id);
                LogonSummary.Add(logons, e, ResultSuccess, ResultFailure);
            }
            if (sigmaHits != null)
            {
                if (e.Fingerprint.Length == 0) e.Fingerprint = U.Hash(e.Xml);
                Sigma.Record(e, sigmaHits, fileDir, fileName, fileFull, id, seq);
            }
            LastFindingId = id;
            if (rdpKeys.ContainsKey(e.Provider + "|" + e.Id.ToString(U.Inv))) flags |= 1;
            return flags;
        }

        public RuleDef Match(EvtEvent e)
        {
            if (e.Id > MaxEventId) return null;
            string key = e.Provider + "|" + e.Id.ToString(U.Inv);
            RuleDef r = null, orig;
            if (rules.TryGetValue(key, out orig)) { r = orig.Clone(); r.RuleId = key; }
            if (U.EqI(e.Provider, Security))
            {
                if (e.Id == 4776)
                {
                    string status = e.FieldValue("Status");
                    if (ZeroStatus.IsMatch(status)) return null;
                    if (status.Length == 0 && r != null) r.Note += " Код результата отсутствует; исход неизвестен.";
                }
                if (e.Id == 4624 || e.Id == 4634)
                {
                    if (r == null) return null;
                    string lt = e.LogonType;
                    if (U.EqI(lt, "10")) r.Title += " (RemoteInteractive, тип 10)";
                    else if (IncludeNetworkLogons && e.Id == 4624 && (lt == "3" || lt == "8"))
                    {
                        r.Title = "Сетевой вход, тип " + lt;
                        r.Note = "Сетевой доступ: возможны SMB, WinRM, службы и другие механизмы; не доказательство RDP.";
                    }
                    else if (e.Id == 4624 && (lt == "2" || lt == "11"))
                    {
                        r.Title = "Интерактивный вход (тип " + lt + ")";
                        r.Note = "Вход за консолью компьютера (тип 2) или по кэшированным учетным данным (тип 11). Проверить, кто и когда работал за АРМ/сервером.";
                    }
                    else if (e.Id == 4624 && lt == "9")
                    {
                        r.Severity = "Medium";
                        r.Title = "Вход с новыми учетными данными (тип 9)";
                        r.Note = "runas /netonly или подстановка учетных данных. LogonProcessName seclogo с пакетом Negotiate характерен для Pass-the-Hash / Overpass-the-Hash.";
                    }
                    else if (e.Id == 4624 && lt == "8")
                    {
                        r.Severity = "Medium";
                        r.Title = "Вход с паролем в открытом виде (тип 8)";
                        r.Note = "NetworkCleartext: пароль передан серверу в открытом виде (IIS Basic, отдельные скрипты). Проверить источник и необходимость.";
                    }
                    else return null;
                }
                if (r != null && (e.Id == 4672 || e.Id == 4648))
                {
                    string sid = e.FieldValue("SubjectUserSid");
                    if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || U.EqI(sid, "S-1-5-18") || U.EqI(sid, "S-1-5-19") || U.EqI(sid, "S-1-5-20"))
                    {
                        if (!IncludeNoise) return null;
                        r.Severity = "Info"; r.Note += " Встроенная служебная учетная запись.";
                    }
                    if (!IncludeNoise && (e.FieldValue("SubjectUserName").EndsWith("$", StringComparison.Ordinal) || DwmUmfd.IsMatch(sid))) return null;
                }
                if (e.Id == 4728 || e.Id == 4732 || e.Id == 4756)
                {
                    string sid = e.FieldValue("TargetSid");
                    if (r != null)
                    {
                        if (PrivilegedGroup.IsMatch(sid))
                        {
                            r.Severity = "High"; r.Title += ": привилегированная группа по SID";
                            r.Note = "Зафиксировано добавление в известную привилегированную группу; проверить MemberSid и согласование. Проверка не вычисляет все эффективные права.";
                        }
                        else if (U.EqI(sid, "S-1-5-32-555")) r.Note += " Группа Remote Desktop Users: предоставление возможности RDP.";
                        else if (U.EqI(sid, "S-1-5-32-580")) r.Note += " Группа Remote Management Users: возможен удаленный доступ через средства управления/WinRM в зависимости от конфигурации.";
                    }
                }
                if (r != null && e.Id == 6416)
                {
                    string cls = e.FieldValue("ClassName");
                    if (!UsbDevice.IsMatch(e.FieldValue("DeviceId")) && !U.EqI(cls, "DiskDrive") && !U.EqI(cls, "WPD") && !U.EqI(cls, "CDROM")) return null;
                }
            }
            if (r != null && U.EqI(e.Provider, "Microsoft-Windows-Kernel-PnP") && (e.Id == 400 || e.Id == 410) && !UsbDevice.IsMatch(e.FieldValue("DeviceInstanceId"))) return null;
            if (r != null && U.EqI(e.Provider, "Microsoft-Windows-Partition") && e.Id == 1006)
            {
                string bus = e.FieldValue("BusType");
                if (bus != "7" && bus != "12" && bus != "13") return null;
            }
            if (r != null && U.EqI(e.Provider, "Microsoft-Windows-UserPnp") && (e.Id == 20001 || e.Id == 20003) && !UsbText.IsMatch(e.Xml)) return null;
            bool scriptCandidate = DeepScriptScan && U.EqI(e.Provider, "Microsoft-Windows-PowerShell") && e.Id == 4104;
            bool processCandidate = IncludeProcessCreation && ((U.EqI(e.Provider, Security) && e.Id == 4688) || (U.EqI(e.Provider, "Microsoft-Windows-Sysmon") && e.Id == 1));
            if (scriptCandidate || processCandidate)
            {
                string text = e.FieldValue("CommandLine", "ScriptBlockText");
                if (CommandHeuristic.IsMatch(text))
                {
                    r = new RuleDef();
                    r.Category = "Подозрительные команды"; r.Severity = "Medium"; r.Title = "Эвристика: команда требует проверки";
                    r.Note = "Возможны штатные скрипты и цитирование кода. 4104 может быть разбит на части: восстановление и декодирование не выполняются.";
                    r.RuleId = "HEURISTIC-COMMAND";
                }
            }
            if (vendorFile && r == null)
            {
                string vendorText = e.Xml + " " + e.Message;
                bool negative = VendorNegative.IsMatch(vendorText);
                bool threat = VendorThreat.IsMatch(vendorText);
                if (threat && !negative)
                {
                    r = new RuleDef(); r.Category = "Антивирус"; r.Severity = "High"; r.Title = "Сторонний антивирус: возможное обнаружение угрозы";
                    r.Note = "Эвристика по XML/описанию. Проверить точное действие, объект, результат лечения и контекст в исходном EVTX."; r.RuleId = "AV-VENDOR-THREAT";
                }
                else if (e.Level == 1 || e.Level == 2)
                {
                    r = new RuleDef(); r.Category = "Антивирус"; r.Severity = e.Level == 1 ? "High" : "Medium"; r.Title = "Сторонний антивирус: Critical/Error";
                    r.Note = "Ошибка/критическое событие продукта защиты. Проверить описание и XML в исходном EVTX."; r.RuleId = "AV-VENDOR-ERROR";
                }
                else if (IncludeAllAntivirusEvents)
                {
                    r = new RuleDef(); r.Category = "Антивирус: ручная проверка"; r.Severity = "Info"; r.Title = "Событие стороннего антивируса";
                    r.Note = "Включен -IncludeAllAntivirusEvents. Точное значение Event ID зависит от продукта/версии."; r.RuleId = "AV-VENDOR-REVIEW";
                }
            }
            if (r == null && GenericErrors && (e.Level == 1 || e.Level == 2))
            {
                r = new RuleDef(); r.Category = "Сбои"; r.Severity = e.Level == 1 ? "High" : "Medium"; r.Title = "Событие уровня Critical/Error";
                r.Note = "Операционная неисправность; связь с ИБ требует отдельной проверки."; r.RuleId = "GENERIC-LEVEL-" + e.Level.ToString(U.Inv);
            }
            return r;
        }

        string Map(Dictionary<string, string> map, string key)
        {
            string v;
            return map.TryGetValue(key ?? "", out v) ? v : U.N(key);
        }

        long WriteFinding(EvtEvent e, RuleDef r)
        {
            if (partRows >= RowsPerCsv) NewFindingFile();
            FindingCount++; partRows++;
            long id = FindingCount;
            StringBuilder details = new StringBuilder();
            for (int i = 0; i < e.Keys.Count; i++)
            {
                if (i > 0) details.Append(" | ");
                details.Append(e.Keys[i]).Append('=').Append(e.Values[i]);
            }
            string detailText = details.ToString();
            if (detailText.Length > 4000) detailText = detailText.Substring(0, 4000) + Cut;
            string message = U.N(e.Message);
            if (message.Length > 8000) message = message.Substring(0, 8000) + Cut;
            string oldTime = e.Get("OldTime"), newTime = e.Get("NewTime"), delta = "";
            if (oldTime.Length > 0 && newTime.Length > 0)
            {
                try { delta = (DateTimeOffset.Parse(newTime, U.Inv) - DateTimeOffset.Parse(oldTime, U.Inv)).TotalSeconds.ToString("0.#######", U.Inv); }
                catch (Exception) { delta = "Unparsed"; }
            }
            string actorSid = e.Get("SubjectUserSid");
            if (actorSid.Length == 0) actorSid = e.Get("SecurityUserID");
            string[] cells = new string[] {
                id.ToString(U.Inv), e.Id.ToString(U.Inv), e.RecordId, Map(sevMap, r.Severity), r.Category, r.Title, r.Note, e.TimeUtc, e.Computer,
                fileDir, fileName, fileFull, e.Channel, e.Provider, e.Level.ToString(U.Inv), Map(auditMap, e.AuditOutcome),
                e.Subject, actorSid, e.Target, e.Get("TargetSid"),
                e.Get("MemberName"), e.Get("MemberSid"), e.SourceIP, e.Get("Port"),
                e.Get("Workstation"), e.LogonType, e.LogonId,
                e.Get("SubjectLogonId"), e.Get("SessionID"), e.SessionName,
                e.Get("Status"), e.Get("SubStatus"), e.Get("Process"),
                e.Get("CommandLine"), e.Get("Privileges"),
                e.Get("Threat"), e.Get("Path"),
                oldTime, newTime, delta, detailText, message, Map(msgMap, e.MessageStatus), r.RuleId, e.Fingerprint, e.XmlRecovery };
            Csv.Row(findingWriter, Delimiter, cells);
            if (IsTriageInput(e, r)) Csv.Row(triageWriter, Delimiter, cells);
            if (evidenceWriter != null)
            {
                evidenceWriter.WriteLine("{\"FindingId\":" + id.ToString(U.Inv) + ",\"SourceFile\":" + Json(fileFull) + ",\"RuleId\":" + Json(r.RuleId) +
                    ",\"Fingerprint\":" + Json(e.Fingerprint) + ",\"Xml\":" + Json(e.Xml) + ",\"Message\":" + Json(e.Message) + ",\"MessageStatus\":" + Json(e.MessageStatus) + "}");
            }
            string skey = r.Severity + "|" + r.Category + "|" + e.Computer;
            SummaryRow s;
            if (!summary.TryGetValue(skey, out s)) { s = new SummaryRow(); s.Severity = r.Severity; s.Category = r.Category; s.Computer = e.Computer; summary[skey] = s; }
            s.Count++;
            return id;
        }

        bool IsTriageInput(EvtEvent e, RuleDef r)
        {
            if (r.RuleId == "AV-VENDOR-THREAT" || r.RuleId == "HEURISTIC-COMMAND") return true;
            if (!triageKeys.ContainsKey(e.Provider + "|" + e.Id.ToString(U.Inv))) return false;
            if (e.Id == 4625 && U.EqI(e.Provider, Security))
                return e.LogonType == "10" && (BadPassword.IsMatch(e.Get("SubStatus")) || BadPassword.IsMatch(e.Get("Status")));
            return true;
        }

        static string Json(string s)
        {
            if (s == null) return "null";
            StringBuilder sb = new StringBuilder(s.Length + 16);
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ') sb.Append("\\u").Append(((int)c).ToString("x4", U.Inv)); else sb.Append(c);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }

        void AddFailure(EvtEvent e, long findingId)
        {
            if (!U.EqI(e.Provider, Security)) return;
            if (e.Id == 4776)
            {
                string st = e.FieldValue("Status");
                if (ZeroStatus.IsMatch(st) || st.Length == 0) return;
            }
            string scope = fileDir;
            string partition = scope.ToLowerInvariant() + "|" + e.Computer.ToLowerInvariant() + "|" + e.Id.ToString(U.Inv);
            if (e.Computer.Length == 0) partition += "|" + fileName;
            string source = e.SourceIP;
            if (Ffff.IsMatch(source)) source = source.Substring(7);
            if (source.Length == 0 || source == "-") source = e.Get("Workstation");
            if (source.Length == 0) source = "[unknown]";
            string account = e.Target.Length > 0 ? e.Target : "[unknown]";
            FailureRec f = new FailureRec();
            f.Ticks = e.Ticks; f.TimeUtc = e.TimeUtc; f.Computer = e.Computer; f.Scope = scope; f.EventId = e.Id; f.Account = account; f.Source = source;
            f.Fingerprint = e.Fingerprint; f.FindingId = findingId; f.File = fileFull; f.RecordId = e.RecordId;
            f.Status = e.F["Status"] as string; f.SubStatus = e.F["SubStatus"] as string;
            List<FailureRec> list;
            if (!failures.TryGetValue(partition, out list)) { list = new List<FailureRec>(); failures[partition] = list; }
            list.Add(f);
        }

        // Port of Correlate-Failures / Save-Burst (same windows, thresholds and output).
        public void CorrelateFailures(TextWriter burstWriter)
        {
            List<KeyValuePair<string, string>> order = new List<KeyValuePair<string, string>>();
            foreach (string p in failures.Keys) order.Add(new KeyValuePair<string, string>(U.Hash(p), p));
            order.Sort(delegate(KeyValuePair<string, string> a, KeyValuePair<string, string> b) { return string.CompareOrdinal(a.Key, b.Key); });
            long windowTicks = WindowMinutes * TimeSpan.TicksPerMinute;
            foreach (KeyValuePair<string, string> kv in order)
            {
                List<FailureRec> source = failures[kv.Value];
                Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.Ordinal);
                List<KeyValuePair<int, FailureRec>> rows = new List<KeyValuePair<int, FailureRec>>();
                foreach (FailureRec f in source)
                {
                    string fp = f.Fingerprint ?? "";
                    if (seen.ContainsKey(fp)) continue;
                    seen[fp] = true;
                    rows.Add(new KeyValuePair<int, FailureRec>(rows.Count, f));
                }
                rows.Sort(delegate(KeyValuePair<int, FailureRec> a, KeyValuePair<int, FailureRec> b)
                {
                    int c = a.Value.Ticks.CompareTo(b.Value.Ticks);
                    return c != 0 ? c : a.Key.CompareTo(b.Key);
                });
                Dictionary<string, FailureGroup> groups = new Dictionary<string, FailureGroup>(StringComparer.Ordinal);
                long iteration = 0;
                foreach (KeyValuePair<int, FailureRec> item in rows)
                {
                    FailureRec row = item.Value;
                    long now = row.Ticks;
                    for (int mode = 0; mode < 2; mode++)
                    {
                        bool sourceMode = mode == 1;
                        if (sourceMode && (row.Source == "[unknown]" || row.Account == "[unknown]")) continue;
                        string key = (sourceMode ? "Source|" : "Account|") + row.Source.ToLowerInvariant();
                        if (!sourceMode) key += "|" + row.Account.ToLowerInvariant();
                        FailureGroup g;
                        if (!groups.TryGetValue(key, out g)) { g = new FailureGroup(); groups[key] = g; }
                        Expire(g, sourceMode, now - windowTicks);
                        g.Queue.Enqueue(row);
                        if (sourceMode)
                        {
                            string userKey = row.Account.ToLowerInvariant();
                            int c; g.UserCounts.TryGetValue(userKey, out c); g.UserCounts[userKey] = c + 1;
                        }
                        bool crossed = g.Queue.Count >= FailureThreshold;
                        if (crossed && sourceMode) crossed = g.UserCounts.Count >= SprayUserThreshold;
                        if (crossed && (g.LastAlert == 0 || (now - g.LastAlert) >= windowTicks)) { SaveBurst(burstWriter, g.Queue, sourceMode); g.LastAlert = now; }
                    }
                    iteration++;
                    if (iteration % 512 == 0)
                    {
                        foreach (string key in new List<string>(groups.Keys))
                        {
                            FailureGroup g = groups[key];
                            Expire(g, key.StartsWith("Source|", StringComparison.Ordinal), now - windowTicks);
                            if (g.Queue.Count == 0) groups.Remove(key);
                        }
                    }
                }
            }
        }
        static void Expire(FailureGroup g, bool sourceMode, long limit)
        {
            while (g.Queue.Count > 0 && g.Queue.Peek().Ticks < limit)
            {
                FailureRec removed = g.Queue.Dequeue();
                if (sourceMode)
                {
                    string userKey = removed.Account.ToLowerInvariant();
                    int c = g.UserCounts[userKey] - 1;
                    if (c == 0) g.UserCounts.Remove(userKey); else g.UserCounts[userKey] = c;
                }
            }
        }
        void SaveBurst(TextWriter w, Queue<FailureRec> queue, bool sourceMode)
        {
            FailureRec[] items = queue.ToArray();
            FailureRec first = items[0], last = items[items.Length - 1];
            List<string> users = new List<string>(), ids = new List<string>(), refs = new List<string>(), codes = new List<string>();
            for (int i = 0; i < items.Length; i++)
            {
                if (!users.Contains(items[i].Account)) users.Add(items[i].Account);
                string code = U.N(items[i].Status) + "/" + U.N(items[i].SubStatus);
                if (!codes.Contains(code)) codes.Add(code);
                if (i < 20) { ids.Add(items[i].FindingId.ToString(U.Inv)); refs.Add(items[i].File + "#" + items[i].RecordId); }
            }
            string kind = sourceMode ? "Отказы для нескольких УЗ с одного источника: возможный password spraying" : "Повторные отказы для УЗ и источника";
            BurstCount++;
            Csv.Row(w, Delimiter, new string[] {
                Map(sevMap, sourceMode ? "High" : "Medium"), first.EventId.ToString(U.Inv), kind, first.Scope, first.Computer, first.Source,
                first.TimeUtc, last.TimeUtc, items.Length.ToString(U.Inv), users.Count.ToString(U.Inv), string.Join(" | ", users.ToArray()),
                string.Join(" | ", ids.ToArray()), string.Join(" | ", refs.ToArray()), string.Join(" | ", codes.ToArray()),
                "Скользящее окно; число событий, не доказанное число попыток пароля. Проверить причины отказа и сохраненные пароли. Ссылки: первые 20 событий окна." });
        }

        public SummaryRow[] GetSummary() { return new List<SummaryRow>(summary.Values).ToArray(); }
        public LogonRow[] GetLogons() { return new List<LogonRow>(logons.Values).ToArray(); }

        public void Dispose()
        {
            if (findingWriter != null) { findingWriter.Dispose(); findingWriter = null; }
            if (triageWriter != null) { triageWriter.Dispose(); triageWriter = null; }
            if (evidenceWriter != null) { evidenceWriter.Dispose(); evidenceWriter = null; }
        }
    }
}
namespace __NS__
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Text;
    using System.Text.RegularExpressions;

    // ---------------------------------------------------------------- YAML
    // Subset of YAML used by Sigma rules: block mappings and sequences, "- key: value"
    // items, plain / single / double quoted scalars, flow sequences [a, b], block
    // scalars (| and >), comments and multi-document files (---).
    public sealed class YMap
    {
        public readonly List<string> Keys = new List<string>();
        readonly Dictionary<string, object> values = new Dictionary<string, object>(StringComparer.Ordinal);
        public void Add(string key, object value)
        {
            if (values.ContainsKey(key)) throw new FormatException("повторяющийся ключ YAML «" + key + "»");
            Keys.Add(key); values[key] = value;
        }
        public object Get(string key) { object v; return values.TryGetValue(key, out v) ? v : null; }
        public bool Has(string key) { return values.ContainsKey(key); }
    }

    sealed class YLine { public int Indent; public string Content; public string Raw; public int Number; }

    public static class MiniYaml
    {
        public static List<object> ParseDocuments(string text)
        {
            List<object> docs = new List<object>();
            List<YLine> current = new List<YLine>();
            string[] raw = (text ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            for (int n = 0; n < raw.Length; n++)
            {
                string line = raw[n];
                if (n == 0 && line.Length > 0 && line[0] == '﻿') line = line.Substring(1);
                string trimmed = line.TrimEnd();
                if (trimmed == "---" || trimmed == "...")
                {
                    AddDoc(docs, current);
                    current = new List<YLine>();
                    continue;
                }
                int indent = 0;
                while (indent < line.Length && line[indent] == ' ') indent++;
                if (indent < line.Length && line[indent] == '\t' && line.Trim().Length > 0 && line.Trim()[0] != '#')
                    throw new FormatException("строка " + (n + 1) + ": табуляция в отступе YAML");
                YLine l = new YLine();
                l.Indent = indent; l.Raw = line; l.Number = n + 1;
                l.Content = indent < line.Length ? line.Substring(indent).TrimEnd() : "";
                current.Add(l);
            }
            AddDoc(docs, current);
            return docs;
        }
        static void AddDoc(List<object> docs, List<YLine> lines)
        {
            bool any = false;
            foreach (YLine l in lines) { if (l.Content.Length > 0 && l.Content[0] != '#') { any = true; break; } }
            if (!any) return;
            YParser p = new YParser(lines);
            docs.Add(p.ParseDocument());
        }
    }

    sealed class YParser
    {
        readonly List<YLine> lines;
        int pos;
        public YParser(List<YLine> l) { lines = l; }

        FormatException Err(YLine l, string message)
        {
            return new FormatException("строка " + (l != null ? l.Number.ToString(CultureInfo.InvariantCulture) : "?") + ": " + message);
        }
        void SkipBlank()
        {
            while (pos < lines.Count && (lines[pos].Content.Length == 0 || lines[pos].Content[0] == '#')) pos++;
        }
        static bool IsSeq(string c) { return c == "-" || c.StartsWith("- ", StringComparison.Ordinal); }

        public object ParseDocument()
        {
            SkipBlank();
            if (pos >= lines.Count) return null;
            object v = ParseNode(lines[pos].Indent);
            SkipBlank();
            if (pos < lines.Count) throw Err(lines[pos], "лишнее содержимое после документа");
            return v;
        }

        object ParseNode(int indent)
        {
            SkipBlank();
            if (pos >= lines.Count) return null;
            YLine ln = lines[pos];
            if (IsSeq(ln.Content)) return ParseSeq(ln.Indent);
            string key, rest;
            if (TryKey(ln.Content, out key, out rest)) return ParseMap(ln.Indent);
            pos++;
            return ParseInline(ln.Content, ln.Indent - 1, ln);
        }

        static bool TryKey(string content, out string key, out string rest)
        {
            key = null; rest = null;
            if (content.Length == 0) return false;
            char c0 = content[0];
            if (IsSeq(content) || c0 == '[' || c0 == '{' || c0 == '#' || c0 == '|' || c0 == '>' || c0 == '&' || c0 == '!') return false;
            if (c0 == '\'' || c0 == '"')
            {
                int end;
                string q = ReadQuoted(content, out end);
                if (q == null) return false;
                int j = end;
                while (j < content.Length && content[j] == ' ') j++;
                if (j < content.Length && content[j] == ':' && (j + 1 == content.Length || content[j + 1] == ' ')) { key = q; rest = content.Substring(j + 1); return true; }
                return false;
            }
            for (int i = 0; i < content.Length; i++)
            {
                char c = content[i];
                if (c == '#' && i > 0 && content[i - 1] == ' ') return false;
                if (c == ':' && (i + 1 == content.Length || content[i + 1] == ' '))
                {
                    key = content.Substring(0, i).TrimEnd();
                    rest = content.Substring(i + 1);
                    return key.Length > 0;
                }
            }
            return false;
        }

        YMap ParseMap(int indent)
        {
            YMap map = new YMap();
            while (true)
            {
                SkipBlank();
                if (pos >= lines.Count) break;
                YLine ln = lines[pos];
                if (ln.Indent < indent) break;
                if (ln.Indent > indent) throw Err(ln, "неожиданный отступ");
                if (IsSeq(ln.Content)) break;
                string key, rest;
                if (!TryKey(ln.Content, out key, out rest)) throw Err(ln, "ожидалась пара «ключ: значение»");
                pos++;
                string r = rest.Trim();
                object value;
                if (r.Length == 0 || r[0] == '#')
                {
                    SkipBlank();
                    if (pos < lines.Count && lines[pos].Indent > indent) value = ParseNode(lines[pos].Indent);
                    else if (pos < lines.Count && lines[pos].Indent == indent && IsSeq(lines[pos].Content)) value = ParseSeq(indent);
                    else value = null;
                }
                else if (r[0] == '|' || r[0] == '>') value = ReadBlock(indent, r);
                else value = ParseInline(r, indent, ln);
                try { map.Add(key, value); } catch (FormatException ex) { throw Err(ln, ex.Message); }
            }
            return map;
        }

        List<object> ParseSeq(int indent)
        {
            List<object> list = new List<object>();
            while (true)
            {
                SkipBlank();
                if (pos >= lines.Count) break;
                YLine ln = lines[pos];
                if (ln.Indent < indent) break;
                if (ln.Indent > indent) throw Err(ln, "неожиданный отступ в списке");
                if (!IsSeq(ln.Content)) break;
                string after = ln.Content.Length > 1 ? ln.Content.Substring(1) : "";
                int extra = 0;
                while (extra < after.Length && after[extra] == ' ') extra++;
                string item = after.Substring(extra);
                int itemIndent = indent + 1 + extra;
                if (item.Length == 0 || item[0] == '#')
                {
                    pos++;
                    SkipBlank();
                    if (pos < lines.Count && lines[pos].Indent > indent) list.Add(ParseNode(lines[pos].Indent));
                    else list.Add(null);
                    continue;
                }
                string k, r;
                if (IsSeq(item) || TryKey(item, out k, out r))
                {
                    YLine virt = new YLine();
                    virt.Indent = itemIndent; virt.Content = item; virt.Raw = ln.Raw; virt.Number = ln.Number;
                    lines[pos] = virt;
                    list.Add(ParseNode(itemIndent));
                }
                else
                {
                    pos++;
                    if (item[0] == '|' || item[0] == '>') list.Add(ReadBlock(indent, item));
                    else list.Add(ParseInline(item, indent, ln));
                }
            }
            return list;
        }

        object ParseInline(string text, int parentIndent, YLine ln)
        {
            char c0 = text[0];
            if (c0 == '\'' || c0 == '"')
            {
                int end;
                string q = ReadQuoted(text, out end);
                if (q == null) throw Err(ln, "незакрытая кавычка (многострочные строки в кавычках не поддерживаются)");
                string tail = text.Substring(end).Trim();
                if (tail.Length > 0 && tail[0] != '#') throw Err(ln, "лишний текст после строки в кавычках");
                return q;
            }
            if (c0 == '[') return ParseFlow(StripComment(text), ln);
            if (c0 == '{') throw Err(ln, "flow-словари {…} не поддерживаются");
            if (c0 == '&' || c0 == '*' && text.Length > 1 && char.IsLetter(text[1])) throw Err(ln, "якоря и ссылки YAML не поддерживаются");
            string v = StripComment(text);
            while (pos < lines.Count)
            {
                YLine next = lines[pos];
                if (next.Content.Length == 0 || next.Content[0] == '#' || next.Indent <= parentIndent) break;
                v = v + " " + StripComment(next.Content);
                pos++;
            }
            return Plain(v);
        }

        static object Plain(string v)
        {
            if (v == "~" || v == "null" || v == "Null" || v == "NULL" || v.Length == 0) return null;
            return v;
        }

        static string StripComment(string text)
        {
            int i = text.IndexOf(" #", StringComparison.Ordinal);
            return (i >= 0 ? text.Substring(0, i) : text).Trim();
        }

        List<object> ParseFlow(string text, YLine ln)
        {
            if (!text.EndsWith("]", StringComparison.Ordinal)) throw Err(ln, "многострочные списки […] не поддерживаются");
            string inner = text.Substring(1, text.Length - 2);
            List<object> items = new List<object>();
            int i = 0;
            while (i < inner.Length)
            {
                while (i < inner.Length && inner[i] == ' ') i++;
                if (i >= inner.Length) break;
                if (inner[i] == '[' || inner[i] == '{') throw Err(ln, "вложенные flow-структуры не поддерживаются");
                if (inner[i] == '\'' || inner[i] == '"')
                {
                    int end;
                    string q = ReadQuoted(inner.Substring(i), out end);
                    if (q == null) throw Err(ln, "незакрытая кавычка в списке");
                    items.Add(q);
                    i += end;
                    while (i < inner.Length && inner[i] == ' ') i++;
                    if (i < inner.Length && inner[i] != ',') throw Err(ln, "ожидалась запятая в списке");
                    i++;
                }
                else
                {
                    int comma = inner.IndexOf(',', i);
                    string part = (comma < 0 ? inner.Substring(i) : inner.Substring(i, comma - i)).Trim();
                    items.Add(Plain(part));
                    i = comma < 0 ? inner.Length : comma + 1;
                }
            }
            return items;
        }

        string ReadBlock(int parentIndent, string header)
        {
            bool folded = header[0] == '>';
            bool keepFinal = header.IndexOf('+') > 0;
            List<string> raw = new List<string>();
            int blockIndent = -1;
            while (pos < lines.Count)
            {
                YLine l = lines[pos];
                bool blank = l.Raw.Trim().Length == 0;
                if (!blank && l.Indent <= parentIndent) break;
                if (!blank && blockIndent < 0) blockIndent = l.Indent;
                raw.Add(l.Raw);
                pos++;
            }
            while (raw.Count > 0 && raw[raw.Count - 1].Trim().Length == 0) raw.RemoveAt(raw.Count - 1);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < raw.Count; i++)
            {
                string s = raw[i];
                s = s.Length >= blockIndent && blockIndent >= 0 ? s.Substring(blockIndent) : s.Trim();
                if (i > 0) sb.Append(folded ? (s.Length == 0 ? "\n" : " ") : "\n");
                sb.Append(s);
            }
            string result = sb.ToString();
            if (keepFinal) result += "\n";
            return result;
        }

        // Returns the unquoted value and the index after the closing quote; null if unclosed.
        internal static string ReadQuoted(string s, out int end)
        {
            end = 0;
            char q = s[0];
            StringBuilder sb = new StringBuilder();
            int i = 1;
            while (i < s.Length)
            {
                char c = s[i];
                if (q == '\'')
                {
                    if (c == '\'')
                    {
                        if (i + 1 < s.Length && s[i + 1] == '\'') { sb.Append('\''); i += 2; continue; }
                        end = i + 1; return sb.ToString();
                    }
                    sb.Append(c); i++; continue;
                }
                if (c == '"') { end = i + 1; return sb.ToString(); }
                if (c == '\\' && i + 1 < s.Length)
                {
                    char n = s[i + 1];
                    switch (n)
                    {
                        case 'n': sb.Append('\n'); i += 2; continue;
                        case 't': sb.Append('\t'); i += 2; continue;
                        case 'r': sb.Append('\r'); i += 2; continue;
                        case '0': sb.Append('\0'); i += 2; continue;
                        case '"': sb.Append('"'); i += 2; continue;
                        case '\\': sb.Append('\\'); i += 2; continue;
                        case '/': sb.Append('/'); i += 2; continue;
                        case 'x':
                            if (i + 3 < s.Length) { sb.Append((char)Convert.ToInt32(s.Substring(i + 2, 2), 16)); i += 4; continue; }
                            break;
                        case 'u':
                            if (i + 5 < s.Length) { sb.Append((char)Convert.ToInt32(s.Substring(i + 2, 4), 16)); i += 6; continue; }
                            break;
                    }
                    sb.Append(n); i += 2; continue;
                }
                sb.Append(c); i++;
            }
            return null;
        }
    }

    // ---------------------------------------------------------------- matchers
    abstract class SMatcher { public abstract bool Match(string v); }
    sealed class SEq : SMatcher
    {
        public readonly string Value; readonly StringComparison cmp;
        public SEq(string v, bool cased) { Value = v; cmp = cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase; }
        public override bool Match(string v) { return string.Equals(v, Value, cmp); }
    }
    sealed class SContains : SMatcher
    {
        readonly string value; readonly StringComparison cmp;
        public SContains(string v, bool cased) { value = v; cmp = cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase; }
        public override bool Match(string v) { return v.IndexOf(value, cmp) >= 0; }
    }
    sealed class SStarts : SMatcher
    {
        readonly string value; readonly StringComparison cmp;
        public SStarts(string v, bool cased) { value = v; cmp = cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase; }
        public override bool Match(string v) { return v.StartsWith(value, cmp); }
    }
    sealed class SEnds : SMatcher
    {
        readonly string value; readonly StringComparison cmp;
        public SEnds(string v, bool cased) { value = v; cmp = cased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase; }
        public override bool Match(string v) { return v.EndsWith(value, cmp); }
    }
    sealed class SRegex : SMatcher
    {
        readonly Regex rx;
        public SRegex(Regex r) { rx = r; }
        public override bool Match(string v) { return rx.IsMatch(v); }
    }
    sealed class SNum : SMatcher
    {
        readonly string op; readonly double value;
        public SNum(string o, double v) { op = o; value = v; }
        public override bool Match(string v)
        {
            double d;
            if (!double.TryParse(v.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return false;
            switch (op) { case "gt": return d > value; case "gte": return d >= value; case "lt": return d < value; default: return d <= value; }
        }
    }
    sealed class SCidr : SMatcher
    {
        readonly byte[] net; readonly int bits;
        public SCidr(string cidr)
        {
            int slash = cidr.IndexOf('/');
            IPAddress a;
            if (slash < 0 || !IPAddress.TryParse(cidr.Substring(0, slash).Trim(), out a)) throw new FormatException("некорректный CIDR «" + cidr + "»");
            net = a.GetAddressBytes();
            bits = int.Parse(cidr.Substring(slash + 1).Trim(), CultureInfo.InvariantCulture);
        }
        public override bool Match(string v)
        {
            IPAddress a;
            string s = U.NormalIp(v);
            if (!IPAddress.TryParse(s, out a)) return false;
            byte[] b = a.GetAddressBytes();
            if (b.Length != net.Length) return false;
            int full = bits / 8, rest = bits % 8;
            for (int i = 0; i < full; i++) if (b[i] != net[i]) return false;
            if (rest > 0) { int mask = 0xFF << (8 - rest) & 0xFF; if ((b[full] & mask) != (net[full] & mask)) return false; }
            return true;
        }
    }

    // ---------------------------------------------------------------- detection tree
    sealed class SCtx
    {
        public EvtEvent E;
        public Dictionary<string, string> FieldMap;
        public string Field(string name)
        {
            string n = name, mapped;
            if (FieldMap != null && FieldMap.TryGetValue(n, out mapped)) n = mapped;
            switch (n.ToLowerInvariant())
            {
                case "eventid": return E.Id.ToString(CultureInfo.InvariantCulture);
                case "provider_name": return E.Provider;
                case "channel": return E.Channel;
                case "computer": case "computername": return E.Computer;
                case "level": return E.Level.ToString(CultureInfo.InvariantCulture);
                case "eventrecordid": return E.RecordId;
                case "keywords": return E.KeywordsText;
                case "securityuserid": return E.SecurityUserId;
            }
            return E.GetData(n);
        }
    }
    abstract class SNode { public abstract bool Eval(SCtx c); }
    sealed class SAnd : SNode
    {
        public readonly List<SNode> Items = new List<SNode>();
        public override bool Eval(SCtx c) { foreach (SNode n in Items) if (!n.Eval(c)) return false; return true; }
    }
    sealed class SOr : SNode
    {
        public readonly List<SNode> Items = new List<SNode>();
        public override bool Eval(SCtx c) { foreach (SNode n in Items) if (n.Eval(c)) return true; return false; }
    }
    sealed class SNot : SNode
    {
        public SNode Item;
        public override bool Eval(SCtx c) { return !Item.Eval(c); }
    }
    sealed class SSel : SNode
    {
        public SSelection Sel;
        public override bool Eval(SCtx c) { return Sel.Match(c); }
    }
    sealed class SFieldCond
    {
        public string Field;
        public readonly List<SMatcher> Matchers = new List<SMatcher>();
        public bool All, HasNull;
        public int Exists = -1;
        public bool Match(SCtx c)
        {
            string v = c.Field(Field);
            if (Exists >= 0) return (v != null) == (Exists == 1);
            if (v == null) return HasNull;
            if (HasNull && v.Length == 0) return true;
            if (Matchers.Count == 0) return false;
            if (All) { foreach (SMatcher m in Matchers) if (!m.Match(v)) return false; return true; }
            foreach (SMatcher m in Matchers) if (m.Match(v)) return true;
            return false;
        }
    }
    sealed class SBranch
    {
        public readonly List<SFieldCond> Conds = new List<SFieldCond>();
        public List<SMatcher> Keywords;
        public bool Match(SCtx c)
        {
            if (Keywords != null)
            {
                string text = c.E.Xml + " " + c.E.Message;
                foreach (SMatcher m in Keywords) if (m.Match(text)) return true;
                return false;
            }
            foreach (SFieldCond f in Conds) if (!f.Match(c)) return false;
            return true;
        }
    }
    sealed class SSelection
    {
        public string Name;
        public readonly List<SBranch> Branches = new List<SBranch>();
        public bool Match(SCtx c) { foreach (SBranch b in Branches) if (b.Match(c)) return true; return false; }
    }

    sealed class SVariant
    {
        public SigmaRule Rule;
        public string Channel;            // null = any channel
        public string DefaultProvider;    // XPath hint
        public Dictionary<string, string> FieldMap;
        public SNode Condition;
        public Dictionary<int, bool> EventIds; // null = not restricted by EventID
    }

    public sealed class SigmaRule
    {
        public string Id = "", Name = "", Title = "", Description = "", Level = "medium", Status = "", Source = "", Author = "";
        public readonly List<string> Tags = new List<string>();
        public readonly List<string> FalsePositives = new List<string>();
        public string Fstec = "";
        internal readonly List<SVariant> Variants = new List<SVariant>();
        internal readonly List<KeyValuePair<SigmaCorrelation, int>> UsedBy = new List<KeyValuePair<SigmaCorrelation, int>>();
        public bool Standalone = true;
        internal int Index;
    }

    public sealed class EventRef
    {
        public string Computer = "", Folder = "", File = "", RecordId = "", TimeUtc = "", Fingerprint = "", Account = "", Ip = "";
        public int EventId; public long Ticks, FindingId, Seq;
    }

    sealed class SigmaHit
    {
        public long Ticks, Seq; public int Step; public string Key, Value; public EventRef Ref;
    }

    public sealed class SigmaCorrelation
    {
        public string Id = "", Name = "", Title = "", Description = "", Level = "medium", Type = "", Source = "", ValueField = "";
        public readonly List<string> Tags = new List<string>();
        public readonly List<string> FalsePositives = new List<string>();
        public string Fstec = "";
        internal readonly List<string> RuleRefs = new List<string>();
        internal readonly List<SigmaRule> Steps = new List<SigmaRule>();
        internal readonly List<string> GroupBy = new List<string>();
        internal readonly Dictionary<string, Dictionary<string, string>> Aliases = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        internal long Span;
        internal string Op = "gte";
        internal long Threshold;
        internal bool Generate;
        internal readonly List<SigmaHit> Hits = new List<SigmaHit>();
        internal readonly Dictionary<string, bool> SeenHits = new Dictionary<string, bool>(StringComparer.Ordinal);
        internal readonly Dictionary<string, string> GroupText = new Dictionary<string, string>(StringComparer.Ordinal);
        internal bool Truncated;
        internal bool Satisfied(long n) { return Op == "gt" ? n > Threshold : n >= Threshold; }
    }

    sealed class SigmaAlert
    {
        public string Title, Id, Level, Description, Source, Fstec, Folder, Computer, Group, Chain, Type;
        public List<string> Tags, FalsePositives;
        public long FirstTicks, LastTicks, Count;
        public readonly List<EventRef> Refs = new List<EventRef>();
        public readonly List<string> Accounts = new List<string>(), Ips = new List<string>();
        public readonly SortedDictionary<int, bool> Ids = new SortedDictionary<int, bool>();
        public int Score;
    }

    // ---------------------------------------------------------------- engine
    public sealed class SigmaEngine
    {
        public readonly List<SigmaRule> Rules = new List<SigmaRule>();
        public readonly List<SigmaCorrelation> Correlations = new List<SigmaCorrelation>();
        public readonly List<string> Problems = new List<string>();
        public int Skipped;
        public int MaxHitsPerCorrelation = 300000;
        public string PriorityHigh = "P1", PriorityMedium = "P2", PriorityLow = "P3";
        readonly Dictionary<int, List<SVariant>> byEventId = new Dictionary<int, List<SVariant>>();
        readonly List<SVariant> anyEventId = new List<SVariant>();
        readonly Dictionary<string, SigmaAlert> standalone = new Dictionary<string, SigmaAlert>(StringComparer.Ordinal);
        readonly Dictionary<string, bool> ids = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        bool prepared;

        static readonly Dictionary<string, string[]> Services = BuildServices();
        static Dictionary<string, string[]> BuildServices()
        {
            Dictionary<string, string[]> s = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            s["security"] = new string[] { "Security", "Microsoft-Windows-Security-Auditing" };
            s["system"] = new string[] { "System", null };
            s["application"] = new string[] { "Application", null };
            s["sysmon"] = new string[] { "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon" };
            s["powershell"] = new string[] { "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell" };
            s["powershell-classic"] = new string[] { "Windows PowerShell", "PowerShell" };
            s["windefend"] = new string[] { "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender" };
            s["taskscheduler"] = new string[] { "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler" };
            s["terminalservices-localsessionmanager"] = new string[] { "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager" };
            s["terminalservices-remoteconnectionmanager"] = new string[] { "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "Microsoft-Windows-TerminalServices-RemoteConnectionManager" };
            s["wmi"] = new string[] { "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity" };
            s["driver-framework"] = new string[] { "Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-DriverFrameworks-UserMode" };
            s["codeintegrity-operational"] = new string[] { "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity" };
            s["firewall-as"] = new string[] { "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-Windows Firewall With Advanced Security" };
            s["bits-client"] = new string[] { "Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-Bits-Client" };
            s["ntlm"] = new string[] { "Microsoft-Windows-NTLM/Operational", "Microsoft-Windows-NTLM" };
            s["smbclient-security"] = new string[] { "Microsoft-Windows-SmbClient/Security", "Microsoft-Windows-SMBClient" };
            s["dns-server"] = new string[] { "DNS Server", null };
            s["kernel-pnp-configuration"] = new string[] { "Microsoft-Windows-Kernel-PnP/Configuration", "Microsoft-Windows-Kernel-PnP" };
            s["partition-diagnostic"] = new string[] { "Microsoft-Windows-Partition/Diagnostic", "Microsoft-Windows-Partition" };
            return s;
        }
        static readonly Dictionary<string, int[]> SysmonCategories = BuildCategories();
        static Dictionary<string, int[]> BuildCategories()
        {
            Dictionary<string, int[]> c = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase);
            c["network_connection"] = new int[] { 3 }; c["process_termination"] = new int[] { 5 }; c["driver_load"] = new int[] { 6 };
            c["image_load"] = new int[] { 7 }; c["create_remote_thread"] = new int[] { 8 }; c["raw_access_thread"] = new int[] { 9 };
            c["process_access"] = new int[] { 10 }; c["file_event"] = new int[] { 11 }; c["registry_add"] = new int[] { 12 };
            c["registry_delete"] = new int[] { 12 }; c["registry_set"] = new int[] { 13 }; c["registry_rename"] = new int[] { 14 };
            c["registry_event"] = new int[] { 12, 13, 14 }; c["create_stream_hash"] = new int[] { 15 }; c["pipe_created"] = new int[] { 17, 18 };
            c["wmi_event"] = new int[] { 19, 20, 21 }; c["dns_query"] = new int[] { 22 }; c["file_delete"] = new int[] { 23, 26 };
            c["clipboard_capture"] = new int[] { 24 }; c["process_tampering"] = new int[] { 25 }; c["file_block_executable"] = new int[] { 27 };
            c["file_block_shredding"] = new int[] { 28 }; c["file_executable_detected"] = new int[] { 29 }; c["sysmon_status"] = new int[] { 4, 16 };
            c["sysmon_error"] = new int[] { 255 };
            return c;
        }
        static readonly Regex TacticTag = new Regex(@"^attack\.([a-z\-]+)$", RegexOptions.CultureInvariant);
        static readonly Regex TechniqueTag = new Regex(@"^attack\.(t\d{4}(?:\.\d{3})?)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Dictionary<string, string> Tactics = BuildTactics();
        static Dictionary<string, string> BuildTactics()
        {
            Dictionary<string, string> t = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            t["reconnaissance"] = "Разведка"; t["resource-development"] = "Подготовка ресурсов"; t["initial-access"] = "Первоначальный доступ";
            t["execution"] = "Выполнение"; t["persistence"] = "Закрепление"; t["privilege-escalation"] = "Повышение привилегий";
            t["defense-evasion"] = "Обход защиты"; t["credential-access"] = "Доступ к учетным данным"; t["discovery"] = "Исследование";
            t["lateral-movement"] = "Боковое перемещение"; t["collection"] = "Сбор данных"; t["command-and-control"] = "Управление (C2)";
            t["exfiltration"] = "Эксфильтрация"; t["impact"] = "Воздействие";
            return t;
        }
        static readonly Dictionary<string, string> TacticFstec = BuildTacticFstec();
        static Dictionary<string, string> BuildTacticFstec()
        {
            Dictionary<string, string> t = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            t["initial-access"] = "УПД"; t["lateral-movement"] = "УПД"; t["credential-access"] = "ИАФ, УПД"; t["persistence"] = "УПД";
            t["privilege-escalation"] = "УПД"; t["defense-evasion"] = "АУД"; t["execution"] = "ОПС"; t["impact"] = "ОДТ";
            t["collection"] = "ЗНИ"; t["exfiltration"] = "ЗНИ"; t["command-and-control"] = "ЗИС"; t["discovery"] = "АУД";
            return t;
        }

        // -------------------------------------------------------- loading
        public int LoadText(string text, string source)
        {
            if (prepared) throw new InvalidOperationException("Sigma: правила добавляются до Prepare()");
            List<object> docs;
            try { docs = MiniYaml.ParseDocuments(text); }
            catch (Exception ex) { Problem(source, "", "ошибка YAML: " + ex.Message); return 0; }
            int loaded = 0;
            foreach (object d in docs)
            {
                YMap doc = d as YMap;
                if (doc == null) continue;
                string id = Str(doc.Get("id"));
                try
                {
                    if (doc.Has("action")) throw new NotSupportedException("коллекции правил (action: global) не поддерживаются");
                    if (doc.Has("correlation")) { LoadCorrelation(doc, source); loaded++; }
                    else if (doc.Has("detection")) { if (LoadRule(doc, source)) loaded++; }
                    else throw new NotSupportedException("нет разделов detection или correlation");
                }
                catch (Exception ex) { Problem(source, id + " " + Str(doc.Get("title")), ex.Message); }
            }
            return loaded;
        }
        void Problem(string source, string rule, string message) { Problem(source, rule, message, true); }
        void Problem(string source, string rule, string message, bool skipped)
        {
            if (skipped) Skipped++;
            if (Problems.Count < 500) Problems.Add(source + (rule.Trim().Length > 0 ? " [" + rule.Trim() + "]" : "") + ": " + message);
        }
        static string Str(object o) { return o == null ? "" : (o as string ?? ""); }
        static List<string> StrList(object o)
        {
            List<string> l = new List<string>();
            if (o == null) return l;
            string s = o as string;
            if (s != null) { l.Add(s); return l; }
            List<object> list = o as List<object>;
            if (list == null) throw new FormatException("ожидалась строка или список строк");
            foreach (object x in list) { if (x != null) { string xs = x as string; if (xs == null) throw new FormatException("ожидался список строк"); l.Add(xs); } }
            return l;
        }
        void ReadCommon(YMap doc, out string id, out string title, out string level)
        {
            id = Str(doc.Get("id")).Trim();
            title = Str(doc.Get("title")).Trim();
            level = Str(doc.Get("level")).Trim().ToLowerInvariant();
            if (title.Length == 0) throw new FormatException("нет title");
            if (id.Length == 0) id = title;
            if (ids.ContainsKey(id)) throw new FormatException("повторяющийся id " + id + " (правило уже загружено)");
            if (level.Length == 0) level = "medium";
        }

        bool LoadRule(YMap doc, string source)
        {
            string id, title, level;
            ReadCommon(doc, out id, out title, out level);
            string status = Str(doc.Get("status")).ToLowerInvariant();
            if (status == "deprecated" || status == "unsupported") throw new NotSupportedException("статус " + status);
            SigmaRule rule = new SigmaRule();
            rule.Id = id; rule.Title = title; rule.Level = level; rule.Status = status; rule.Source = source;
            rule.Name = Str(doc.Get("name")).Trim();
            rule.Description = Str(doc.Get("description")).Trim();
            rule.Author = Str(doc.Get("author"));
            rule.Tags.AddRange(StrList(doc.Get("tags")));
            rule.FalsePositives.AddRange(StrList(doc.Get("falsepositives")));
            rule.Fstec = U.Join(", ", StrList(doc.Get("fstec239")));
            YMap logsource = doc.Get("logsource") as YMap;
            if (logsource == null) throw new FormatException("нет logsource");
            string product = Str(logsource.Get("product")).ToLowerInvariant();
            string service = Str(logsource.Get("service")).ToLowerInvariant();
            string category = Str(logsource.Get("category")).ToLowerInvariant();
            if (product.Length > 0 && product != "windows") throw new NotSupportedException("logsource product " + product + " не относится к журналам Windows");
            YMap detection = doc.Get("detection") as YMap;
            if (detection == null) throw new FormatException("detection должен быть словарем");
            if (detection.Has("timeframe")) throw new NotSupportedException("timeframe (агрегации Sigma v1) не поддерживается; используйте correlation");
            Dictionary<string, SSelection> selections = new Dictionary<string, SSelection>(StringComparer.Ordinal);
            foreach (string key in detection.Keys)
            {
                if (key == "condition") continue;
                selections[key] = CompileSelection(key, detection.Get(key));
            }
            List<string> conditions = StrList(detection.Get("condition"));
            if (conditions.Count == 0) throw new FormatException("нет condition");
            SNode condition;
            if (conditions.Count == 1) condition = new ConditionParser(conditions[0], selections).Parse();
            else
            {
                SOr or = new SOr();
                foreach (string c in conditions) or.Items.Add(new ConditionParser(c, selections).Parse());
                condition = or;
            }
            foreach (SVariant v in BuildVariants(product, service, category))
            {
                v.Rule = rule;
                v.Condition = condition;
                Dictionary<int, bool> req = RequiredIds(condition);
                if (v.EventIds != null) req = req == null ? v.EventIds : Intersect(req, v.EventIds);
                v.EventIds = req;
                rule.Variants.Add(v);
            }
            rule.Index = Rules.Count;
            Rules.Add(rule);
            ids[id] = true;
            return true;
        }

        static List<SVariant> BuildVariants(string product, string service, string category)
        {
            List<SVariant> list = new List<SVariant>();
            if (category.Length > 0)
            {
                if (category == "process_creation")
                {
                    SVariant sys = new SVariant(); sys.Channel = Services["sysmon"][0]; sys.DefaultProvider = Services["sysmon"][1]; sys.EventIds = Ids(1); list.Add(sys);
                    SVariant sec = new SVariant(); sec.Channel = "Security"; sec.DefaultProvider = "Microsoft-Windows-Security-Auditing"; sec.EventIds = Ids(4688);
                    sec.FieldMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    sec.FieldMap["Image"] = "NewProcessName"; sec.FieldMap["ParentImage"] = "ParentProcessName"; sec.FieldMap["ProcessId"] = "NewProcessId";
                    sec.FieldMap["ParentProcessId"] = "ProcessId"; sec.FieldMap["User"] = "SubjectUserName"; sec.FieldMap["LogonId"] = "SubjectLogonId";
                    sec.FieldMap["IntegrityLevel"] = "MandatoryLabel";
                    list.Add(sec);
                    return list;
                }
                if (category == "ps_script" || category == "ps_module")
                {
                    SVariant ps = new SVariant(); ps.Channel = Services["powershell"][0]; ps.DefaultProvider = Services["powershell"][1];
                    ps.EventIds = Ids(category == "ps_script" ? 4104 : 4103); list.Add(ps); return list;
                }
                int[] sysmonIds;
                if (SysmonCategories.TryGetValue(category, out sysmonIds))
                {
                    SVariant v = new SVariant(); v.Channel = Services["sysmon"][0]; v.DefaultProvider = Services["sysmon"][1]; v.EventIds = Ids(sysmonIds); list.Add(v); return list;
                }
                throw new NotSupportedException("logsource category " + category + " не поддерживается");
            }
            if (service.Length == 0) throw new NotSupportedException("logsource без service/category");
            string[] svc;
            if (!Services.TryGetValue(service, out svc)) throw new NotSupportedException("logsource service " + service + " не поддерживается");
            SVariant s = new SVariant(); s.Channel = svc[0]; s.DefaultProvider = svc[1]; list.Add(s);
            return list;
        }
        static Dictionary<int, bool> Ids(params int[] values)
        {
            Dictionary<int, bool> d = new Dictionary<int, bool>();
            foreach (int v in values) d[v] = true;
            return d;
        }
        static Dictionary<int, bool> Intersect(Dictionary<int, bool> a, Dictionary<int, bool> b)
        {
            Dictionary<int, bool> d = new Dictionary<int, bool>();
            foreach (int k in a.Keys) if (b.ContainsKey(k)) d[k] = true;
            return d;
        }

        static SSelection CompileSelection(string name, object value)
        {
            SSelection sel = new SSelection();
            sel.Name = name;
            YMap map = value as YMap;
            if (map != null) { sel.Branches.Add(CompileBranch(map)); return sel; }
            List<object> list = value as List<object>;
            if (list != null)
            {
                bool maps = true, scalars = true;
                foreach (object o in list) { if (!(o is YMap)) maps = false; if (!(o is string)) scalars = false; }
                if (maps && list.Count > 0) { foreach (object o in list) sel.Branches.Add(CompileBranch((YMap)o)); return sel; }
                if (scalars && list.Count > 0)
                {
                    SBranch b = new SBranch(); b.Keywords = new List<SMatcher>();
                    foreach (object o in list) b.Keywords.Add(BuildMatcher((string)o, "contains", false, false));
                    sel.Branches.Add(b); return sel;
                }
                throw new FormatException("выборка «" + name + "»: список должен содержать только словари или только строки");
            }
            string s = value as string;
            if (s != null)
            {
                SBranch b = new SBranch(); b.Keywords = new List<SMatcher>();
                b.Keywords.Add(BuildMatcher(s, "contains", false, false));
                sel.Branches.Add(b); return sel;
            }
            throw new FormatException("выборка «" + name + "» пуста");
        }

        static SBranch CompileBranch(YMap map)
        {
            SBranch b = new SBranch();
            foreach (string key in map.Keys)
            {
                string[] parts = key.Split('|');
                SFieldCond cond = new SFieldCond();
                cond.Field = parts[0].Trim();
                string type = "eq";
                bool cased = false, windash = false;
                RegexOptions rxo = RegexOptions.CultureInvariant;
                for (int i = 1; i < parts.Length; i++)
                {
                    string m = parts[i].Trim().ToLowerInvariant();
                    switch (m)
                    {
                        case "contains": case "startswith": case "endswith": case "re": case "cidr": case "exists":
                        case "gt": case "gte": case "lt": case "lte":
                            type = m; break;
                        case "all": cond.All = true; break;
                        case "cased": cased = true; break;
                        case "windash": windash = true; break;
                        case "i": rxo |= RegexOptions.IgnoreCase; break;
                        case "m": rxo |= RegexOptions.Multiline; break;
                        case "s": rxo |= RegexOptions.Singleline; break;
                        default: throw new NotSupportedException("модификатор |" + m + " не поддерживается");
                    }
                }
                List<object> values = new List<object>();
                object raw = map.Get(key);
                List<object> rawList = raw as List<object>;
                if (rawList != null) values.AddRange(rawList); else values.Add(raw);
                foreach (object v in values)
                {
                    if (v is YMap || v is List<object>) throw new FormatException("поле " + key + ": вложенные структуры не поддерживаются");
                    string sv = v as string;
                    if (type == "exists")
                    {
                        cond.Exists = (sv != null && sv.Trim().ToLowerInvariant() == "true") ? 1 : 0;
                        continue;
                    }
                    if (sv == null) { cond.HasNull = true; continue; }
                    if (type == "re") { cond.Matchers.Add(new SRegex(new Regex(sv, rxo))); continue; }
                    if (type == "cidr") { cond.Matchers.Add(new SCidr(sv)); continue; }
                    if (type == "gt" || type == "gte" || type == "lt" || type == "lte")
                    {
                        double d;
                        if (!double.TryParse(sv, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) throw new FormatException("поле " + key + ": ожидалось число");
                        cond.Matchers.Add(new SNum(type, d)); continue;
                    }
                    cond.Matchers.Add(BuildMatcher(sv, type, cased, windash));
                }
                b.Conds.Add(cond);
            }
            return b;
        }

        // Sigma wildcard semantics: * any sequence, ? one character, \* \? \\ escapes.
        static SMatcher BuildMatcher(string value, string type, bool cased, bool windash)
        {
            StringBuilder literal = new StringBuilder();
            StringBuilder pattern = new StringBuilder();
            bool wild = false;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '\\' && i + 1 < value.Length && (value[i + 1] == '*' || value[i + 1] == '?' || value[i + 1] == '\\'))
                {
                    literal.Append(value[i + 1]); pattern.Append(Regex.Escape(value[i + 1].ToString())); i++; continue;
                }
                if (c == '*') { wild = true; pattern.Append(".*"); continue; }
                if (c == '?') { wild = true; pattern.Append('.'); continue; }
                literal.Append(c);
                pattern.Append(Regex.Escape(c.ToString()));
            }
            if (!wild && !windash)
            {
                string l = literal.ToString();
                switch (type)
                {
                    case "contains": return new SContains(l, cased);
                    case "startswith": return new SStarts(l, cased);
                    case "endswith": return new SEnds(l, cased);
                    default: return new SEq(l, cased);
                }
            }
            string p = pattern.ToString();
            if (windash) p = Regex.Replace(p, @"(^|\s)(\\-|/)", "$1[-/–—―]");
            string prefix = (type == "contains" || type == "endswith") ? ".*" : "";
            string suffix = (type == "contains" || type == "startswith") ? ".*" : "";
            RegexOptions o = RegexOptions.Singleline | RegexOptions.CultureInvariant;
            if (!cased) o |= RegexOptions.IgnoreCase;
            return new SRegex(new Regex("^" + prefix + p + suffix + "$", o));
        }

        // EventIDs that every match of the node must have (null = unrestricted).
        static Dictionary<int, bool> RequiredIds(SNode n)
        {
            SSel sel = n as SSel;
            if (sel != null)
            {
                Dictionary<int, bool> union = new Dictionary<int, bool>();
                foreach (SBranch b in sel.Sel.Branches)
                {
                    Dictionary<int, bool> branch = null;
                    foreach (SFieldCond c in b.Conds)
                    {
                        if (!U.EqI(c.Field, "EventID") || c.Exists >= 0 || c.HasNull || c.Matchers.Count == 0) continue;
                        Dictionary<int, bool> vals = new Dictionary<int, bool>();
                        bool ok = true;
                        foreach (SMatcher m in c.Matchers)
                        {
                            SEq eq = m as SEq; int id;
                            if (eq == null || !int.TryParse(eq.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out id)) { ok = false; break; }
                            vals[id] = true;
                        }
                        if (ok && !(c.All && c.Matchers.Count > 1)) { branch = branch == null ? vals : Intersect(branch, vals); }
                    }
                    if (branch == null) return null;
                    foreach (int k in branch.Keys) union[k] = true;
                }
                return union;
            }
            SAnd and = n as SAnd;
            if (and != null)
            {
                Dictionary<int, bool> result = null;
                foreach (SNode c in and.Items)
                {
                    Dictionary<int, bool> r = RequiredIds(c);
                    if (r != null) result = result == null ? r : Intersect(result, r);
                }
                return result;
            }
            SOr or = n as SOr;
            if (or != null)
            {
                Dictionary<int, bool> union = new Dictionary<int, bool>();
                foreach (SNode c in or.Items)
                {
                    Dictionary<int, bool> r = RequiredIds(c);
                    if (r == null) return null;
                    foreach (int k in r.Keys) union[k] = true;
                }
                return union;
            }
            return null;
        }

        void LoadCorrelation(YMap doc, string source)
        {
            string id, title, level;
            ReadCommon(doc, out id, out title, out level);
            YMap c = doc.Get("correlation") as YMap;
            if (c == null) throw new FormatException("correlation должен быть словарем");
            SigmaCorrelation cor = new SigmaCorrelation();
            cor.Id = id; cor.Title = title; cor.Level = level; cor.Source = source;
            cor.Name = Str(doc.Get("name")).Trim();
            cor.Description = Str(doc.Get("description")).Trim();
            cor.Tags.AddRange(StrList(doc.Get("tags")));
            cor.FalsePositives.AddRange(StrList(doc.Get("falsepositives")));
            cor.Fstec = U.Join(", ", StrList(doc.Get("fstec239")));
            cor.Type = Str(c.Get("type")).Trim().ToLowerInvariant();
            if (cor.Type != "event_count" && cor.Type != "value_count" && cor.Type != "temporal" && cor.Type != "temporal_ordered")
                throw new NotSupportedException("тип корреляции " + cor.Type + " не поддерживается");
            cor.RuleRefs.AddRange(StrList(c.Get("rules")));
            if (cor.RuleRefs.Count == 0) throw new FormatException("correlation.rules пуст");
            if ((cor.Type == "temporal" || cor.Type == "temporal_ordered") && cor.RuleRefs.Count < 2) throw new FormatException("для " + cor.Type + " нужно не менее двух правил");
            cor.GroupBy.AddRange(StrList(c.Get("group-by")));
            cor.Span = ParseSpan(Str(c.Get("timespan")));
            cor.Generate = Str(c.Get("generate")).Trim().ToLowerInvariant() == "true";
            YMap aliases = c.Get("aliases") as YMap;
            if (aliases != null)
            {
                foreach (string alias in aliases.Keys)
                {
                    YMap m = aliases.Get(alias) as YMap;
                    if (m == null) throw new FormatException("aliases." + alias + " должен быть словарем");
                    Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string r in m.Keys) d[r] = Str(m.Get(r));
                    cor.Aliases[alias] = d;
                }
            }
            if (cor.Type == "event_count" || cor.Type == "value_count")
            {
                YMap cond = c.Get("condition") as YMap;
                if (cond == null) throw new FormatException("для " + cor.Type + " нужен condition");
                bool found = false;
                foreach (string k in cond.Keys)
                {
                    string kk = k.ToLowerInvariant();
                    if (kk == "field") { cor.ValueField = Str(cond.Get(k)); continue; }
                    if (kk == "gt" || kk == "gte")
                    {
                        long t;
                        if (!long.TryParse(Str(cond.Get(k)).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out t)) throw new FormatException("condition." + k + ": ожидалось целое число");
                        cor.Op = kk; cor.Threshold = t; found = true; continue;
                    }
                    throw new NotSupportedException("условие корреляции " + k + " не поддерживается (только gt/gte)");
                }
                if (!found) throw new FormatException("condition: нужен gt или gte");
                if (cor.Type == "value_count" && cor.ValueField.Length == 0) throw new FormatException("value_count: нужен condition.field");
            }
            Correlations.Add(cor);
            ids[id] = true;
        }

        static long ParseSpan(string s)
        {
            Match m = Regex.Match(s.Trim(), @"^(\d+)\s*([smhdw])$", RegexOptions.CultureInvariant);
            if (!m.Success) throw new FormatException("timespan «" + s + "»: ожидается число и s/m/h/d/w");
            long n = long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            switch (m.Groups[2].Value)
            {
                case "s": return n * TimeSpan.TicksPerSecond;
                case "m": return n * TimeSpan.TicksPerMinute;
                case "h": return n * TimeSpan.TicksPerHour;
                case "d": return n * TimeSpan.TicksPerDay;
                default: return n * TimeSpan.TicksPerDay * 7;
            }
        }

        // Resolves correlation references, decides which rules alert on their own and builds indexes.
        public void Prepare()
        {
            if (prepared) return;
            prepared = true;
            Dictionary<string, SigmaRule> byRef = new Dictionary<string, SigmaRule>(StringComparer.OrdinalIgnoreCase);
            foreach (SigmaRule r in Rules) { byRef[r.Id] = r; if (r.Name.Length > 0) byRef[r.Name] = r; }
            List<SigmaCorrelation> valid = new List<SigmaCorrelation>();
            foreach (SigmaCorrelation c in Correlations)
            {
                string error = null;
                foreach (string rf in c.RuleRefs)
                {
                    SigmaRule r;
                    if (!byRef.TryGetValue(rf, out r)) { error = "правило «" + rf + "» не найдено (вложенные корреляции не поддерживаются)"; break; }
                    c.Steps.Add(r);
                }
                if (error == null)
                {
                    foreach (string g in c.GroupBy)
                    {
                        Dictionary<string, string> alias;
                        if (!c.Aliases.TryGetValue(g, out alias)) continue;
                        foreach (SigmaRule r in c.Steps)
                            if (!alias.ContainsKey(r.Name) && !alias.ContainsKey(r.Id)) { error = "alias " + g + " не задан для правила " + (r.Name.Length > 0 ? r.Name : r.Id); break; }
                    }
                }
                if (error != null) { Problem(c.Source, c.Id + " " + c.Title, error); continue; }
                for (int i = 0; i < c.Steps.Count; i++) c.Steps[i].UsedBy.Add(new KeyValuePair<SigmaCorrelation, int>(c, i));
                valid.Add(c);
            }
            Correlations.Clear();
            Correlations.AddRange(valid);
            foreach (SigmaRule r in Rules)
            {
                if (r.UsedBy.Count == 0) { r.Standalone = true; continue; }
                r.Standalone = false;
                foreach (KeyValuePair<SigmaCorrelation, int> u in r.UsedBy) if (u.Key.Generate) r.Standalone = true;
            }
            foreach (SigmaRule r in Rules)
            {
                if (!r.Standalone && r.UsedBy.Count == 0) continue;
                foreach (SVariant v in r.Variants)
                {
                    if (v.EventIds == null) { anyEventId.Add(v); continue; }
                    foreach (int id in v.EventIds.Keys)
                    {
                        List<SVariant> l;
                        if (!byEventId.TryGetValue(id, out l)) { l = new List<SVariant>(); byEventId[id] = l; }
                        l.Add(v);
                    }
                }
            }
        }

        public int RuleCount { get { return Rules.Count; } }
        public int CorrelationCount { get { return Correlations.Count; } }

        // -------------------------------------------------------- XPath hints
        // Selector templates for Build-Query; {TIME} is replaced by the time window.
        public string[] GetSelectors(int maxEventId)
        {
            List<string> result = new List<string>();
            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (SigmaRule r in Rules)
            {
                if (!r.Standalone && r.UsedBy.Count == 0) continue;
                foreach (SVariant v in r.Variants)
                {
                    if (v.EventIds == null || v.EventIds.Count == 0) continue;
                    foreach (string s in Selectors(v, maxEventId)) if (!seen.ContainsKey(s)) { seen[s] = true; result.Add(s); }
                }
            }
            return result.ToArray();
        }
        static readonly Regex Pushable = new Regex(@"^(\d+|0x[0-9a-f]+|S-1-[0-9-]+)$", RegexOptions.CultureInvariant);
        static readonly string[] PushProviders = new string[] { "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Partition", "Microsoft-Windows-Sysmon", "Service Control Manager" };
        static readonly string[] AlwaysPresent = new string[] { "SubjectUserSid", "TargetUserSid", "LogonType", "SubjectLogonId" };

        static List<string> Selectors(SVariant v, int maxEventId)
        {
            List<string> list = new List<string>();
            List<int> idList = new List<int>();
            foreach (int id in v.EventIds.Keys) if (id <= maxEventId) idList.Add(id);
            idList.Sort();
            if (idList.Count == 0) return list;
            // Providers named in the rule, otherwise the logsource default.
            List<string> providers = ProviderHints(v.Condition);
            if (providers.Count == 0 && v.DefaultProvider != null) providers.Add(v.DefaultProvider);
            string eventData = "";
            bool canPush = providers.Count > 0;
            foreach (string p in providers) { bool ok = false; foreach (string pp in PushProviders) if (U.EqI(p, pp)) ok = true; if (!ok) canPush = false; }
            if (canPush) eventData = PushDown(v);
            if (providers.Count == 0) providers.Add(null);
            foreach (string provider in providers)
            {
                for (int i = 0; i < idList.Count; i += 8)
                {
                    List<string> parts = new List<string>();
                    for (int j = i; j < Math.Min(i + 8, idList.Count); j++) parts.Add("EventID=" + idList[j].ToString(CultureInfo.InvariantCulture));
                    string sys = (provider != null ? "Provider[@Name='" + provider + "'] and " : "") + "(" + string.Join(" or ", parts.ToArray()) + ")";
                    list.Add("*[System[" + sys + "{TIME}]" + (eventData.Length > 0 ? " and EventData[" + eventData + "]" : "") + "]");
                }
            }
            return list;
        }
        static List<string> ProviderHints(SNode n)
        {
            List<string> result = new List<string>();
            SSel sel = Positive(n);
            if (sel == null) return result;
            foreach (SBranch b in sel.Sel.Branches)
            {
                List<string> branch = new List<string>();
                foreach (SFieldCond c in b.Conds)
                {
                    if (!U.EqI(c.Field, "Provider_Name") || c.Exists >= 0 || c.HasNull) continue;
                    foreach (SMatcher m in c.Matchers) { SEq eq = m as SEq; if (eq == null) return new List<string>(); branch.Add(eq.Value); }
                }
                if (branch.Count == 0) return new List<string>();
                foreach (string p in branch) if (!result.Contains(p)) result.Add(p);
            }
            return result;
        }
        // The positive selection that restricts EventID (first one in a top-level AND).
        static SSel Positive(SNode n)
        {
            SSel s = n as SSel;
            if (s != null) return RequiredIds(s) != null ? s : null;
            SAnd a = n as SAnd;
            if (a == null) return null;
            foreach (SNode c in a.Items) { SSel cs = c as SSel; if (cs != null && RequiredIds(cs) != null) return cs; }
            return null;
        }
        // Exact digit/hex/SID values only: string comparison in event XPath is not
        // case-insensitive, and a missed event is worse than reading a few extra ones.
        static string PushDown(SVariant v)
        {
            SSel sel = Positive(v.Condition);
            if (sel == null || sel.Sel.Branches.Count != 1) return "";
            List<string> terms = new List<string>();
            foreach (SFieldCond c in sel.Sel.Branches[0].Conds)
            {
                string term = PushTerm(c, v.FieldMap, false);
                if (term != null) terms.Add(term);
            }
            SAnd and = v.Condition as SAnd;
            if (and != null)
            {
                foreach (SNode n in and.Items)
                {
                    SNot not = n as SNot;
                    if (not == null) continue;
                    SSel neg = not.Item as SSel;
                    if (neg == null || neg.Sel.Branches.Count != 1 || neg.Sel.Branches[0].Conds.Count != 1) continue;
                    SFieldCond c = neg.Sel.Branches[0].Conds[0];
                    bool always = false;
                    foreach (string f in AlwaysPresent) if (U.EqI(f, c.Field)) always = true;
                    if (!always) continue;
                    string term = PushTerm(c, v.FieldMap, true);
                    if (term != null) terms.Add(term);
                }
            }
            if (terms.Count > 6) terms.RemoveRange(6, terms.Count - 6);
            return string.Join(" and ", terms.ToArray());
        }
        static string PushTerm(SFieldCond c, Dictionary<string, string> map, bool negative)
        {
            if (U.EqI(c.Field, "EventID") || U.EqI(c.Field, "Provider_Name") || U.EqI(c.Field, "Channel") || U.EqI(c.Field, "Computer") || U.EqI(c.Field, "Level")) return null;
            if (c.Exists >= 0 || c.HasNull || c.Matchers.Count == 0 || c.Matchers.Count > 4 || (c.All && c.Matchers.Count > 1)) return null;
            if (c.Field.IndexOf('\'') >= 0 || c.Field.IndexOf(' ') >= 0) return null;
            string field = c.Field, mapped;
            if (map != null && map.TryGetValue(field, out mapped)) field = mapped;
            List<string> parts = new List<string>();
            foreach (SMatcher m in c.Matchers)
            {
                SEq eq = m as SEq;
                if (eq == null || !Pushable.IsMatch(eq.Value)) return null;
                parts.Add("Data[@Name='" + field + "']" + (negative ? "!=" : "=") + "'" + eq.Value + "'");
            }
            return negative ? string.Join(" and ", parts.ToArray()) : "(" + string.Join(" or ", parts.ToArray()) + ")";
        }

        // -------------------------------------------------------- evaluation
        public List<SigmaRule> Evaluate(EvtEvent e)
        {
            List<SVariant> list;
            List<SigmaRule> matched = null;
            if (byEventId.TryGetValue(e.Id, out list)) matched = EvaluateList(e, list, matched);
            if (anyEventId.Count > 0) matched = EvaluateList(e, anyEventId, matched);
            return matched;
        }
        static List<SigmaRule> EvaluateList(EvtEvent e, List<SVariant> list, List<SigmaRule> matched)
        {
            SCtx ctx = null;
            foreach (SVariant v in list)
            {
                if (v.Channel != null && !U.EqI(v.Channel, e.Channel)) continue;
                if (matched != null && matched.Contains(v.Rule)) continue;
                if (ctx == null) ctx = new SCtx();
                ctx.E = e; ctx.FieldMap = v.FieldMap;
                bool ok;
                try { ok = v.Condition.Eval(ctx); } catch (Exception) { ok = false; }
                if (!ok) continue;
                if (matched == null) matched = new List<SigmaRule>();
                matched.Add(v.Rule);
            }
            return matched;
        }

        public static int Score(string level)
        {
            switch ((level ?? "").ToLowerInvariant())
            {
                case "critical": return 95;
                case "high": return 85;
                case "medium": return 65;
                case "low": return 40;
                case "informational": return 20;
                default: return 50;
            }
        }
        static string Severity(string level)
        {
            int s = Score(level);
            return s >= 80 ? "High" : s >= 50 ? "Medium" : s >= 30 ? "Low" : "Info";
        }
        // Finding for an event that only a standalone Sigma rule matched.
        internal RuleDef FindingRule(List<SigmaRule> matched)
        {
            SigmaRule best = null;
            foreach (SigmaRule r in matched) { if (!r.Standalone) continue; if (best == null || Score(r.Level) > Score(best.Level)) best = r; }
            if (best == null) return null;
            RuleDef d = new RuleDef();
            d.Category = "Sigma";
            d.Severity = Severity(best.Level);
            d.Title = best.Title;
            string desc = best.Description.Replace("\n", " ");
            if (desc.Length > 300) desc = desc.Substring(0, 300) + "…";
            d.Note = "Правило Sigma " + best.Id + ". " + desc;
            d.RuleId = "SIGMA:" + best.Id;
            return d;
        }

        public void Record(EvtEvent e, List<SigmaRule> matched, string folder, string fileName, string fullPath, long findingId, long seq)
        {
            EventRef er = null;
            foreach (SigmaRule r in matched)
            {
                if (er == null) er = MakeRef(e, folder, fileName, findingId, seq);
                string scope = folder.ToLowerInvariant() + "|" + e.Computer.ToLowerInvariant();
                if (r.Standalone)
                {
                    string key = r.Index.ToString(CultureInfo.InvariantCulture) + "|" + scope;
                    SigmaAlert a;
                    if (!standalone.TryGetValue(key, out a))
                    {
                        a = NewAlert(r.Title, r.Id, r.Level, r.Description, r.Source, r.Fstec, r.Tags, r.FalsePositives, "detection", folder, e.Computer);
                        a.FirstTicks = e.Ticks; a.LastTicks = e.Ticks;
                        standalone[key] = a;
                    }
                    AddToAlert(a, er);
                }
                foreach (KeyValuePair<SigmaCorrelation, int> u in r.UsedBy) AddHit(u.Key, u.Value, r, e, er, scope);
            }
        }
        static EventRef MakeRef(EvtEvent e, string folder, string fileName, long findingId, long seq)
        {
            EventRef er = new EventRef();
            er.Computer = e.Computer; er.Folder = folder; er.File = fileName; er.RecordId = e.RecordId; er.TimeUtc = e.TimeUtc;
            er.Ticks = e.Ticks; er.EventId = e.Id; er.FindingId = findingId; er.Seq = seq; er.Fingerprint = e.Fingerprint;
            string account = e.Target;
            if (account.Length == 0) account = e.Subject;
            if (account.Length == 0) account = e.Get("User");
            er.Account = account;
            er.Ip = U.IsRemoteIp(e.SourceIP) ? U.NormalIp(e.SourceIP) : "";
            return er;
        }
        static void AddToAlert(SigmaAlert a, EventRef er)
        {
            a.Count++;
            if (er.Ticks < a.FirstTicks) a.FirstTicks = er.Ticks;
            if (er.Ticks > a.LastTicks) a.LastTicks = er.Ticks;
            if (a.Refs.Count < 20) a.Refs.Add(er);
            U.AddUnique(a.Accounts, er.Account, 10, true);
            U.AddUnique(a.Ips, er.Ip, 10, true);
            a.Ids[er.EventId] = true;
        }
        static string ResolveField(SigmaCorrelation c, SigmaRule r, string field)
        {
            Dictionary<string, string> alias;
            if (c.Aliases.TryGetValue(field, out alias))
            {
                string f;
                if (alias.TryGetValue(r.Name, out f) || alias.TryGetValue(r.Id, out f)) return f;
            }
            return field;
        }
        void AddHit(SigmaCorrelation c, int step, SigmaRule r, EvtEvent e, EventRef er, string scope)
        {
            if (c.Truncated) return;
            SCtx ctx = new SCtx(); ctx.E = e;
            foreach (SVariant v in r.Variants) if (v.Channel == null || U.EqI(v.Channel, e.Channel)) { ctx.FieldMap = v.FieldMap; break; }
            StringBuilder key = new StringBuilder(scope);
            StringBuilder text = new StringBuilder();
            foreach (string g in c.GroupBy)
            {
                string value = ctx.Field(ResolveField(c, r, g));
                if (value == null || value.Trim().Length == 0 || value == "-") return;
                key.Append('\u001f').Append(value.ToLowerInvariant());
                if (text.Length > 0) text.Append("; ");
                text.Append(g).Append('=').Append(value);
            }
            string val = null;
            if (c.Type == "value_count")
            {
                val = ctx.Field(ResolveField(c, r, c.ValueField));
                if (val == null || val.Trim().Length == 0 || val == "-") return;
            }
            string dedupe = step.ToString(CultureInfo.InvariantCulture) + "|" + er.Fingerprint;
            if (c.SeenHits.ContainsKey(dedupe)) return;
            if (c.Hits.Count >= MaxHitsPerCorrelation) { c.Truncated = true; Problem(c.Source, c.Id + " " + c.Title, "достигнут предел " + MaxHitsPerCorrelation + " событий; корреляция неполная", false); return; }
            c.SeenHits[dedupe] = true;
            SigmaHit h = new SigmaHit();
            h.Ticks = e.Ticks; h.Seq = er.Seq; h.Step = step; h.Key = key.ToString(); h.Value = val; h.Ref = er;
            if (!c.GroupText.ContainsKey(h.Key)) c.GroupText[h.Key] = text.ToString();
            c.Hits.Add(h);
        }

        static SigmaAlert NewAlert(string title, string id, string level, string description, string source, string fstec, List<string> tags, List<string> fps, string type, string folder, string computer)
        {
            SigmaAlert a = new SigmaAlert();
            a.Title = title; a.Id = id; a.Level = level; a.Description = description; a.Source = source; a.Fstec = fstec;
            a.Tags = tags; a.FalsePositives = fps; a.Type = type; a.Folder = folder; a.Computer = computer; a.Score = Score(level);
            return a;
        }

        // -------------------------------------------------------- correlation
        static int CompareHits(SigmaHit a, SigmaHit b)
        {
            int r = a.Ticks.CompareTo(b.Ticks);
            if (r != 0) return r;
            r = a.Seq.CompareTo(b.Seq);
            if (r != 0) return r;
            return b.Step.CompareTo(a.Step);
        }
        List<SigmaAlert> Correlate(SigmaCorrelation c)
        {
            List<SigmaAlert> alerts = new List<SigmaAlert>();
            Dictionary<string, List<SigmaHit>> groups = new Dictionary<string, List<SigmaHit>>(StringComparer.Ordinal);
            foreach (SigmaHit h in c.Hits)
            {
                List<SigmaHit> l;
                if (!groups.TryGetValue(h.Key, out l)) { l = new List<SigmaHit>(); groups[h.Key] = l; }
                l.Add(h);
            }
            List<string> keys = new List<string>(groups.Keys);
            keys.Sort(StringComparer.Ordinal);
            foreach (string key in keys)
            {
                List<SigmaHit> list = groups[key];
                list.Sort(CompareHits);
                string groupText = c.GroupText[key];
                if (c.Type == "event_count" || c.Type == "value_count") CountWindows(c, list, groupText, alerts);
                else if (c.Type == "temporal") Temporal(c, list, groupText, alerts);
                else Ordered(c, list, groupText, alerts);
            }
            return alerts;
        }
        void CountWindows(SigmaCorrelation c, List<SigmaHit> list, string groupText, List<SigmaAlert> alerts)
        {
            Queue<SigmaHit> window = new Queue<SigmaHit>();
            Dictionary<string, int> values = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            bool valueCount = c.Type == "value_count";
            long lastAlert = long.MinValue;
            foreach (SigmaHit h in list)
            {
                window.Enqueue(h);
                if (valueCount) { int n; values.TryGetValue(h.Value, out n); values[h.Value] = n + 1; }
                while (window.Peek().Ticks < h.Ticks - c.Span)
                {
                    SigmaHit old = window.Dequeue();
                    if (valueCount) { int n = values[old.Value] - 1; if (n == 0) values.Remove(old.Value); else values[old.Value] = n; }
                }
                long measure = valueCount ? values.Count : window.Count;
                if (!c.Satisfied(measure) || (lastAlert != long.MinValue && h.Ticks - lastAlert < c.Span)) continue;
                lastAlert = h.Ticks;
                SigmaHit[] items = window.ToArray();
                SigmaAlert a = CorrAlert(c, items, groupText);
                if (valueCount)
                {
                    List<string> distinct = new List<string>(values.Keys);
                    distinct.Sort(StringComparer.OrdinalIgnoreCase);
                    string shown = U.Join(", ", distinct.Count > 15 ? distinct.GetRange(0, 15) : distinct) + (distinct.Count > 15 ? ", …" : "");
                    a.Chain = items.Length.ToString(CultureInfo.InvariantCulture) + " событ. (" + IdList(a) + ") за " + U.Duration(a.LastTicks - a.FirstTicks) +
                        "; разных значений " + c.ValueField + ": " + distinct.Count.ToString(CultureInfo.InvariantCulture) + " — " + shown;
                }
                else
                {
                    a.Chain = "Event ID " + IdList(a) + " ×" + items.Length.ToString(CultureInfo.InvariantCulture) + " за " + U.Duration(a.LastTicks - a.FirstTicks) +
                        " (" + U.UtcText(a.FirstTicks) + " – " + U.UtcText(a.LastTicks) + " UTC)";
                }
                alerts.Add(a);
            }
        }
        void Temporal(SigmaCorrelation c, List<SigmaHit> list, string groupText, List<SigmaAlert> alerts)
        {
            SigmaHit[] latest = new SigmaHit[c.Steps.Count];
            foreach (SigmaHit h in list)
            {
                latest[h.Step] = h;
                bool all = true;
                Dictionary<long, bool> events = new Dictionary<long, bool>();
                for (int i = 0; i < latest.Length; i++)
                {
                    if (latest[i] == null || latest[i].Ticks < h.Ticks - c.Span) { all = false; break; }
                    events[latest[i].Seq] = true;
                }
                if (!all || events.Count < latest.Length) continue;
                List<SigmaHit> chain = new List<SigmaHit>(latest);
                chain.Sort(CompareHits);
                alerts.Add(ChainAlert(c, chain, groupText));
                for (int i = 0; i < latest.Length; i++) latest[i] = null;
            }
        }
        void Ordered(SigmaCorrelation c, List<SigmaHit> list, string groupText, List<SigmaAlert> alerts)
        {
            int steps = c.Steps.Count;
            List<SigmaHit>[] chains = new List<SigmaHit>[steps];
            foreach (SigmaHit h in list)
            {
                int k = h.Step;
                if (k == 0) chains[0] = new List<SigmaHit>(new SigmaHit[] { h });
                else
                {
                    List<SigmaHit> prev = chains[k - 1];
                    if (prev != null && h.Ticks - prev[0].Ticks <= c.Span && prev[prev.Count - 1].Seq != h.Seq)
                    {
                        List<SigmaHit> candidate = new List<SigmaHit>(prev);
                        candidate.Add(h);
                        if (chains[k] == null || candidate[0].Ticks >= chains[k][0].Ticks) chains[k] = candidate;
                    }
                }
                if (chains[steps - 1] != null)
                {
                    alerts.Add(ChainAlert(c, chains[steps - 1], groupText));
                    for (int i = 0; i < steps; i++) chains[i] = null;
                }
            }
        }
        SigmaAlert CorrAlert(SigmaCorrelation c, IList<SigmaHit> hits, string groupText)
        {
            SigmaAlert a = NewAlert(c.Title, c.Id, c.Level, c.Description, c.Source, c.Fstec, c.Tags, c.FalsePositives, c.Type, hits[0].Ref.Folder, hits[0].Ref.Computer);
            a.Group = groupText;
            a.FirstTicks = hits[0].Ticks; a.LastTicks = hits[0].Ticks;
            foreach (SigmaHit h in hits) AddToAlert(a, h.Ref);
            return a;
        }
        SigmaAlert ChainAlert(SigmaCorrelation c, List<SigmaHit> chain, string groupText)
        {
            SigmaAlert a = CorrAlert(c, chain, groupText);
            List<string> parts = new List<string>();
            foreach (SigmaHit h in chain)
                parts.Add(c.Steps[h.Step].Title + " (" + h.Ref.EventId.ToString(CultureInfo.InvariantCulture) + ", " + U.UtcText(h.Ticks) + ")");
            a.Chain = string.Join(" → ", parts.ToArray()) + "; интервал " + U.Duration(a.LastTicks - a.FirstTicks);
            return a;
        }
        static string IdList(SigmaAlert a)
        {
            List<string> l = new List<string>();
            foreach (int id in a.Ids.Keys) l.Add(id.ToString(CultureInfo.InvariantCulture));
            return string.Join(", ", l.ToArray());
        }

        // -------------------------------------------------------- output
        public static readonly string[] AlertHeaders = new string[] {
            "Приоритет", "Оценка риска", "Уровень Sigma", "Тип", "Правило", "ID правила", "Компьютер", "Папка источника",
            "Первое время UTC", "Последнее время UTC", "Событий", "Группировка", "Учетные записи", "IP источника", "Event ID",
            "Цепочка событий", "Ссылки на события", "Тактика", "MITRE ATT&CK", "Меры ФСТЭК №239 (группы)", "Описание", "Ложные срабатывания", "Источник правила" };

        public int Finish(TextWriter w, string delimiter)
        {
            List<SigmaAlert> all = new List<SigmaAlert>();
            foreach (SigmaAlert a in standalone.Values)
            {
                a.Chain = "Event ID " + IdList(a) + " ×" + a.Count.ToString(CultureInfo.InvariantCulture) +
                    (a.Count > 1 ? " (" + U.UtcText(a.FirstTicks) + " – " + U.UtcText(a.LastTicks) + " UTC)" : " (" + U.UtcText(a.FirstTicks) + " UTC)");
                a.Group = "";
                all.Add(a);
            }
            foreach (SigmaCorrelation c in Correlations) all.AddRange(Correlate(c));
            all.Sort(delegate(SigmaAlert x, SigmaAlert y)
            {
                int r = y.Score.CompareTo(x.Score);
                if (r != 0) return r;
                r = string.Compare(x.Computer, y.Computer, StringComparison.OrdinalIgnoreCase);
                if (r != 0) return r;
                return x.FirstTicks.CompareTo(y.FirstTicks);
            });
            Csv.Row(w, delimiter, AlertHeaders);
            foreach (SigmaAlert a in all)
            {
                List<string> refs = new List<string>();
                foreach (EventRef r in a.Refs)
                    refs.Add(r.File + "#" + r.RecordId + " (Event ID " + r.EventId.ToString(CultureInfo.InvariantCulture) + ", " + U.UtcText(r.Ticks) + (r.FindingId > 0 ? ", находка " + r.FindingId.ToString(CultureInfo.InvariantCulture) : "") + ")");
                List<string> tactics = new List<string>(), techniques = new List<string>();
                List<string> fstec = new List<string>();
                foreach (string t in a.Tags)
                {
                    Match m = TechniqueTag.Match(t);
                    if (m.Success) { U.AddUnique(techniques, m.Groups[1].Value.ToUpperInvariant(), 20, true); continue; }
                    m = TacticTag.Match(t.ToLowerInvariant());
                    string name;
                    if (m.Success && Tactics.TryGetValue(m.Groups[1].Value, out name))
                    {
                        U.AddUnique(tactics, name, 10, true);
                        string f;
                        if (TacticFstec.TryGetValue(m.Groups[1].Value, out f)) foreach (string x in f.Split(',')) U.AddUnique(fstec, x.Trim(), 10, true);
                    }
                }
                string fstecText = a.Fstec.Length > 0 ? a.Fstec : U.Join(", ", fstec);
                List<string> idText = new List<string>();
                foreach (int id in a.Ids.Keys) idText.Add(id.ToString(CultureInfo.InvariantCulture));
                string priority = a.Score >= 80 ? PriorityHigh : a.Score >= 50 ? PriorityMedium : PriorityLow;
                string typeText = a.Type == "detection" ? "Одиночное правило" : "Корреляция " + a.Type;
                Csv.Row(w, delimiter, new string[] {
                    priority, a.Score.ToString(CultureInfo.InvariantCulture), a.Level, typeText, a.Title, a.Id, a.Computer, a.Folder,
                    U.UtcText(a.FirstTicks), U.UtcText(a.LastTicks), a.Count.ToString(CultureInfo.InvariantCulture), a.Group,
                    U.Join(" | ", a.Accounts), U.Join(" | ", a.Ips), string.Join(", ", idText.ToArray()), a.Chain, U.Join(" || ", refs),
                    U.Join(" → ", tactics), U.Join(", ", techniques), fstecText, a.Description.Replace("\n", " "),
                    U.Join("; ", a.FalsePositives), a.Source });
            }
            return all.Count;
        }
    }

    // Recursive descent parser for Sigma conditions:
    // and / or / not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them".
    sealed class ConditionParser
    {
        readonly List<string> tokens = new List<string>();
        readonly Dictionary<string, SSelection> selections;
        int pos;
        public ConditionParser(string text, Dictionary<string, SSelection> sel)
        {
            selections = sel;
            if (text.IndexOf('|') >= 0) throw new NotSupportedException("агрегации в condition («|») не поддерживаются; используйте correlation");
            foreach (Match m in Regex.Matches(text, @"\(|\)|[^\s()]+", RegexOptions.CultureInvariant)) tokens.Add(m.Value);
        }
        string Peek() { return pos < tokens.Count ? tokens[pos] : null; }
        bool Is(string t, string word) { return t != null && string.Equals(t, word, StringComparison.OrdinalIgnoreCase); }
        public SNode Parse()
        {
            SNode n = ParseOr();
            if (pos != tokens.Count) throw new FormatException("condition: лишний токен «" + tokens[pos] + "»");
            return n;
        }
        SNode ParseOr()
        {
            SNode left = ParseAnd();
            if (!Is(Peek(), "or")) return left;
            SOr or = new SOr(); or.Items.Add(left);
            while (Is(Peek(), "or")) { pos++; or.Items.Add(ParseAnd()); }
            return or;
        }
        SNode ParseAnd()
        {
            SNode left = ParseNot();
            if (!Is(Peek(), "and")) return left;
            SAnd and = new SAnd(); and.Items.Add(left);
            while (Is(Peek(), "and")) { pos++; and.Items.Add(ParseNot()); }
            return and;
        }
        SNode ParseNot()
        {
            if (Is(Peek(), "not")) { pos++; SNot n = new SNot(); n.Item = ParseNot(); return n; }
            return ParsePrimary();
        }
        SNode ParsePrimary()
        {
            string t = Peek();
            if (t == null) throw new FormatException("condition: неожиданный конец");
            if (t == "(")
            {
                pos++;
                SNode n = ParseOr();
                if (Peek() != ")") throw new FormatException("condition: нет закрывающей скобки");
                pos++;
                return n;
            }
            if ((t == "1" || Is(t, "any") || Is(t, "all")) && pos + 1 < tokens.Count && Is(tokens[pos + 1], "of"))
            {
                bool all = Is(t, "all");
                pos += 2;
                string target = Peek();
                if (target == null) throw new FormatException("condition: после «of» ожидается имя");
                pos++;
                List<SNode> items = new List<SNode>();
                if (Is(target, "them"))
                {
                    foreach (KeyValuePair<string, SSelection> kv in selections) if (!kv.Key.StartsWith("_", StringComparison.Ordinal)) items.Add(Sel(kv.Value));
                }
                else
                {
                    Regex rx = new Regex("^" + Regex.Escape(target).Replace("\\*", ".*") + "$", RegexOptions.CultureInvariant);
                    foreach (KeyValuePair<string, SSelection> kv in selections) if (rx.IsMatch(kv.Key)) items.Add(Sel(kv.Value));
                }
                if (items.Count == 0) throw new FormatException("condition: нет выборок для «" + target + "»");
                if (items.Count == 1) return items[0];
                if (all) { SAnd a = new SAnd(); a.Items.AddRange(items); return a; }
                SOr o = new SOr(); o.Items.AddRange(items); return o;
            }
            pos++;
            SSelection s;
            if (!selections.TryGetValue(t, out s)) throw new FormatException("condition: неизвестная выборка «" + t + "»");
            return Sel(s);
        }
        static SNode Sel(SSelection s) { SSel n = new SSel(); n.Sel = s; return n; }
    }
}
'@
# Embedded Sigma rule pack (Sigma v2 rules and correlation rules).
$script:SigmaPack=@'
# Встроенный пакет правил Sigma (формат Sigma v2, корреляции по спецификации
# Sigma Correlation Rules). Базовые правила с полем name используются только в
# корреляциях и сами не дают срабатываний; одиночные правила (без ссылок из
# корреляций) дают срабатывания. Поле fstec239 — нестандартное расширение:
# группы мер приказа ФСТЭК России №239.
title: Создана учетная запись
id: 36ac2807-90cc-43c1-af6b-28e935335552
name: evtxa_account_created
status: test
description: Создание локальной или доменной учетной записи (4720). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1136
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
level: informational
---
title: Удалена учетная запись
id: 1efc515a-5834-4af5-8dbd-e4026fa77e37
name: evtxa_account_deleted
status: test
description: Удаление учетной записи (4726). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4726
    condition: selection
level: informational
---
title: Включена учетная запись
id: 1e571f09-0e34-4e3b-aff4-f4f6ad282ac7
name: evtxa_account_enabled
status: test
description: Учетная запись включена (4722). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4722
    condition: selection
level: informational
---
title: Отключена учетная запись
id: 20c191f3-e95d-4c27-97d2-e71ebb29a82d
name: evtxa_account_disabled
status: test
description: Учетная запись отключена (4725). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4725
    condition: selection
level: informational
---
title: Неудачный вход с сетевого адреса
id: 6cccfbc5-7afb-4983-8fcb-1bf3885b7ae0
name: evtxa_failed_logon
status: test
description: Неудачный вход (4625) с известным удаленным адресом. Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    filter_local:
        IpAddress:
            - '-'
            - '127.0.0.1'
            - '::1'
            - ''
    condition: selection and not filter_local
level: informational
---
title: Успешный RDP-вход
id: f63ff011-a14e-4ba8-a03e-4b34c3d31314
name: evtxa_rdp_logon
status: test
description: Успешный вход типа 10 (RemoteInteractive). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    condition: selection
level: informational
---
title: Вход с явными учетными данными на другой узел
id: 3b185395-9653-4ff5-87fb-551c9619423f
name: evtxa_explicit_credentials
status: test
description: Вход с явными учетными данными (4648) не от служебных учетных записей и не на локальный узел. Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4648
    filter_system:
        SubjectUserSid:
            - 'S-1-5-18'
            - 'S-1-5-19'
            - 'S-1-5-20'
    filter_local:
        TargetServerName:
            - 'localhost'
            - '-'
            - '127.0.0.1'
    condition: selection and not filter_system and not filter_local
level: informational
---
title: Запрос билета TGS со слабым шифрованием RC4
id: f04b9233-fce7-4cf3-8b34-79e5bd6ef906
name: evtxa_kerberos_rc4_tgs
status: test
description: Выдан билет службы Kerberos (4769) с шифрованием RC4 (0x17) для пользовательской службы. Базовое правило для корреляции Kerberoasting.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        Status: '0x0'
    filter_machine:
        ServiceName|endswith: '$'
    filter_krbtgt:
        ServiceName: 'krbtgt'
    condition: selection and not filter_machine and not filter_krbtgt
level: informational
---
title: Создано задание планировщика
id: bebe2a07-7f59-42f0-9d19-9b0e6fbb73fd
name: evtxa_task_created
status: test
description: Создано задание планировщика (4698). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    condition: selection
level: informational
---
title: Удалено задание планировщика
id: b4e2889c-b3c9-4fd4-9f6f-385ae61acdba
name: evtxa_task_deleted
status: test
description: Удалено задание планировщика (4699). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4699
    condition: selection
level: informational
---
title: Закрепление (служба, задание или учетная запись)
id: ce65d9d0-bacb-4d95-a509-497e4396b2c8
name: evtxa_persistence_security
status: test
description: Установка службы (4697), создание задания (4698) или учетной записи (4720) по журналу Security. Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4697
            - 4698
            - 4720
    condition: selection
level: informational
---
title: Установлена служба
id: dcf0eb8d-f928-4083-ba74-42e820cefe96
name: evtxa_service_installed
status: test
description: Установлена служба (System 7045). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    condition: selection
level: informational
---
title: Очищен журнал Security
id: 44c81f46-3495-4c22-aef6-646ccd9c0cb4
name: evtxa_security_log_cleared
status: test
description: Очищен журнал Security (1102). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        Provider_Name: 'Microsoft-Windows-Eventlog'
        EventID: 1102
    condition: selection
level: informational
---
title: Очищен журнал System или Application
id: 9c34d675-cabe-4d8e-917e-0801958ff669
name: evtxa_system_log_cleared
status: test
description: Очищен журнал (System 104). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Microsoft-Windows-Eventlog'
        EventID: 104
    condition: selection
level: informational
---
title: Изменена политика аудита
id: 0e7d3eec-6f85-4e60-8809-f351b301ee69
name: evtxa_audit_policy_changed
status: test
description: Изменена системная политика аудита (4719). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4719
    condition: selection
level: informational
---
title: Defender обнаружил угрозу
id: 58997515-919b-4bbf-8f55-0e4acd17f8a9
name: evtxa_defender_detection
status: test
description: Обнаружение вредоносного ПО Microsoft Defender (1006, 1015, 1116). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 1006
            - 1015
            - 1116
    condition: selection
level: informational
---
title: Defender обработал угрозу
id: a83d3ab2-7c29-49ff-94c3-5285cb235f64
name: evtxa_defender_action
status: test
description: Microsoft Defender выполнил действие над угрозой (1007, 1117). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 1007
            - 1117
    condition: selection
level: informational
---
title: Системное время изменено пользователем
id: 231a4dfb-a669-4c1d-a18e-6ec468536803
name: evtxa_time_changed_by_user
status: test
description: Изменение системного времени (4616) не службой времени Windows. Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4616
    filter_service:
        SubjectUserSid:
            - 'S-1-5-18'
            - 'S-1-5-19'
    condition: selection and not filter_service
level: informational
---
title: Подключен USB-накопитель (Kernel-PnP)
id: 0bdc05bb-d287-498d-8739-0fb52bf185b6
name: evtxa_usb_kernelpnp
status: test
description: Настроено или запущено запоминающее устройство USB либо устройство WPD (Kernel-PnP/Configuration 400, 410). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: kernel-pnp-configuration
detection:
    selection:
        EventID:
            - 400
            - 410
        DeviceInstanceId|startswith:
            - 'USBSTOR\'
            - 'SWD\WPDBUSENUM\'
    condition: selection
level: informational
---
title: Подключен USB-накопитель (Partition)
id: d6bfbb9b-6142-4e5e-b620-43e327fb0d62
name: evtxa_usb_partition
status: test
description: Подключен диск на шине USB, SD или MMC (Partition/Diagnostic 1006). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: partition-diagnostic
detection:
    selection:
        EventID: 1006
        BusType:
            - 7
            - 12
            - 13
    condition: selection
level: informational
---
title: Распознано внешнее запоминающее устройство
id: ceb881fe-6d64-4810-a5e6-7d5c9a9ab92d
name: evtxa_usb_security
status: test
description: Распознано новое внешнее устройство хранения (Security 6416, аудит Plug and Play). Базовое правило для корреляций.
author: EVTX Audit
date: 2026-10-08
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 6416
    selection_device:
        - DeviceId|startswith:
              - 'USBSTOR\'
              - 'SWD\WPDBUSENUM\'
        - ClassName:
              - 'DiskDrive'
              - 'WPD'
    condition: selection and selection_device
level: informational
---
title: Распределенный подбор пароля к одной учетной записи
id: 52d0d475-79de-427e-8c24-4bc739a05141
status: test
description: Неудачные входы одной учетной записи с пяти и более разных адресов за 30 минут — подбор пароля с нескольких узлов или ботнета. Дополняет лист «Подбор_пароля», где серии группируются по источнику.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.credential-access
    - attack.t1110
fstec239: [ИАФ, УПД]
correlation:
    type: value_count
    rules:
        - evtxa_failed_logon
    group-by:
        - TargetUserName
    timespan: 30m
    condition:
        gte: 5
        field: IpAddress
falsepositives:
    - Мобильные пользователи и VPN с меняющимися адресами при устаревшем сохраненном пароле
level: high
---
title: Kerberoasting — массовый запрос билетов служб с RC4
id: c007bf09-66e3-413b-ba89-a04b34538263
status: test
description: Одна учетная запись за 5 минут запросила билеты TGS с шифрованием RC4 для десяти и более разных служб — типичный сбор хешей для офлайн-подбора паролей сервисных учетных записей.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.credential-access
    - attack.t1558.003
fstec239: [ИАФ, УПД]
correlation:
    type: value_count
    rules:
        - evtxa_kerberos_rc4_tgs
    group-by:
        - TargetUserName
    timespan: 5m
    condition:
        gte: 10
        field: ServiceName
falsepositives:
    - Устаревшие домены и приложения, работающие только с RC4
level: high
---
title: Одноразовое задание планировщика (удаленное выполнение, atexec)
id: 89326f11-1bca-41b2-9fec-936cf0bf29b3
status: test
description: Задание планировщика создано и удалено в течение 10 минут. Так работают Impacket atexec и аналогичные средства удаленного выполнения команд.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1053.005
fstec239: [ОПС, УПД]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_task_created
        - evtxa_task_deleted
    group-by:
        - TaskName
    timespan: 10m
falsepositives:
    - Установщики ПО, создающие временные задания
level: high
---
title: Закрепление с последующей очисткой журнала Security
id: a492bc45-711e-45b7-803d-9aaeffb857b6
status: test
description: После установки службы, создания задания или учетной записи в течение 2 часов очищен журнал Security — признак сокрытия следов закрепления.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1070.001
fstec239: [АУД, УПД]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_persistence_security
        - evtxa_security_log_cleared
    timespan: 2h
falsepositives:
    - Плановое обслуживание с очисткой журналов (должно быть согласовано)
level: high
---
title: Установка службы с последующей очисткой журнала Security
id: 36633cf0-2224-4ba1-85c3-9885f194fded
status: test
description: После установки службы (System 7045) в течение 2 часов очищен журнал Security.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1543.003
    - attack.t1070.001
fstec239: [АУД, ОПС]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_service_installed
        - evtxa_security_log_cleared
    timespan: 2h
falsepositives:
    - Плановое обслуживание с очисткой журналов (должно быть согласовано)
level: high
---
title: Установка службы с последующей очисткой журнала System
id: eef8c318-7089-4a1f-980e-0fcea9575b49
status: test
description: После установки службы (7045) в течение 2 часов очищен журнал System или Application (104).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1543.003
    - attack.t1070.001
fstec239: [АУД, ОПС]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_service_installed
        - evtxa_system_log_cleared
    timespan: 2h
falsepositives:
    - Плановое обслуживание с очисткой журналов (должно быть согласовано)
level: high
---
title: Повторное обнаружение угрозы после ее обработки
id: 47af0b79-9c8c-4992-ab8e-04dd9571b04a
status: test
description: Defender обработал угрозу, но в течение суток та же угроза обнаружена снова — источник заражения или механизм закрепления не устранен.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.execution
fstec239: [АВЗ]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_defender_action
        - evtxa_defender_detection
    group-by:
        - Threat Name
    timespan: 1d
falsepositives:
    - Повторное копирование одного и того же зараженного файла пользователем
level: high
---
title: Множественные обнаружения вредоносного ПО на узле
id: 1aa5dfd4-ca97-4a27-96dd-a00170271998
status: test
description: Пять и более обнаружений Defender на одном компьютере за час — возможная активная эпидемия или попытки запуска разных инструментов.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.execution
fstec239: [АВЗ]
correlation:
    type: event_count
    rules:
        - evtxa_defender_detection
    timespan: 1h
    condition:
        gte: 5
falsepositives:
    - Проверка архива или носителя с коллекцией вредоносных образцов
level: high
---
title: Временно включенная учетная запись
id: 17b26b0c-e31a-486f-9e83-f77028496db4
status: test
description: Учетная запись включена и в течение суток снова отключена. Характерно для временного использования встроенного Администратора, Гостя или учетных записей подрядчиков.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1078
fstec239: [УПД]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_account_enabled
        - evtxa_account_disabled
    group-by:
        - TargetSid
    timespan: 1d
falsepositives:
    - Согласованное временное предоставление доступа подрядчику
level: medium
---
title: RDP-входы одной учетной записи с разных адресов
id: 53382da5-475b-4176-ae01-4b918d320852
status: test
description: Одна учетная запись за час вошла по RDP с трех и более разных адресов — совместное использование учетной записи или ее компрометация.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.lateral-movement
    - attack.t1021.001
    - attack.t1078
fstec239: [УПД, ИАФ]
correlation:
    type: value_count
    rules:
        - evtxa_rdp_logon
    group-by:
        - TargetUserName
    timespan: 1h
    condition:
        gte: 3
        field: IpAddress
falsepositives:
    - Администраторы, работающие с нескольких АРМ
level: medium
---
title: Использование явных учетных данных для доступа ко многим узлам
id: f617ab44-e4b7-43d7-a766-9505c0fce031
status: test
description: Одна учетная запись за 10 минут использовала явные учетные данные (4648) для пяти и более разных узлов — возможное боковое перемещение или проверка украденных учетных данных.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.lateral-movement
    - attack.t1078
    - attack.t1021
fstec239: [УПД, ИАФ]
correlation:
    type: value_count
    rules:
        - evtxa_explicit_credentials
    group-by:
        - SubjectUserName
    timespan: 10m
    condition:
        gte: 5
        field: TargetServerName
falsepositives:
    - Скрипты администрирования, обходящие серверы
level: medium
---
title: Подключение USB-накопителя и установка службы (Kernel-PnP)
id: 2cf378bb-5876-42aa-95c7-680ae712add9
status: test
description: После подключения USB-накопителя в течение 30 минут установлена служба. В изолированном сегменте АСУ ТП это возможный перенос ВПО или неучтенного ПО через съемный носитель.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.initial-access
    - attack.t1091
    - attack.persistence
    - attack.t1543.003
fstec239: [ЗНИ, ОПС]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_usb_kernelpnp
        - evtxa_service_installed
    timespan: 30m
falsepositives:
    - Согласованная установка ПО с носителя
level: medium
---
title: Подключение USB-накопителя и установка службы (Partition)
id: f2c991fa-35f1-4368-8905-0e7dd67d8ec5
status: test
description: После подключения диска на шине USB/SD в течение 30 минут установлена служба.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.initial-access
    - attack.t1091
    - attack.persistence
    - attack.t1543.003
fstec239: [ЗНИ, ОПС]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_usb_partition
        - evtxa_service_installed
    timespan: 30m
falsepositives:
    - Согласованная установка ПО с носителя
level: medium
---
title: Подключение USB-накопителя и установка службы (Security 6416)
id: ddeaf5b5-43d3-4aa7-a7b2-9ab3bf53ac27
status: test
description: После распознавания внешнего запоминающего устройства в течение 30 минут установлена служба.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.initial-access
    - attack.t1091
    - attack.persistence
    - attack.t1543.003
fstec239: [ЗНИ, ОПС]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_usb_security
        - evtxa_service_installed
    timespan: 30m
falsepositives:
    - Согласованная установка ПО с носителя
level: medium
---
title: Изменение времени и очистка журнала
id: 30185600-5c61-4425-9dc9-9eeb6f75e95a
status: test
description: Пользователь изменил системное время, и в пределах часа очищен журнал Security — сокрытие и искажение хронологии событий.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.defense-evasion
    - attack.t1070.006
    - attack.t1070.001
fstec239: [АУД]
correlation:
    type: temporal
    rules:
        - evtxa_time_changed_by_user
        - evtxa_security_log_cleared
    timespan: 1h
falsepositives:
    - Ручная коррекция времени при обслуживании с очисткой журнала (должна быть согласована)
level: high
---
title: Изменение политики аудита и последующее закрепление в той же сессии
id: 033b5aaf-e909-4f27-ba64-b2d79f826dbf
status: test
description: Сессия, изменившая политику аудита, в течение часа установила службу, создала задание или учетную запись (один SubjectLogonId).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.defense-evasion
    - attack.t1562.002
    - attack.persistence
fstec239: [АУД, УПД]
correlation:
    type: temporal_ordered
    rules:
        - evtxa_audit_policy_changed
        - evtxa_persistence_security
    group-by:
        - SubjectLogonId
    timespan: 1h
falsepositives:
    - Ввод в эксплуатацию с настройкой аудита и учетных записей одним администратором
level: high
---
title: Массовое создание учетных записей
id: 29c27c7a-f498-40d0-8891-b3bb7fd90a83
status: test
description: Три и более учетных записи созданы на одном компьютере за час.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1136
fstec239: [УПД]
correlation:
    type: event_count
    rules:
        - evtxa_account_created
    timespan: 1h
    condition:
        gte: 3
falsepositives:
    - Плановое заведение пользователей
level: medium
---
title: Массовое удаление учетных записей
id: da39fbf0-e57d-487d-bc18-0ccc666f7ea0
status: test
description: Три и более учетных записи удалены на одном компьютере за час — возможное нарушение доступности (лишение операторов доступа) или сокрытие следов.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.impact
    - attack.t1531
fstec239: [УПД, ОДТ]
correlation:
    type: event_count
    rules:
        - evtxa_account_deleted
    timespan: 1h
    condition:
        gte: 3
falsepositives:
    - Плановая чистка учетных записей
level: medium
---
title: Массовое отключение учетных записей
id: a56213fd-9ebd-4ba3-9cbb-9d93be50e146
status: test
description: Три и более учетных записи отключены на одном компьютере за час — возможное лишение доступа (воздействие на доступность).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.impact
    - attack.t1531
fstec239: [УПД, ОДТ]
correlation:
    type: event_count
    rules:
        - evtxa_account_disabled
    timespan: 1h
    condition:
        gte: 3
falsepositives:
    - Плановое отключение учетных записей уволенных сотрудников
level: medium
---
title: Массовая установка служб
id: a8b026fa-e254-43cc-b278-fa3a4c44f3b6
status: test
description: Три и более службы установлены на одном компьютере за 10 минут — средства удаленного выполнения (PsExec и аналоги) или установка ПО.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.execution
    - attack.t1569.002
fstec239: [ОПС]
correlation:
    type: event_count
    rules:
        - evtxa_service_installed
    timespan: 10m
    condition:
        gte: 3
falsepositives:
    - Установка или обновление прикладного ПО
level: medium
---
title: Overpass-the-Hash / Pass-the-Hash (вход типа 9 через seclogo)
id: 0a5b8772-4a87-4507-9788-7514169a326d
status: test
description: Вход с новыми учетными данными (тип 9) процессом seclogo с пакетом Negotiate. Так выглядит запуск процесса с подставленным хешем пароля (утилиты Pass-the-Hash) и runas /netonly.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.lateral-movement
    - attack.t1550.002
fstec239: [ИАФ, УПД]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: 'seclogo'
        AuthenticationPackageName: 'Negotiate'
    condition: selection
falsepositives:
    - Легитимное использование runas /netonly администраторами
level: high
---
title: Создана скрытая учетная запись (имя оканчивается на $)
id: ce5212e2-c71d-4d0d-861a-8ab6730d2ce3
status: test
description: Имя новой учетной записи оканчивается символом $, как у учетных записей компьютеров; такие записи не видны в части оснасток.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.defense-evasion
    - attack.t1564.002
fstec239: [УПД]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        TargetUserName|endswith: '$'
    condition: selection
falsepositives:
    - Не ожидаются для локальных учетных записей
level: high
---
title: Включена учетная запись Гость
id: 624385f4-2e68-4240-a1c1-1855b2db2796
status: test
description: Включена встроенная учетная запись Гость (RID 501).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1078.001
fstec239: [УПД, ИАФ]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4722
        TargetSid|endswith: '-501'
    condition: selection
falsepositives:
    - Не ожидаются
level: high
---
title: Включена встроенная учетная запись Администратор
id: b9c8e0c7-7489-401e-a1d1-dcad56ce3eae
status: test
description: Включена встроенная учетная запись Администратор (RID 500). Использование общей встроенной учетной записи затрудняет персонификацию действий.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1078.001
fstec239: [УПД, ИАФ]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4722
        TargetSid|endswith: '-500'
    condition: selection
falsepositives:
    - Согласованное аварийное использование встроенной учетной записи
level: medium
---
title: Сброшен пароль встроенной учетной записи Администратор
id: 4c9edb96-2d0b-435b-9bad-834703821f89
status: test
description: Другой учетной записью сброшен пароль встроенного Администратора (RID 500).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.persistence
    - attack.t1098
fstec239: [УПД, ИАФ]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4724
        TargetSid|endswith: '-500'
    condition: selection
falsepositives:
    - Плановая смена пароля встроенной учетной записи (LAPS и аналоги)
level: medium
---
title: RDP-вход под встроенной учетной записью Администратор
id: 7a98f69c-0f6a-48a5-80ff-55f0e287eb60
status: test
description: Удаленный вход (тип 10) под встроенной учетной записью Администратор (RID 500) — действия не персонифицированы.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.lateral-movement
    - attack.t1021.001
    - attack.t1078.001
fstec239: [УПД, ИАФ]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        TargetUserSid|endswith: '-500'
    condition: selection
falsepositives:
    - Согласованное аварийное администрирование
level: medium
---
title: Установлено средство удаленного доступа (служба)
id: 7a3b74ff-f608-419a-b91c-9963f66b78f3
status: test
description: Установлена служба средства удаленного доступа (TeamViewer, AnyDesk, Radmin, RMS, VNC, LiteManager, Ammyy, RustDesk и др.). В сегменте АСУ ТП это неконтролируемый канал удаленного доступа, если он не согласован.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.command-and-control
    - attack.t1219
fstec239: [УПД, ОПС]
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_tool:
        - ServiceName|contains:
              - 'TeamViewer'
              - 'AnyDesk'
              - 'Radmin'
              - 'RManService'
              - 'LiteManager'
              - 'ROMServer'
              - 'Ammyy'
              - 'AeroAdmin'
              - 'Splashtop'
              - 'ScreenConnect'
              - 'RustDesk'
              - 'DWAgent'
              - 'NetSupport'
              - 'DameWare'
              - 'Mesh Agent'
              - 'AteraAgent'
              - 'TightVNC'
              - 'UltraVNC'
              - 'uvnc_service'
              - 'RealVNC'
              - 'VNC Server'
              - 'Chrome Remote Desktop'
              - 'LogMeIn'
              - 'GoToAssist'
              - 'Getscreen'
              - 'AnyViewer'
              - 'ToDesk'
              - 'Supremo'
              - 'NoMachine'
              - 'Remote Utilities'
        - ImagePath|contains:
              - 'TeamViewer'
              - 'AnyDesk'
              - 'rserver3'
              - 'rutserv'
              - 'rfusclient'
              - 'LiteManager'
              - 'ROMServer'
              - 'Ammyy'
              - 'AeroAdmin'
              - 'Splashtop'
              - 'ScreenConnect'
              - 'rustdesk'
              - 'dwagent'
              - 'client32.exe'
              - 'DWRCS'
              - 'MeshAgent'
              - 'AteraAgent'
              - 'tvnserver'
              - 'winvnc'
              - 'vncserver'
              - 'remoting_host'
              - 'LogMeIn'
              - 'g2ax_'
              - 'getscreen'
              - 'AnyViewer'
              - 'ToDesk'
              - 'Supremo'
              - 'nxservice'
    condition: selection and selection_tool
falsepositives:
    - Согласованное средство удаленного обслуживания поставщика (должно быть учтено и контролироваться)
level: high
---
title: Установлено средство удаленного доступа (служба, Security 4697)
id: f2241285-3566-4689-96f8-268c43c583ab
status: test
description: Установлена служба средства удаленного доступа (по журналу Security 4697).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.command-and-control
    - attack.t1219
fstec239: [УПД, ОПС]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4697
    selection_tool:
        - ServiceName|contains:
              - 'TeamViewer'
              - 'AnyDesk'
              - 'Radmin'
              - 'RManService'
              - 'LiteManager'
              - 'ROMServer'
              - 'Ammyy'
              - 'AeroAdmin'
              - 'Splashtop'
              - 'ScreenConnect'
              - 'RustDesk'
              - 'DWAgent'
              - 'NetSupport'
              - 'DameWare'
              - 'Mesh Agent'
              - 'AteraAgent'
              - 'TightVNC'
              - 'UltraVNC'
              - 'uvnc_service'
              - 'RealVNC'
              - 'VNC Server'
              - 'Chrome Remote Desktop'
              - 'LogMeIn'
              - 'NoMachine'
              - 'Remote Utilities'
        - ServiceFileName|contains:
              - 'TeamViewer'
              - 'AnyDesk'
              - 'rserver3'
              - 'rutserv'
              - 'rfusclient'
              - 'LiteManager'
              - 'ROMServer'
              - 'Ammyy'
              - 'AeroAdmin'
              - 'Splashtop'
              - 'ScreenConnect'
              - 'rustdesk'
              - 'dwagent'
              - 'client32.exe'
              - 'DWRCS'
              - 'MeshAgent'
              - 'AteraAgent'
              - 'tvnserver'
              - 'winvnc'
              - 'vncserver'
              - 'remoting_host'
              - 'nxservice'
    condition: selection and selection_tool
falsepositives:
    - Согласованное средство удаленного обслуживания поставщика (должно быть учтено и контролироваться)
level: high
---
title: Установлено средство удаленного доступа (Windows Installer)
id: 127b5ddf-d720-419b-8085-d3d3ce86bc78
status: test
description: Через Windows Installer (MsiInstaller 1033) установлен продукт удаленного доступа.
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.command-and-control
    - attack.t1219
fstec239: [УПД, ОПС]
logsource:
    product: windows
    service: application
detection:
    selection:
        Provider_Name: 'MsiInstaller'
        EventID: 1033
    keywords:
        - 'TeamViewer'
        - 'AnyDesk'
        - 'Radmin'
        - 'Remote Manipulator'
        - 'Remote Utilities'
        - 'LiteManager'
        - 'Ammyy'
        - 'AeroAdmin'
        - 'Splashtop'
        - 'ScreenConnect'
        - 'RustDesk'
        - 'NetSupport'
        - 'DameWare'
        - 'TightVNC'
        - 'UltraVNC'
        - 'RealVNC'
        - 'Chrome Remote Desktop'
        - 'LogMeIn'
        - 'NoMachine'
        - 'AnyViewer'
        - 'Getscreen'
    condition: selection and keywords
falsepositives:
    - Согласованное средство удаленного обслуживания поставщика (должно быть учтено и контролироваться)
level: high
---
title: Попытка подключения запрещенного устройства
id: 2a70fd04-4e5a-422e-aedc-f4d2e27a719a
status: test
description: Установка устройства запрещена групповой политикой (Security 6423). Кто-то пытался подключить запрещенное устройство (обычно съемный носитель).
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.initial-access
    - attack.t1091
fstec239: [ЗНИ]
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 6423
    condition: selection
falsepositives:
    - Подключение личных устройств без злого умысла (нарушение политики все равно фиксируется)
level: medium
---
title: Подключен съемный носитель (USB/WPD)
id: 5f9b2c30-3f6f-4557-9b57-0ac90c709ce0
status: test
description: Подключено запоминающее устройство USB или устройство WPD (телефон, плеер) — Kernel-PnP/Configuration 400/410. Сведения для контроля подключения машинных носителей; перечень устройств — на листе «Съемные_носители».
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.initial-access
    - attack.t1091
fstec239: [ЗНИ]
logsource:
    product: windows
    service: kernel-pnp-configuration
detection:
    selection:
        EventID:
            - 400
            - 410
        DeviceInstanceId|startswith:
            - 'USBSTOR\'
            - 'SWD\WPDBUSENUM\'
    condition: selection
falsepositives:
    - Учтенные носители, разрешенные регламентом
level: low
---
title: Подключен съемный носитель (диск USB/SD)
id: cd584316-249c-4cc2-8153-5573df3f4ed8
status: test
description: Подключен диск на шине USB, SD или MMC (Partition/Diagnostic 1006): производитель, модель и серийный номер — на листе «Съемные_носители».
author: EVTX Audit
date: 2026-10-08
tags:
    - attack.initial-access
    - attack.t1091
fstec239: [ЗНИ]
logsource:
    product: windows
    service: partition-diagnostic
detection:
    selection:
        EventID: 1006
        BusType:
            - 7
            - 12
            - 13
    condition: selection
falsepositives:
    - Учтенные носители, разрешенные регламентом
level: low
'@
$script:Engine=$null; $script:EngineType=$null; $script:EngineNote=''; $script:Sigma=$null; $script:SigmaAlertCount=0; $script:SigmaProblemsLogged=0
function Get-EngineType {
    if ($script:EngineType) { return $script:EngineType }
    $ns='EvtxAudit_'+(Hash-Text $script:EngineSource).Substring(0,16)
    $type=($ns+'.Engine') -as [type]
    if (-not $type) {
        $source=$script:EngineSource.Replace('__NS__',$ns)
        # Non-ASCII characters become \uXXXX escapes, so compilation does not depend
        # on the encoding of the compiler's temporary source file.
        $source=[regex]::Replace($source,'[^\x00-\x7F]',{ param($m) '\u{0:X4}' -f [int][char]$m.Value })
        # Add-Type compiles a debug build by default and the JIT then does not optimize it
        # (about 3x slower). Ask for an optimized build; fall back to the default build.
        try {
            if ($PSVersionTable.PSEdition -eq 'Core') { Add-Type -TypeDefinition $source -Language CSharp -IgnoreWarnings -CompilerOptions '/optimize+' -ErrorAction Stop }
            else {
                $parameters=New-Object System.CodeDom.Compiler.CompilerParameters
                $parameters.GenerateInMemory=$true; $parameters.CompilerOptions='/optimize+'; $parameters.WarningLevel=0
                [void]$parameters.ReferencedAssemblies.Add('System.dll')
                Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $parameters -IgnoreWarnings -ErrorAction Stop
            }
        } catch {
            if (($ns+'.Engine') -as [type]) { throw }
            Add-Type -TypeDefinition $source -Language CSharp -IgnoreWarnings -ErrorAction Stop
        }
        $type=($ns+'.Engine') -as [type]
        if (-not $type) { throw 'Тип Engine не найден после компиляции.' }
    }
    $script:EngineType=$type
    return $type
}
function New-AuditEngine([string]$RunPath) {
    $type=Get-EngineType
    $engine=New-Object ($type.FullName)
    $engine.IncludeNoise=[bool]$IncludeNoise; $engine.IncludeNetworkLogons=[bool]$IncludeNetworkLogons
    $engine.DeepScriptScan=[bool]$DeepScriptScan; $engine.IncludeProcessCreation=[bool]$IncludeProcessCreation
    $engine.IncludeAllAntivirusEvents=[bool]$IncludeAllAntivirusEvents; $engine.GenericErrors=[bool]$script:GenericErrors
    $engine.SkipCorrelation=[bool]$SkipCorrelation; $engine.KeepEvidence=[bool]$KeepTechnicalFiles
    $engine.MaxEventId=$MaxEventId; $engine.FailureThreshold=$FailureThreshold; $engine.WindowMinutes=$WindowMinutes
    $engine.SprayUserThreshold=$SprayUserThreshold; $engine.RowsPerCsv=$RowsPerCsv
    $engine.HasStart=[bool]$script:HasStart; $engine.HasEnd=[bool]$script:HasEnd; $engine.StartTicks=$script:StartTicks; $engine.EndTicks=$script:EndTicks
    $engine.Delimiter=[string]$Delimiter; $engine.RunPath=$RunPath; $engine.FindingHeaders=[string[]]$script:FindingHeaders
    $engine.ResultSuccess=$script:ResultSuccess; $engine.ResultFailure=$script:ResultFailure
    $engine.SetFieldSpecs([object[]]$script:FieldSpecs)
    foreach ($r in $script:RuleTable) { $engine.AddRule($r.Provider,[string]$r.Id,$r.Category,$r.Severity,$r.Title,$r.Note) }
    foreach ($k in $script:RuSeverityMap.Keys) { $engine.SetMap('Severity',$k,$script:RuSeverityMap[$k]) }
    foreach ($k in $script:RuAuditMap.Keys) { $engine.SetMap('Audit',$k,$script:RuAuditMap[$k]) }
    foreach ($k in $script:RuMessageMap.Keys) { $engine.SetMap('Message',$k,$script:RuMessageMap[$k]) }
    foreach ($k in $script:TriageInputKeys) { $engine.AddTriageKey($k) }
    foreach ($k in $script:RdpRelevant) { $engine.AddRdpKey($k) }
    return $engine
}
# Loads the embedded pack and -SigmaRulesPath files; returns the prepared SigmaEngine.
function New-SigmaEngine([string[]]$ExtraPaths) {
    $type=Get-EngineType
    $sigma=New-Object ($type.Namespace+'.SigmaEngine')
    $sigma.PriorityHigh=$script:P1; $sigma.PriorityMedium=$script:P2; $sigma.PriorityLow=$script:P3
    [void]$sigma.LoadText($script:SigmaPack,'Встроенный пакет EVTX Audit')
    # A missing or unreadable rule path is reported; the embedded pack is still used.
    foreach ($path in @($ExtraPaths | Where-Object { $_ })) {
        try {
            $item=Get-Item -LiteralPath $path -ErrorAction Stop
            $files=@($item)
            if ($item.PSIsContainer) { $files=@(Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Include '*.yml','*.yaml' -ErrorAction Stop | Sort-Object FullName) }
            foreach ($f in $files) {
                try { [void]$sigma.LoadText([IO.File]::ReadAllText($f.FullName,[Text.Encoding]::UTF8),$f.FullName) }
                catch { $sigma.Problems.Add($f.FullName+': файл не прочитан: '+$_.Exception.Message) }
            }
        } catch { $sigma.Problems.Add($path+': путь к правилам Sigma недоступен: '+$_.Exception.Message) }
    }
    $sigma.Prepare()
    return $sigma
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
            [pscustomobject]@{Label='Режим обработки';Value=$(if($run.EngineMode -eq 'C#'){'C# (скомпилированное ядро)'}else{'PowerShell (совместимый, без Sigma)'})},
            [pscustomobject]@{Label='Примечание к режиму';Value=$run.EngineNote},
            [pscustomobject]@{Label='Правил Sigma загружено';Value=$run.SigmaRules},
            [pscustomobject]@{Label='Корреляций Sigma';Value=$run.SigmaCorrelations},
            [pscustomobject]@{Label='Правил Sigma пропущено (неподдерживаемые)';Value=$run.SigmaSkipped},
            [pscustomobject]@{Label='Срабатываний Sigma';Value=$run.SigmaAlerts},
            [pscustomobject]@{Label='Дополнительные правила Sigma';Value=$run.Parameters.SigmaRulesPath},
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
            [pscustomobject]@{Label='HashFiles';Value=$run.Parameters.HashFiles},
            [pscustomobject]@{Label='Окно цепочек, мин';Value=$run.Parameters.TriageWindowMinutes},
            [pscustomobject]@{Label='Объединение в КИ, ч';Value=$run.Parameters.IncidentGapHours},
            [pscustomobject]@{Label='NoSigma';Value=$run.Parameters.NoSigma},
            [pscustomobject]@{Label='NoCompiledEngine';Value=$run.Parameters.NoCompiledEngine}
        )
        foreach ($pair in $pairs) { Write-Row $w @($pair.Label,$pair.Value) }
    } finally { Close-Writer $w }
    return $path
}
# Excel layout: sheet order, numeric columns, widths, wrapping, hidden technical
# columns and priority colors. Kept separate from COM so SelfTest can check it.
$script:NumericHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Оценка риска','Связанных уникальных событий','Сценариев','Количество','Событий в окне','Разных УЗ',
    'Сеансов (пар)','Суммарная длительность, сек','Длительность, сек','Номер','Находок','Прочитано подходящих событий','Ошибок разбора','Нет описания Windows','Размер, байт','Время обработки, сек',
    'КИ P1','КИ P2','Срабатываний Sigma','Правил Sigma','Успешных входов','Неудачных входов','RDP-сеансов','Съемных носителей','Изменений ПО','Изменений УЗ','Очисток журналов','Аварийных перезагрузок',
    'Глубина Security, дней','Событий','Компьютеров','Подключений (оценка)','Емкость, ГБ'))
$script:WideHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Хронология','Основание связи','Почему выделено','Что проверить','УЗ / объект / IP','Ссылки на находки и EVTX (до 10)',
    'Комментарий','Что это означает / что запросить','Что делать','Ограничения','Ошибка','Этапы (тактики)','Данные события','Описание Windows','Командная строка',
    'Цепочка событий','Ссылки на события','Описание','Ложные срабатывания','Главные сценарии','Замечания','Путь / параметры','Изменение / детали','Риск / примечание'))
$script:MediumHeaders=[Collections.Generic.HashSet[string]]::new([string[]]@('Сценарий','Тактика','MITRE ATT&CK','Учетные записи','IP источника','IP источников','Компьютер','Событие','Категория',
    'Цепочка атаки','Инициатор','Целевая УЗ','Учетная запись','Файл источника','Папка источника','Полный путь','Процесс','Имя угрозы','Ресурс / путь',
    'Правило','Группировка','Устройство','Продукт / служба / обновление','Меры ФСТЭК №239 (группы)','Внешние IP (успешные входы, RDP)','Средства удаленного доступа','Компьютеры',
    'Вероятные пользователи','Вероятный пользователь (активный вход)','Журналы (каналы)','Папки источника','Источник (IP / станция)','Расшифровка кодов',
    'Описание типа','Идентификатор устройства','Действие','Примечание','Группа','Источник правила'))
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
    # Freeze: columns kept visible when scrolling right (-1 = by kind).
    $add={ param([string]$Name,[string]$Path,[string]$Kind,[int]$Freeze=-1)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $headers=@(Read-CsvHeader $Path)
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
        if ($Freeze -lt 0) { $Freeze=0; if ($Kind -eq 'Priority') { $Freeze=3 } }
        $plan.Add([pscustomobject]@{Name=$Name;Path=$Path;Kind=$Kind;Headers=$headers;Types=$types.ToArray();Widths=$widths.ToArray();Wrap=$wrap.ToArray();Hidden=$hidden.ToArray();PriorityColumn=$priority;Freeze=$Freeze})
    }
    & $add 'Хосты' (Join-Path $WorkPath 'Hosts.csv') 'Priority' 1
    & $add 'Инциденты' (Join-Path $WorkPath 'Incidents.csv') 'Priority'
    & $add 'Приоритетные' (Join-Path $WorkPath 'Triage.csv') 'Priority'
    & $add 'Sigma' (Join-Path $WorkPath 'SigmaAlerts.csv') 'Priority' 5
    & $add 'Подбор_пароля' (Join-Path $WorkPath 'AuthBursts.csv') 'Severity'
    & $add 'Входы' (Join-Path $WorkPath 'LogonSummary.csv') 'Plain' 3
    & $add 'RDP_итоги' (Join-Path $WorkPath 'RdpTotals.csv') 'Plain'
    & $add 'RDP_сеансы' (Join-Path $WorkPath 'RdpIntervals.csv') 'Plain'
    & $add 'Съемные_носители' (Join-Path $WorkPath 'UsbDevices.csv') 'Plain' 2
    & $add 'Носители_события' (Join-Path $WorkPath 'UsbEvents.csv') 'Plain' 3
    & $add 'Изменения_ПО' (Join-Path $WorkPath 'SoftwareChanges.csv') 'Plain' 3
    & $add 'Учетные_записи' (Join-Path $WorkPath 'AccountChanges.csv') 'Plain' 3
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
                    elseif ($item.Name -eq 'Хосты') { $sheet.Tab.Color=12611584 } elseif ($item.Name -eq 'Sigma') { $sheet.Tab.Color=10498160 }
                } catch { }
                try {
                    $sheet.Activate()
                    $excel.ActiveWindow.SplitColumn=$item.Freeze
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
        $hostPath=Join-Path $WorkPath 'Hosts.csv'
        if (Test-Path -LiteralPath $hostPath) {
            foreach ($r in (Import-Csv -LiteralPath $hostPath -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Хост','',$r.'Приоритет',('Оценка '+$r.'Оценка риска'+'; КИ P1: '+$r.'КИ P1'+'; P2: '+$r.'КИ P2'+'; Sigma: '+$r.'Срабатываний Sigma'),$r.'Компьютер',$r.'Период событий с (UTC)',$r.'Период событий по (UTC)','',$r.'Внешние IP (успешные входы, RDP)','',$r.'Изменений ПО','',$r.'Папки источника',($r.'Главные сценарии'+' | '+$r.'Замечания'))
            }
        }
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
        $sigmaPath=Join-Path $WorkPath 'SigmaAlerts.csv'
        if (Test-Path -LiteralPath $sigmaPath) {
            foreach ($r in (Import-Csv -LiteralPath $sigmaPath -Delimiter $Delimiter -Encoding UTF8)) {
                Write-Row $w @('Sigma',$r.'Event ID',$r.'Приоритет',($r.'Правило'+' ['+$r.'Оценка риска'+'; '+$r.'MITRE ATT&CK'+']'),$r.'Компьютер',$r.'Первое время UTC',$r.'Последнее время UTC',$r.'Учетные записи',$r.'IP источника','',$r.'Событий',$r.'Тип',$r.'Папка источника',($r.'Цепочка событий'+' | '+$r.'Ссылки на события'))
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
    'Очистка журнала|90|Сокрытие следов|T1070.001 Clear Windows Event Logs|Очистка уничтожает предшествующие события; одна из типовых операций после компрометации.|АУД',
    'Потеря или переполнение журналирования|55|Сокрытие следов|T1562.002 Disable Windows Event Logging|Часть событий не записана; интервал неполноты нужно учитывать при расследовании.|АУД',
    'Журналирование остановлено без перезагрузки|75|Сокрытие следов|T1562.002 Disable Windows Event Logging|Служба журнала остановлена, а система продолжила работу: так отключают запись событий.|АУД',
    'Добавление в привилегированную группу|85|Повышение привилегий|T1098 Account Manipulation|Членство в административной группе дает полный контроль над системой или доменом.|УПД',
    'Выдан удаленный доступ (группа RDP/WinRM)|60|Закрепление|T1098 Account Manipulation|Добавление в Remote Desktop/Remote Management Users открывает удаленный вход.|УПД',
    'Изменение механизма аудита или политики безопасности|70|Обход защиты|T1562.002 Disable Windows Event Logging|Изменение аудита может скрыть последующие действия.|АУД',
    'Изменение политики аудита|65|Обход защиты|T1562.002 Disable Windows Event Logging|Отключение категорий аудита скрывает последующие действия.|АУД',
    'Служба удаленного выполнения (PsExec/Impacket)|95|Выполнение / боковое перемещение|T1569.002 Service Execution; T1021.002 SMB/Admin Shares|Служба запускает командный интерпретатор или пишет в административный общий ресурс — типичный след PsExec, Impacket smbexec/psexec, Cobalt Strike.|ОПС, УПД',
    'Служба с нетипичными параметрами|65|Закрепление|T1543.003 Windows Service|Служба из нестандартного пути или с нетипичными параметрами — частый способ закрепления.|ОПС',
    'Задание с рискованной командой|75|Закрепление / выполнение|T1053.005 Scheduled Task|Задание запускает интерпретатор или закодированную команду.|ОПС',
    'Изменение SID History|90|Повышение привилегий|T1134.005 SID-History Injection|SID History позволяет получить права другой УЗ, в том числе администратора домена.|УПД',
    'Назначено опасное право пользователя|70|Повышение привилегий|T1134 Access Token Manipulation|Право позволяет обойти контроль доступа (отладка, резервное копирование, загрузка драйверов и т.п.).|УПД',
    'Выдано право входа по RDP|60|Закрепление|T1098 Account Manipulation|Право SeRemoteInteractiveLogonRight разрешает вход по RDP.|УПД',
    'Обнаружение угрозы Defender|75|Вредоносное ПО|T1204 User Execution|Defender обнаружил вредоносный объект; нужно убедиться, что угроза устранена и не запускалась.|АВЗ',
    'Ошибка устранения угрозы Defender|90|Вредоносное ПО|T1204 User Execution|Угроза обнаружена, но не устранена — объект может оставаться активным.|АВЗ',
    'Отключение компонентов защиты Defender|85|Обход защиты|T1562.001 Disable or Modify Tools|Отключение защиты в реальном времени — типовой шаг перед запуском ВПО.|АВЗ',
    'Добавлено исключение Defender|85|Обход защиты|T1562.001 Disable or Modify Tools|Исключение позволяет хранить и запускать ВПО без проверки.|АВЗ',
    'Попытка изменить Defender заблокирована|70|Обход защиты|T1562.001 Disable or Modify Tools|Tamper Protection остановила изменение настроек: кто-то пытался ослабить защиту.|АВЗ',
    'ASR заблокировал операцию|65|Выполнение|T1204 User Execution|Правило Attack Surface Reduction остановило подозрительное действие процесса.|АВЗ, ОПС',
    'Отключение службы защиты или журналирования|85|Обход защиты|T1562.001 Disable or Modify Tools|Служба защиты или журналирования переведена в состояние «Отключена».|АВЗ, АУД',
    'Аварийная остановка службы защиты или журналирования|55|Обход защиты|T1562.001 Disable or Modify Tools|Неожиданная остановка службы защиты может быть сбоем или принудительным завершением.|АВЗ, АУД',
    'Sysmon: вмешательство в процесс|90|Обход защиты|T1055 Process Injection|Подмена образа процесса (Process Hollowing/Herpaderping) характерна для ВПО.|АУД',
    'Изменение конфигурации Sysmon|60|Обход защиты|T1562.001 Disable or Modify Tools|Изменение фильтров Sysmon может скрыть активность.|АУД',
    'Сторонний антивирус: признаки угрозы|70|Вредоносное ПО|T1204 User Execution|Продукт защиты сообщил об угрозе.|АВЗ',
    'Значительное изменение времени пользователем|60|Сокрытие следов|T1070.006 Timestomp|Перевод часов искажает хронологию событий.|АУД',
    'Потенциально опасная команда|75|Выполнение|T1059 Command and Scripting Interpreter|Команда удаляет следы, ослабляет защиту или загружает и исполняет код.|ОПС',
    'RDP-вход с внешнего IP|70|Первоначальный доступ|T1133 External Remote Services; T1021.001 Remote Desktop Protocol|Успешный RDP-вход с публичного адреса: RDP опубликован в интернет или используется внешний доступ.|УПД',
    'Подбор пароля к УЗ|55|Доступ к учетным данным|T1110.001 Password Guessing|Серия отказов для одной УЗ с одного источника; бывает и из-за сохраненного старого пароля.|ИАФ, УПД',
    'Password spraying с одного источника|80|Доступ к учетным данным|T1110.003 Password Spraying|Отказы для многих разных УЗ с одного источника — признак перебора паролей.|ИАФ, УПД',
    'Массовая блокировка УЗ|80|Доступ к учетным данным|T1110.003 Password Spraying|Много разных УЗ заблокировано за короткое время — признак перебора паролей.|ИАФ, УПД',
    'Отказы RDP с неверным паролем → успешный вход|95|Первоначальный доступ|T1110 Brute Force → T1021.001 Remote Desktop Protocol|После серии неверных паролей с того же IP выполнен успешный RDP-вход — возможный успешный подбор.|ИАФ, УПД',
    'Новая УЗ получила привилегии|90|Закрепление / повышение привилегий|T1136.001 Create Local Account → T1098 Account Manipulation|Только что созданная УЗ сразу получила административные права.|УПД',
    'Новая УЗ → RDP-вход|85|Закрепление|T1136 Create Account → T1021.001 Remote Desktop Protocol|Только что созданная УЗ сразу использована для RDP-входа.|УПД',
    'Включение/сброс УЗ → RDP-вход|85|Закрепление / боковое перемещение|T1098 Account Manipulation → T1021.001 Remote Desktop Protocol|УЗ включена или ей сброшен пароль, после чего под ней сразу выполнен RDP-вход.|УПД, ИАФ',
    'Временная УЗ: создана и удалена|80|Закрепление / сокрытие следов|T1136 Create Account; T1070 Indicator Removal|УЗ существовала недолго — типично для временной УЗ злоумышленника.|УПД',
    'Изменение аудита → потеря/очистка журналирования|95|Сокрытие следов|T1562.002 → T1070.001|Та же сессия изменила аудит и затем очистила или потеряла журнал.|АУД',
    'Обнаружение угрозы → отключение защиты|95|Обход защиты|T1562.001 Disable or Modify Tools|После обнаружения угрозы защита на том же компьютере ослаблена.|АВЗ',
    'Локально добавлено правило Firewall|40|Обход защиты|T1562.004 Disable or Modify System Firewall|Новое правило может открыть порт; часто создается установщиками ПО.|ЗИС',
    'Ослаблены параметры безопасности УЗ|70|Закрепление / доступ к учетным данным|T1098 Account Manipulation; T1558.004 AS-REP Roasting|Флаги UserAccountControl ослабляют аутентификацию: пароль не обязателен, нет предварительной аутентификации Kerberos, обратимое шифрование, делегирование.|ИАФ, УПД'
)) {
    $p=$line.Split('|')
    $script:ScenarioCatalog[$p[0]]=[pscustomobject]@{Score=[int]$p[1];Tactic=$p[2];Mitre=$p[3];Why=$p[4];Fstec=$p[5]}
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
        [long]$EventCount=0,
        [string]$Fstec='',
        [string]$RuleSource='',
        [string[]]$ExtraRefs=@(),
        [string[]]$ExtraIps=@(),
        [string[]]$ExtraIds=@()
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
        if (-not $Fstec) { $Fstec=$catalog.Fstec }
    }
    if (-not $Fstec -and $Scenario.StartsWith('RDP-сеанс: ')) { $Fstec='УПД' }
    if (-not $RuleSource) { $RuleSource='Эвристика EVTX Audit' }
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
            Recovered=$false; EventCount=[long]0; Incident=''; Fstec=$Fstec; Source=$RuleSource
        }
    }
    $g=$Groups[$key]
    foreach ($ref in $ExtraRefs) { if ($ref -and $g.Refs.Count -lt 10 -and -not $g.Refs.Contains($ref)) { $g.Refs.Add($ref) } }
    foreach ($ip in $ExtraIps) { $ip=Triage-NormalIp $ip; if ((Triage-IsRemoteIp $ip) -and $g.Ips.Count -lt 10 -and -not $g.Ips.Contains($ip)) { $g.Ips.Add($ip) } }
    foreach ($id in $ExtraIds) { if ($id) { [void]$g.Ids.Add($id.Trim()) } }
    if ($Score -gt $g.Score) { $g.Score=$Score; $g.Priority=$Priority }
    $g.EventCount+=$EventCount
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if (-not $g.Seen.Add((Triage-Key $r))) { continue }
        $time=Triage-Value $r 'Время UTC'
        if (-not $g.First -or [string]::CompareOrdinal($time,$g.First) -lt 0) { $g.First=$time }
        if (-not $g.Last -or [string]::CompareOrdinal($time,$g.Last) -gt 0) { $g.Last=$time }
        [void]$g.Ids.Add((Triage-Value $r 'Event ID'))
        if ($g.Refs.Count -lt 10 -and (Triage-Value $r 'Полный путь')) { [void]$g.Refs.Add(('Находка '+(Triage-Value $r 'Номер')+'; '+(Triage-Value $r 'Полный путь')+'; Record ID='+(Triage-Value $r 'Record ID'))) }
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
    if ($security -and $id -eq 4738) {
        $weak=Get-UacChange $r $true
        if ($weak) {
            Add-Triage -Groups $Groups -Priority $script:P2 -Scenario 'Ослаблены параметры безопасности УЗ' -Evidence ('Факт: в UserAccountControl установлены флаги: '+$weak+'.') -Why '' -Check 'Проверить, кто и зачем изменил УЗ. Без предварительной аутентификации Kerberos хеш пароля подбирается офлайн (AS-REP Roasting); «пароль не обязателен» допускает пустой пароль; делегирование позволяет действовать от имени других УЗ.' -Object ($target+' | '+(Triage-Value $r 'SID целевой УЗ')) -Rows @($r)
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
        Write-Row $w @('Папка источника','Компьютеры','Security','Глубина Security, дней','System','PowerShell Operational','Defender Operational','RDP Operational','Sysmon Operational','Журналы носителей (Kernel-PnP, Partition)','Файлы с неполной обработкой','Что это означает / что запросить')
        foreach ($folder in ($groups.Keys | Sort-Object)) {
            $g=$groups[$folder]; $names=@($g.Files | ForEach-Object { [IO.Path]::GetFileName($_.'Полный путь').ToLowerInvariant() })
            $check={ param([string]$Pattern) if (@($names | Where-Object { $_ -like $Pattern }).Count -gt 0) {'Передан'} else {'Не передан'} }
            $security=& $check 'security.evtx'; $system=& $check 'system.evtx'
            $ps=& $check 'microsoft-windows-powershell%4operational.evtx'; $defender=& $check 'microsoft-windows-windows defender%4operational.evtx'
            $rdp=if ((& $check 'microsoft-windows-terminalservices-localSessionmanager%4operational.evtx') -eq 'Передан' -or (& $check 'microsoft-windows-terminalservices-remoteconnectionmanager%4operational.evtx') -eq 'Передан') {'Передан хотя бы один'} else {'Не передан'}
            $sysmon=& $check 'microsoft-windows-sysmon%4operational.evtx'
            $media=@()
            if ((& $check 'microsoft-windows-kernel-pnp%4configuration.evtx') -eq 'Передан') { $media+='Kernel-PnP' }
            if ((& $check 'microsoft-windows-partition%4diagnostic.evtx') -eq 'Передан') { $media+='Partition' }
            $mediaText='Не передан'; if ($media.Count -gt 0) { $mediaText='Передан: '+($media -join ', ') }
            # Security depth: first and last record of Security.evtx (not min/max when the clock moved).
            $securityDays=''
            foreach ($f in $g.Files) {
                if ([IO.Path]::GetFileName([string]$f.'Полный путь') -ine 'security.evtx' -or -not $f.'Время первой записи UTC' -or -not $f.'Время последней записи UTC') { continue }
                try {
                    $days=((Get-IsoTicks $f.'Время последней записи UTC')-(Get-IsoTicks $f.'Время первой записи UTC'))/[double][TimeSpan]::TicksPerDay
                    if ($days -ge 0) { $securityDays=[Math]::Round($days,1).ToString('0.#',$script:Invariant) }
                } catch { }
            }
            $note='Это полнота переданной выгрузки, а не доказательство включения/выключения аудита. Запросить auditpol /get /category:* /r, размеры/retention журналов и сведения о централизованном сборе.'
            if ($security -eq 'Не передан') { $note+=' Security.evtx отсутствует в этой папке: выводы об аутентификации и УЗ ограничены.' }
            elseif ($securityDays -ne '' -and [double]::Parse($securityDays,$script:Invariant) -lt 30) { $note+=' Журнал Security охватывает только '+$securityDays+' дн.: более ранние события недоступны; проверить максимальный размер журнала (wevtutil gl security) и наличие централизованной копии.' }
            if ($mediaText -eq 'Не передан') { $note+=' Журналы Kernel-PnP/Configuration и Partition/Diagnostic не переданы: подключения носителей видны только при включенном аудите PnP (Security 6416).' }
            if ($system -eq 'Не передан') { $note+=' System.evtx отсутствует: ограничены выводы о времени, службах и сбоях.' }
            if ($g.Bad.Count -gt 0) { $note+=' Есть неполная обработка: '+($g.Bad -join '; ')+'.' }
            Write-Row $w @($folder,(@($g.Computers) -join ' | '),$security,$securityDays,$system,$ps,$defender,$rdp,$sysmon,$mediaText,($g.Bad -join ' | '),$note)
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
            # Clustering uses first occurrences: a row whose repeats span weeks (merged
            # recurring logons, media) does not glue later, unrelated activity to it.
            if ($null -eq $current -or $first -gt ($current.AnchorTicks+$gapTicks)) {
                $current=[pscustomobject]@{Id='';Groups=(New-Object 'System.Collections.Generic.List[object]');FirstTicks=$first;LastTicks=$last;AnchorTicks=$first;First=$g.First;Last=$g.Last;Computer=$g.Computer;Scope=$g.Scope;Score=0;Priority=$script:P3;Chain=$false}
                $incidents.Add($current)
            }
            $current.Groups.Add($g)
            if ($first -gt $current.AnchorTicks) { $current.AnchorTicks=$first }
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
        Write-Row $w @('КИ','Приоритет','Оценка риска','Компьютер','Начало UTC','Конец UTC','Начало (местное)','Длительность','Сценариев','Цепочка атаки','Этапы (тактики)','Хронология','Учетные записи','IP источников','Event ID','Меры ФСТЭК №239 (группы)','Правил Sigma','Папка источника','Что делать')
        foreach ($inc in $Incidents) {
            $ordered=@($inc.Groups | Sort-Object @{Expression={Get-IsoTicks $_.First}},Scenario)
            $timeline=New-Object 'System.Collections.Generic.List[string]'
            $tactics=New-Object 'System.Collections.Generic.List[string]'
            $accounts=New-Object 'System.Collections.Generic.List[string]'; $ips=New-Object 'System.Collections.Generic.List[string]'
            $ids=New-Object 'System.Collections.Generic.HashSet[string]'
            $fstec=New-Object 'System.Collections.Generic.List[string]'; $sigmaRules=0
            foreach ($g in $ordered) {
                foreach ($m in ([string]$g.Fstec -split ',\s*')) { if ($m -and -not $fstec.Contains($m)) { $fstec.Add($m) } }
                if ([string]$g.Source -like 'Sigma*') { $sigmaRules++ }
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
                ((@($ids) | Sort-Object {[int]$_}) -join ', '),(($fstec.ToArray() | Sort-Object) -join ', '),$sigmaRules,$inc.Scope,$todo)
        }
    } finally { Close-Writer $w }
}
function Write-TriageReport([string]$WorkPath,$Groups,[int]$ScopeCount,[int]$BlockedCount,[int]$RowFailures,[int]$ChainFailures,[string]$BuildNote) {
    # Writing the report is isolated from correlation.  Thus a malformed
    # individual record can never remove the entire "Приоритетные" sheet.
    $incidents=@()
    try { $incidents=Build-Incidents $Groups; Write-IncidentReport $WorkPath $incidents; $script:TriageIncidents=$incidents }
    catch { Log-Issue 'Triage' $WorkPath '' ('Не сформирован лист Инциденты: '+(Get-TriageErrorText $_)) }
    $w=New-Writer (Join-Path $WorkPath 'Triage.csv')
    try {
        Write-Row $w @('КИ','Приоритет','Оценка риска','Первое время UTC','Последнее время UTC','Первое время (местное)','Компьютер','Сценарий','Тактика','MITRE ATT&CK','Источник правила','Меры ФСТЭК №239 (группы)','Учетные записи','IP источника','УЗ / объект / IP','Основание связи','Почему выделено','Что проверить','Event ID','Связанных уникальных событий','Ссылки на находки и EVTX (до 10)','Папка источника','Ограничения')
        foreach ($g in (@($Groups.Values) | Sort-Object @{Expression={$_.Score};Descending=$true},@{Expression={$_.Incident}},@{Expression={$_.First}},Scenario)) {
            $note='Кандидат для проверки, не подтвержденный инцидент. Повторы объединены; диапазон времени не является длительностью атаки.'
            if ($g.Recovered) { $note+=' Есть восстановленный XML: перепроверить исходную запись.' }
            $ids=@($g.Ids | Sort-Object {[int]$_}) -join ', '
            $count=[long]$g.Seen.Count; if ($g.EventCount -gt $count) { $count=$g.EventCount }
            Write-Row $w @($g.Incident,$g.Priority,$g.Score,(Format-UtcText $g.First),(Format-UtcText $g.Last),(Format-LocalText $g.First),$g.Computer,$g.Scenario,$g.Tactic,$g.Mitre,$g.Source,$g.Fstec,
                ($g.Accounts.ToArray() -join ' | '),($g.Ips.ToArray() -join ' | '),$g.Object,$g.Evidence,$g.Why,$g.Check,$ids,$count,($g.Refs.ToArray() -join ' || '),$g.Scope,$note)
        }
        $limits=New-Object 'System.Collections.Generic.List[string]'
        if ($RowFailures -gt 0) { [void]$limits.Add('Строк с ошибкой приоритизации: '+$RowFailures+'. Они перечислены на листе Ошибки (этап «Приоритизация: строка»).') }
        if ($ChainFailures -gt 0) { [void]$limits.Add('Областей со сбойной связкой: '+$ChainFailures+'. Остальные области обработаны.') }
        if ($BuildNote) { [void]$limits.Add($BuildNote) }
        if ($limits.Count -gt 0) {
            Write-Row $w @('','Справка','','','','','','Приоритизация выполнена с ограничениями','','','','','','','',($limits.ToArray() -join ' '),'Это не отменяет уже сформированные строки; проверить лист Ошибки и исходный EVTX.','После устранения причины повторить запуск на неизменяемой копии.','','','','',$null)
        }
        Write-Row $w @('','Справка','','','','','','Границы анализа','','','','','','','','Связки не строятся через ошибки чтения, восстановленный XML, изменение времени/загрузку ОС и между разными папками либо компьютерами.','Оценка риска: P1 ≥ 80, P2 ≥ 50, P3 — к сведению. Строки «Sigma: …» — срабатывания правил и корреляций Sigma (лист Sigma). Одиночные отказы входа и обычные системные ошибки сюда не включаются.','Также просмотреть листы Хосты, Инциденты, Sigma, Подбор_пароля, Съемные_носители и Качество_выгрузки.','','','','',('Областей с кандидатами цепочек: '+$ScopeCount+'; областей с запретом цепочек: '+$BlockedCount+'. Окно цепочек: '+$TriageWindowMinutes+' мин.; окно отказов: '+$WindowMinutes+' мин.; объединение в КИ: '+$IncidentGapHours+' ч.'))
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
# Sigma alerts (single rules and correlations) become priority rows. Variants of one rule
# for different logs ("… (Kernel-PnP)", "… (Partition)", "… (служба)") share one row.
$script:SigmaVariantRx=New-Object Text.RegularExpressions.Regex('\s*\((Kernel-PnP|Partition|Security \d+|служба(, Security \d+)?|Windows Installer|USB/WPD|диск USB/SD)\)$')
function Add-SigmaTriage($Groups,[string]$WorkPath) {
    $path=Join-Path $WorkPath 'SigmaAlerts.csv'
    if (-not (Test-Path -LiteralPath $path)) { return }
    $n=0
    foreach ($a in (Import-Csv -LiteralPath $path -Delimiter $Delimiter -Encoding UTF8)) {
        $n++
        # Informational rules (hunting, context) stay on the Sigma sheet only.
        if ([string]$a.'Уровень Sigma' -eq 'informational') { continue }
        $first=Convert-UtcDisplayToIso $a.'Первое время UTC'
        $last=Convert-UtcDisplayToIso $a.'Последнее время UTC'
        $ids=@(([string]$a.'Event ID') -split ',\s*' | Where-Object { $_ })
        $ips=@(([string]$a.'IP источника') -split ' \| ' | Where-Object { $_ })
        $row=[pscustomobject]@{'Номер'='';'Event ID'=$(if($ids.Count){$ids[0]}else{'0'});'Record ID'='';'Время UTC'=$first;'Папка источника'=$a.'Папка источника';
            'Полный путь'='';'Компьютер'=$a.'Компьютер';'Целевая УЗ'=$a.'Учетные записи';'IP источника'=$(if($ips.Count){$ips[0]}else{''});
            'SHA256 XML события'=('sigma|'+$n);'Восстановление XML'=''}
        $type=[string]$a.'Тип'
        $evidence=$a.'Цепочка событий'+'. Правило Sigma '+$a.'ID правила'+' ('+$type+').'
        if ($a.'Группировка') { $evidence+=' Группировка: '+$a.'Группировка'+'.' }
        $check='Проверить события по ссылкам в исходном EVTX и контекст на листах Инциденты и Находки.'
        if ($a.'Ложные срабатывания') { $check+=' Возможные ложные срабатывания: '+$a.'Ложные срабатывания'+'.' }
        $object=[string]$a.'Группировка'
        $source='Sigma: '+$a.'Источник правила'
        $scenario='Sigma: '+$script:SigmaVariantRx.Replace([string]$a.'Правило','')
        Add-Triage -Groups $Groups -Priority $a.'Приоритет' -Scenario $scenario -Evidence $evidence -Why ([string]$a.'Описание') -Check $check -Object $object -Rows @($row) `
            -Score ([int]$a.'Оценка риска') -Tactic ([string]$a.'Тактика') -Mitre ([string]$a.'MITRE ATT&CK') -LastTime $last -EventCount ([long]$a.'Событий') -Fstec ([string]$a.'Меры ФСТЭК №239 (группы)') `
            -RuleSource ('Sigma '+$a.'ID правила') -ExtraRefs @(([string]$a.'Ссылки на события') -split ' \|\| ') -ExtraIps $ips -ExtraIds $ids
    }
}
function Convert-UtcDisplayToIso([string]$Text) {
    if (-not $Text) { return '' }
    $styles=[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    return [DateTime]::ParseExact($Text,'yyyy-MM-dd HH:mm:ss',$script:Invariant,$styles).ToString('o',$script:Invariant)
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
foreach ($i in @(4616,4624,4697,4698,4702,4704,4715,4717,4719,4728,4738,4732,4739,4756,4765,4766,4904,4905,4906,4907,4946)) { [void]$script:SingleTriageKeys.Add('Microsoft-Windows-Security-Auditing|'+$i) }
foreach ($i in @(1006,1008,1015,1116,1118,1119,1121,5001,5007,5010,5012,5013)) { [void]$script:SingleTriageKeys.Add('Microsoft-Windows-Windows Defender|'+$i) }
# Everything the priority layer and the account / media / software / host sheets read.
$script:TriageInputKeys=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($k in $script:SingleTriageKeys) { [void]$script:TriageInputKeys.Add($k) }
foreach ($i in @(4608,4616,4624,4625,4634,4647,4648,4697,4698,4699,4702,4704,4715,4717,4719,4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,
    4738,4739,4740,4741,4743,4756,4757,4765,4766,4767,4781,4904,4905,4906,4907,4946,4947,4948,4950,4954,4964,6416,6419,6420,6421,6422,6423,6424)) {
    [void]$script:TriageInputKeys.Add('Microsoft-Windows-Security-Auditing|'+$i)
}
foreach ($k in @('Microsoft-Windows-Eventlog|104','Microsoft-Windows-Eventlog|1100','Microsoft-Windows-Eventlog|1101','Microsoft-Windows-Eventlog|1102',
    'Microsoft-Windows-Eventlog|1104','Microsoft-Windows-Eventlog|1108','EventLog|6005','EventLog|6006','EventLog|6008','Microsoft-Windows-Kernel-Power|41',
    'User32|1074','Microsoft-Windows-Kernel-General|1','Microsoft-Windows-Kernel-General|24','Microsoft-Windows-Windows Defender|1007','Microsoft-Windows-Windows Defender|1117',
    'Microsoft-Windows-Kernel-PnP|400','Microsoft-Windows-Kernel-PnP|410','Microsoft-Windows-Partition|1006','Microsoft-Windows-UserPnp|20001','Microsoft-Windows-UserPnp|20003',
    'MsiInstaller|1033','MsiInstaller|1034','MsiInstaller|1035','MsiInstaller|1022','Microsoft-Windows-WindowsUpdateClient|19','Microsoft-Windows-WindowsUpdateClient|20',
    'Microsoft-Windows-TaskScheduler|141','Microsoft-Windows-Sysmon|19','Microsoft-Windows-Sysmon|20','Microsoft-Windows-Sysmon|21')) { [void]$script:TriageInputKeys.Add($k) }
$script:TriageRows=$null; $script:TriageRowsPath=''; $script:TriageGroups=@{}; $script:TriageIncidents=@()
$script:TriageColumns=@('Номер','Event ID','Record ID','Время UTC','Папка источника','Полный путь','Компьютер','Провайдер','Результат аудита','SID целевой УЗ','SID участника','SID инициатора','Logon ID цели','Logon ID инициатора','Тип входа','Целевая УЗ','IP источника','Status','SubStatus','Данные события','Командная строка','Процесс','SHA256 XML события','Восстановление XML','Инициатор','Имя угрозы')
function Build-Triage([string]$WorkPath) {
    $script:TriageIncomplete=$false
    $script:TriageHasErrors=$false
    $groups=@{}; $scopes=@{}; $blocked=@{}; $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    $sourceScopes=@{}; $candidateCount=0; $limit=100000; $limitWarned=$false; $rowFailures=0; $chainFailures=0; $buildNote=''
    $script:TriageRows=New-Object 'System.Collections.Generic.List[object]'; $script:TriageRowsPath=$WorkPath
    # TriageInput.csv holds only the rows this layer needs; older runs and tests use the findings.
    $inputFiles=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'TriageInput.csv' -File)
    if ($inputFiles.Count -eq 0) { $inputFiles=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'Findings-*.csv' -File | Sort-Object Name) }
    try {
        foreach ($file in $inputFiles) {
            Import-Csv -LiteralPath $file.FullName -Delimiter $Delimiter -Encoding UTF8 | ForEach-Object {
                $r=$_
                $script:TriageRows.Add($r)
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
    try { Add-SigmaTriage $groups $WorkPath }
    catch {
        $script:TriageIncomplete=$true; $script:TriageHasErrors=$true
        $errorText=Get-TriageErrorText $_
        if ($buildNote) { $buildNote+=' | ' }
        $buildNote+='Не удалось перенести срабатывания Sigma: '+$errorText
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
    $script:TriageGroups=$groups
    Write-TriageReport $WorkPath $groups $scopes.Count $blocked.Count $rowFailures $chainFailures $buildNote
}

# ============================================================== v10 audit sheets
# Хосты, Входы, Съемные_носители, Носители_события, Изменения_ПО, Учетные_записи.
# Built from TriageInput rows and in-memory results; findings are not read again.
$script:LogonTypeText=@{'2'='Интерактивный (консоль)';'3'='Сетевой (SMB, WinRM, RPC и др.)';'4'='Пакетный (планировщик)';'5'='Служба';'7'='Разблокировка';
    '8'='Сетевой, пароль в открытом виде';'9'='Новые учетные данные (runas /netonly)';'10'='Удаленный интерактивный (RDP)';'11'='Кэшированные учетные данные';
    '12'='Кэшированный удаленный интерактивный';'13'='Кэшированная разблокировка';'Kerberos'='Предварительная аутентификация Kerberos (4771, контроллер домена)';
    'NTLM'='Проверка учетных данных NTLM (4776)'}
$script:NtStatusText=@{'0xc000006a'='неверный пароль';'0xc0000064'='нет такой УЗ';'0xc000006d'='неверное имя пользователя или пароль';'0xc000006e'='ограничения УЗ';
    '0xc000006f'='вход вне разрешенного времени';'0xc0000070'='вход с неразрешенной рабочей станции';'0xc0000071'='срок действия пароля истек';'0xc0000072'='УЗ отключена';
    '0xc0000193'='срок действия УЗ истек';'0xc0000224'='требуется смена пароля при входе';'0xc0000234'='УЗ заблокирована';'0xc000015b'='тип входа не разрешен политикой';
    '0xc0000133'='рассинхронизация времени с контроллером домена';'0xc000005e'='нет доступных серверов входа';'0xc0000192'='служба Netlogon не запущена';
    '0xc0000413'='запрещено политикой проверки подлинности';'0xc00000dc'='SAM в недопустимом состоянии';'0xc000018c'='сбой доверительных отношений';'0xc000018d'='сбой доверительных отношений'}
$script:KerberosStatusText=@{'0x6'='нет такой УЗ';'0xc'='ограничение политики входа';'0x12'='УЗ отключена, заблокирована или истек срок действия';'0x17'='срок действия пароля истек';
    '0x18'='неверный пароль';'0x25'='рассинхронизация времени'}
function Get-StatusText([string]$Codes,[string]$EventId) {
    $parts=New-Object 'System.Collections.Generic.List[string]'
    foreach ($code in ($Codes -split '\s*[|/]\s*')) {
        $c=$code.Trim().ToLowerInvariant()
        if (-not $c -or $c -match '^0x0+$') { continue }
        if ($EventId -eq '4771') { $text=$script:KerberosStatusText[$c] } else { $text=$script:NtStatusText[$c] }
        if ($text) { $item=$c+' — '+$text; if (-not $parts.Contains($item)) { $parts.Add($item) } }
    }
    return ($parts.ToArray() -join '; ')
}
function Write-LogonSummary([string]$Path,$Rows) {
    $w=New-Writer $Path
    try {
        Write-Row $w @('Компьютер','Учетная запись','Результат','Тип входа','Описание типа','Источник (IP / станция)','Внешний IP','Количество','Первое время UTC','Последнее время UTC','Первое время (местное)','Коды отказа','Расшифровка кодов','Event ID')
        # No @() around the rows: pwsh 7.4 throws on @() of List[object].
        foreach ($row in ($Rows | Sort-Object -Property @('Computer','Result','Account','LogonType','Source'))) {
            $type=[string]$row.LogonType
            $typeText=$script:LogonTypeText[$type]
            $public=''; if (Triage-IsPublicIp ([string]$row.Source)) { $public='Да' }
            Write-Row $w @($row.Computer,$row.Account,$row.Result,$type,$typeText,$row.Source,$public,$row.Count,(Format-UtcText $row.First),(Format-UtcText $row.Last),
                (Format-LocalText $row.First),$row.Codes,(Get-StatusText ([string]$row.Codes) ([string]$row.EventId)),$row.EventId)
        }
    } finally { Close-Writer $w }
}
function Get-AuditRows([string]$WorkPath) {
    if ($null -ne $script:TriageRows -and $script:TriageRowsPath -eq $WorkPath) { return ,$script:TriageRows }
    $rows=New-Object 'System.Collections.Generic.List[object]'
    $files=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'TriageInput.csv' -File)
    if ($files.Count -eq 0) { $files=@(Get-ChildItem -LiteralPath $WorkPath -Filter 'Findings-*.csv' -File | Sort-Object Name) }
    foreach ($f in $files) { foreach ($r in (Import-Csv -LiteralPath $f.FullName -Delimiter $Delimiter -Encoding UTF8)) { $rows.Add($r) } }
    $script:TriageRows=$rows; $script:TriageRowsPath=$WorkPath
    return ,$rows
}
# Who was logged on when a device was connected: removable-media events are written by SYSTEM,
# so the user is inferred (not proven) from 4624 types 2, 10, 11 and the logoffs 4634 / 4647.
function New-InteractiveIndex($Rows) {
    $ends=@{}; $index=@{}
    foreach ($r in $Rows) {
        $id=[string]$r.'Event ID'
        if (($id -ne '4634' -and $id -ne '4647') -or [string]$r.'Провайдер' -ne 'Microsoft-Windows-Security-Auditing') { continue }
        $logon=Triage-LogonId $r 'Logon ID цели'
        if (-not $logon) { continue }
        $k=([string]$r.'Компьютер').ToLowerInvariant()+'|'+$logon
        if (-not $ends.ContainsKey($k)) { $ends[$k]=New-Object 'System.Collections.Generic.List[long]' }
        $ends[$k].Add((Get-IsoTicks $r.'Время UTC'))
    }
    foreach ($r in $Rows) {
        if ([string]$r.'Event ID' -ne '4624' -or [string]$r.'Провайдер' -ne 'Microsoft-Windows-Security-Auditing') { continue }
        $type=[string]$r.'Тип входа'
        if ($type -notin @('2','10','11')) { continue }
        if ([string]$r.'SID целевой УЗ' -match '^S-1-5-(18|19|20)$|^S-1-5-(90|96)-') { continue }
        $account=[string]$r.'Целевая УЗ'
        if (-not $account -or $account.EndsWith('$')) { continue }
        $computer=([string]$r.'Компьютер').ToLowerInvariant()
        $start=Get-IsoTicks $r.'Время UTC'; $end=[long]::MaxValue
        $logon=Triage-LogonId $r 'Logon ID цели'
        if ($logon -and $ends.ContainsKey($computer+'|'+$logon)) { foreach ($t in $ends[$computer+'|'+$logon]) { if ($t -ge $start -and $t -lt $end) { $end=$t } } }
        $text=$account+' (тип '+$type+', вход '+(Format-UtcText $r.'Время UTC')+' UTC'
        if ($end -eq [long]::MaxValue) { $text+=', выход не зафиксирован)' } else { $text+=', выход '+(Format-UtcText ([DateTime]::new($end,[DateTimeKind]::Utc).ToString('o',$script:Invariant)))+' UTC)' }
        if (-not $index.ContainsKey($computer)) { $index[$computer]=New-Object 'System.Collections.Generic.List[object]' }
        $index[$computer].Add([pscustomobject]@{Start=$start;End=$end;Account=$account;Text=$text})
    }
    foreach ($k in @($index.Keys)) { $index[$k]=@($index[$k] | Sort-Object Start) }
    return $index
}
# Latest logon that started before the event, had not ended and is at most 7 days old.
function Find-LastInteractive($Index,[string]$Computer,[long]$Ticks) {
    $list=$Index[$Computer.ToLowerInvariant()]
    $found=$null
    if ($null -eq $list) { return $found }
    foreach ($item in $list) {
        if ($item.Start -gt $Ticks) { break }
        if ($item.End -ge $Ticks -and ($Ticks-$item.Start) -le 7*[TimeSpan]::TicksPerDay) { $found=$item }
    }
    return $found
}
$script:UsbKeys=[Collections.Generic.HashSet[string]]::new([string[]]@('Microsoft-Windows-Security-Auditing|6416','Microsoft-Windows-Security-Auditing|6419',
    'Microsoft-Windows-Security-Auditing|6420','Microsoft-Windows-Security-Auditing|6421','Microsoft-Windows-Security-Auditing|6422','Microsoft-Windows-Security-Auditing|6423',
    'Microsoft-Windows-Security-Auditing|6424','Microsoft-Windows-Kernel-PnP|400','Microsoft-Windows-Kernel-PnP|410','Microsoft-Windows-Partition|1006',
    'Microsoft-Windows-UserPnp|20001','Microsoft-Windows-UserPnp|20003'),[StringComparer]::OrdinalIgnoreCase)
$script:UsbStorRx=New-Object Text.RegularExpressions.Regex('(?i)USBSTOR[\\#]+([^\\#]*)[\\#]+([^\\#{]+)')
$script:UsbVidRx=New-Object Text.RegularExpressions.Regex('(?i)\bUSB[\\#]+VID_([0-9a-f]{4})&PID_([0-9a-f]{4})[^\\#]*[\\#]+([^\\#{]+)')
function Get-UsbIdentity([string]$InstanceId,[string]$ParentId) {
    # USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\SERIAL&0, SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_...#SERIAL&0#{guid}, USB\VID_xxxx&PID_yyyy\SERIAL
    $vendor=''; $product=''; $serial=''; $vidPid=''
    $m=$script:UsbStorRx.Match([string]$InstanceId)
    if ($m.Success) {
        $desc=$m.Groups[1].Value
        $v=[regex]::Match($desc,'(?i)Ven_([^&]*)'); if ($v.Success) { $vendor=$v.Groups[1].Value }
        $p=[regex]::Match($desc,'(?i)Prod_([^&]*)'); if ($p.Success) { $product=$p.Groups[1].Value }
        $serial=$m.Groups[2].Value
    }
    foreach ($text in @([string]$ParentId,[string]$InstanceId)) {
        $u=$script:UsbVidRx.Match($text)
        if ($u.Success) {
            $vidPid=('VID_'+$u.Groups[1].Value+'&PID_'+$u.Groups[2].Value).ToUpperInvariant()
            if (-not $serial) { $serial=$u.Groups[3].Value }
            break
        }
    }
    # "&0" is the LUN. "&" in the second position means Windows generated the ID: the device has no serial.
    $serial=($serial -replace '&\d+$','').Trim().ToUpperInvariant()
    $unique=($serial.Length -gt 2 -and $serial[1] -ne '&')
    return [pscustomobject]@{Vendor=($vendor -replace '_',' ').Trim();Product=($product -replace '_',' ').Trim();Serial=$serial;VidPid=$vidPid;Unique=$unique}
}
function Build-UsbSheets([string]$WorkPath,$Rows,$Logons) {
    $devices=@{}; $events=New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $Rows) {
        $provider=[string]$r.'Провайдер'; $id=[string]$r.'Event ID'
        if (-not $script:UsbKeys.Contains($provider+'|'+$id)) { continue }
        $computer=[string]$r.'Компьютер'; $time=[string]$r.'Время UTC'; $ticks=Get-IsoTicks $time
        $instance=Triage-DataValue $r @('DeviceId','DeviceInstanceId','DeviceInstanceID')
        $usb=Get-UsbIdentity $instance (Triage-DataValue $r @('ParentId','ParentDeviceInstanceId'))
        $vendor=$usb.Vendor; $model=$usb.Product; $serial=$usb.Serial; $unique=$usb.Unique
        $capacity=''; $action=[string]$r.'Событие'
        if ($provider -eq 'Microsoft-Windows-Partition') {
            $text=Triage-DataValue $r @('Manufacturer'); if ($text) { $vendor=$text.Trim() }
            $text=Triage-DataValue $r @('Model'); if ($text) { $model=$text.Trim() }
            if (-not $serial) { $serial=(Triage-DataValue $r @('SerialNumber')).Trim().ToUpperInvariant(); $unique=$serial.Length -gt 2 }
            $bytes=[double]0
            if ([double]::TryParse((Triage-DataValue $r @('Capacity')),[Globalization.NumberStyles]::Float,$script:Invariant,[ref]$bytes)) {
                $capacity=[Math]::Round($bytes/1e9,1).ToString('0.#',$script:Invariant)
                if ($bytes -eq 0) { $action+=' — емкость 0: вероятно, извлечение' }
            }
        }
        $name=($vendor+' '+$model).Trim(); $strong=[bool]$name
        if (-not $name) { $name=Triage-DataValue $r @('DeviceDescription','FriendlyName') }
        if ($unique) { $key='sn:'+$serial }
        elseif ($instance) { $key='id:'+$computer.ToLowerInvariant()+'|'+$instance.ToUpperInvariant() }
        else { $key='name:'+$computer.ToLowerInvariant()+'|'+$name.ToUpperInvariant() }
        $last=Find-LastInteractive $Logons $computer $ticks
        $d=$devices[$key]
        if ($null -eq $d) {
            $d=[pscustomobject]@{Serial=$(if($unique){$serial}else{''});Name='';Strong=$false;VidPid='';Computers=(New-Object 'System.Collections.Generic.List[string]');Times=@{};
                First=$time;Last=$time;Count=0;Ids=(New-Object 'System.Collections.Generic.HashSet[string]');Capacity='';Users=(New-Object 'System.Collections.Generic.List[string]');
                Blocked=$false;Instance=$instance}
            $devices[$key]=$d
        }
        $d.Count++
        if ($name -and (-not $d.Name -or ($strong -and -not $d.Strong))) { $d.Name=$name; $d.Strong=$strong }
        if (-not $d.VidPid -and $usb.VidPid) { $d.VidPid=$usb.VidPid }
        if ($capacity -and $capacity -ne '0' -and -not $d.Capacity) { $d.Capacity=$capacity }
        if (-not $d.Instance -and $instance) { $d.Instance=$instance }
        $ck=$computer.ToLowerInvariant()
        if (-not $d.Times.ContainsKey($ck)) { $d.Times[$ck]=New-Object 'System.Collections.Generic.List[long]'; $d.Computers.Add($computer) }
        $d.Times[$ck].Add($ticks)
        if ([string]::CompareOrdinal($time,$d.First) -lt 0) { $d.First=$time }
        if ([string]::CompareOrdinal($time,$d.Last) -gt 0) { $d.Last=$time }
        [void]$d.Ids.Add($id)
        if ($id -eq '6423') { $d.Blocked=$true }
        $userText=''
        if ($last) { $userText=$last.Text; if ($d.Users.Count -lt 5 -and -not $d.Users.Contains($last.Account)) { $d.Users.Add($last.Account) } }
        $events.Add([pscustomobject]@{Computer=$ck;Ticks=$ticks;Row=@((Format-UtcText $time),(Format-LocalText $time),$computer,$action,$id,$name,$serial,$usb.VidPid,(Triage-DataValue $r @('ClassName')),
            $capacity,$userText,$instance,(Triage-Value $r 'Номер'),(Triage-Value $r 'Record ID'),(Triage-Value $r 'Полный путь'),(Triage-Value $r 'Папка источника'))})
    }
    $empty='Событий подключения носителей не найдено. Это не доказывает отсутствие подключений: проверить, переданы ли журналы Kernel-PnP/Configuration и Partition/Diagnostic и включен ли аудит PnP (6416), — см. лист Качество_выгрузки.'
    $w=New-Writer (Join-Path $WorkPath 'UsbEvents.csv')
    try {
        Write-Row $w @('Время UTC','Время (местное)','Компьютер','Событие','Event ID','Устройство','Серийный номер','VID/PID','Класс','Емкость, ГБ','Вероятный пользователь (активный вход)','Идентификатор устройства','Номер находки','Record ID','Файл источника','Папка источника')
        foreach ($ev in ($events | Sort-Object Computer,Ticks)) { Write-Row $w $ev.Row }
        if ($events.Count -eq 0) { Write-Row $w @('','','',$empty,'','','','','','','','','','','','') }
    } finally { Close-Writer $w }
    $w=New-Writer (Join-Path $WorkPath 'UsbDevices.csv')
    try {
        Write-Row $w @('Устройство','Серийный номер','VID/PID','Компьютеров','Компьютеры','Подключений (оценка)','Первое событие UTC','Последнее событие UTC','Событий','Event ID','Емкость, ГБ','Вероятные пользователи','Запрет политикой (6423)','Идентификатор устройства','Что проверить')
        foreach ($d in (@($devices.Values) | Sort-Object @{Expression={$_.Computers.Count};Descending=$true},First)) {
            # Events of one connection (6416, Kernel-PnP, Partition) are seconds apart.
            $connections=0
            foreach ($list in $d.Times.Values) {
                $previous=[long]-1
                foreach ($t in ($list | Sort-Object)) { if ($previous -lt 0 -or ($t-$previous) -gt 120*[TimeSpan]::TicksPerSecond) { $connections++ }; $previous=$t }
            }
            $check='Сверить с журналом учета машинных носителей (меры ЗНИ): носитель учтен, разрешен для этого компьютера, известен владелец.'
            if ($d.Computers.Count -gt 1) { $check='Носитель подключался к нескольким компьютерам: возможный перенос данных или ВПО между сегментами. '+$check }
            if ($d.Blocked) { $check='Политика запретила установку устройства (6423): была попытка подключения. '+$check }
            if (-not $d.Serial) { $check+=' Серийный номер не получен: устройство определено по ID экземпляра.' }
            Write-Row $w @($d.Name,$d.Serial,$d.VidPid,$d.Computers.Count,($d.Computers.ToArray() -join ' | '),$connections,(Format-UtcText $d.First),(Format-UtcText $d.Last),$d.Count,
                ((@($d.Ids) | Sort-Object {[int]$_}) -join ', '),$d.Capacity,($d.Users.ToArray() -join ' | '),$(if($d.Blocked){'Да'}else{''}),$d.Instance,$check)
        }
        if ($devices.Count -eq 0) { Write-Row $w @($empty,'','','','','','','','','','','','','','') }
    } finally { Close-Writer $w }
    return $devices
}
$script:SoftwareKeys=[Collections.Generic.HashSet[string]]::new([string[]]@('MsiInstaller|1033','MsiInstaller|1034','MsiInstaller|1035','MsiInstaller|1022',
    'Microsoft-Windows-WindowsUpdateClient|19','Microsoft-Windows-WindowsUpdateClient|20','Service Control Manager|7045','Microsoft-Windows-Security-Auditing|4697'),[StringComparer]::OrdinalIgnoreCase)
# Remote administration tools; the same list as the Sigma pack rules.
$script:RemoteToolRx='(?i)(teamviewer|anydesk|radmin|rserver3|rmanservice|rutserv|rfusclient|remote utilities|litemanager|romserver|ammyy|aeroadmin|splashtop|screenconnect|rustdesk|rudesktop|dwagent|dwservice|netsupport|client32\.exe|dameware|dwrcs|mesh ?agent|atera|tightvnc|tvnserver|ultravnc|uvnc_service|winvnc|realvnc|vnc server|vncserver|chrome remote desktop|remoting_host|logmein|gotoassist|g2ax_|getscreen|anyviewer|todesk|supremo|nomachine|nxservice)'
$script:SignatureUpdateRx='(?i)(KB2267602|KB4052623|KB915597|Security Intelligence Update|Definition Update|обновлени[ея] (аналитики|определений|сигнатур))'
function Build-SoftwareSheet([string]$WorkPath,$Rows) {
    $items=New-Object 'System.Collections.Generic.List[object]'; $signatures=@{}; $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $Rows) {
        $provider=[string]$r.'Провайдер'; $id=[string]$r.'Event ID'
        if (-not $script:SoftwareKeys.Contains($provider+'|'+$id)) { continue }
        $computer=[string]$r.'Компьютер'; $time=[string]$r.'Время UTC'
        $action=[string]$r.'Событие'; $product=''; $version=''; $vendor=''; $result=''; $details=''
        $risk=New-Object 'System.Collections.Generic.List[string]'
        $user=Triage-Value $r 'Инициатор'; if (-not $user) { $user=Triage-Value $r 'SID инициатора' }
        if ($provider -eq 'MsiInstaller') {
            # Windows Installer: Data0 product, Data1 version, Data2 language, Data3 status, Data4 manufacturer.
            $product=Triage-DataValue $r @('Data0')
            if ($id -eq '1022') { $details=Triage-DataValue $r @('Data1') }
            else {
                $version=Triage-DataValue $r @('Data1'); $vendor=Triage-DataValue $r @('Data4')
                $status=Triage-DataValue $r @('Data3')
                if ($status -eq '0') { $result='Успешно' } elseif ($status) { $result='Код '+$status }
            }
        } elseif ($provider -eq 'Microsoft-Windows-WindowsUpdateClient') {
            $product=Triage-DataValue $r @('updateTitle')
            if ($id -eq '20') { $result='Ошибка '+(Triage-DataValue $r @('errorCode')) } else { $result='Успешно' }
            if ($id -eq '19' -and $product -match $script:SignatureUpdateRx) {
                # Antivirus signature updates arrive several times a day: one summary row per computer.
                $k=$computer.ToLowerInvariant(); $s=$signatures[$k]
                if ($null -eq $s) { $s=[pscustomobject]@{Computer=$computer;Count=0;First=$time;Last=$time;Title=$product;Row=$r}; $signatures[$k]=$s }
                $s.Count++
                if ([string]::CompareOrdinal($time,$s.First) -lt 0) { $s.First=$time }
                if ([string]::CompareOrdinal($time,$s.Last) -gt 0) { $s.Last=$time; $s.Title=$product; $s.Row=$r }
                continue
            }
        } else {
            $product=Triage-DataValue $r @('ServiceName')
            $image=Triage-DataValue $r @('ImagePath','ServiceFileName')
            $details=$image
            $start=Triage-DataValue $r @('StartType','ServiceStartType'); $account=Triage-DataValue $r @('AccountName','ServiceAccount')
            if ($start) { $details+=' | запуск: '+$start }
            if ($account) { $details+=' | УЗ: '+$account }
            $minute=$time; if ($minute.Length -ge 16) { $minute=$minute.Substring(0,16) }
            # Security 4697 and System 7045 describe the same installation.
            if (-not $seen.Add(($computer+'|'+$product+'|'+$minute).ToLowerInvariant())) { continue }
            if (($product+' '+$image) -match $script:RemoteExecService) { $risk.Add('признак удаленного выполнения (PsExec/Impacket): '+$Matches[0]) }
            else { $serviceRisk=Get-ServiceRisk $r; if ($serviceRisk.HasRisk) { $risk.Add($serviceRisk.Evidence) } }
            $result='Установлена'
        }
        $tool=''
        if (($product+' '+$vendor+' '+$details) -match $script:RemoteToolRx) { $tool=$Matches[0]; $risk.Insert(0,'средство удаленного доступа: '+$tool) }
        $items.Add([pscustomobject]@{Computer=$computer;Tool=$tool;Ticks=(Get-IsoTicks $time);Row=@((Format-UtcText $time),(Format-LocalText $time),$computer,$action,$product,$version,$vendor,$result,
            $details,$user,($risk.ToArray() -join '; '),$id,$provider,(Triage-Value $r 'Номер'),(Triage-Value $r 'Record ID'),(Triage-Value $r 'Полный путь'),(Triage-Value $r 'Папка источника'))})
    }
    foreach ($s in $signatures.Values) {
        $r=$s.Row
        $items.Add([pscustomobject]@{Computer=$s.Computer;Tool='';Ticks=(Get-IsoTicks $s.Last);Row=@((Format-UtcText $s.Last),(Format-LocalText $s.Last),$s.Computer,'Обновления сигнатур антивируса (Windows Update)',
            $s.Title,'','',('Успешно: '+$s.Count),('Сводная строка: первое обновление '+(Format-UtcText $s.First)+' UTC, последнее '+(Format-UtcText $s.Last)+' UTC'),'','','19',
            'Microsoft-Windows-WindowsUpdateClient',(Triage-Value $r 'Номер'),(Triage-Value $r 'Record ID'),(Triage-Value $r 'Полный путь'),(Triage-Value $r 'Папка источника'))})
    }
    $w=New-Writer (Join-Path $WorkPath 'SoftwareChanges.csv')
    try {
        Write-Row $w @('Время UTC','Время (местное)','Компьютер','Действие','Продукт / служба / обновление','Версия','Производитель','Результат','Путь / параметры','Инициатор','Риск / примечание','Event ID','Источник','Номер находки','Record ID','Файл источника','Папка источника')
        foreach ($item in ($items | Sort-Object Computer,Ticks)) { Write-Row $w $item.Row }
    } finally { Close-Writer $w }
    return ,$items
}
$script:AccountActions=@{'4720'='Создана УЗ';'4722'='Включена УЗ';'4723'='Попытка смены пароля';'4724'='Сброс пароля';'4725'='Отключена УЗ';'4726'='Удалена УЗ';
    '4738'='Изменена УЗ';'4740'='УЗ заблокирована';'4767'='УЗ разблокирована';'4781'='УЗ переименована';'4741'='Создана УЗ компьютера';'4743'='Удалена УЗ компьютера';
    '4728'='Добавлен в глобальную группу';'4732'='Добавлен в локальную группу';'4756'='Добавлен в универсальную группу';'4729'='Удален из глобальной группы';
    '4733'='Удален из локальной группы';'4757'='Удален из универсальной группы';'4765'='Добавлен SID History';'4766'='Отказ в добавлении SID History'}
$script:AccountChangeFields=@('SamAccountName','DisplayName','UserPrincipalName','HomeDirectory','ScriptPath','ProfilePath','UserWorkstations','AccountExpires','PrimaryGroupId','AllowedToDelegateTo','UserParameters','SidHistory','LogonHours')
# UserAccountControl of 4720/4738 uses SAM bits (0x15 = disabled + password not required + normal account).
$script:UacRiskFlags=@(@(0x4,'пароль не обязателен',$true),@(0x200,'срок действия пароля не ограничен',$false),@(0x800,'хранение пароля с обратимым шифрованием',$true),
    @(0x2000,'доверена для делегирования',$true),@(0x8000,'только DES',$true),@(0x10000,'без предварительной аутентификации Kerberos (AS-REP Roasting)',$true),
    @(0x40000,'делегирование с переходом протокола',$true))
function Get-UacChange($r,[bool]$StrongOnly) {
    $old=Triage-DataValue $r @('OldUacValue'); $new=Triage-DataValue $r @('NewUacValue')
    if ($new -notmatch '^0x[0-9a-fA-F]{1,8}$') { return '' }
    $o=[long]0; if ($old -match '^0x[0-9a-fA-F]{1,8}$') { $o=[Convert]::ToInt64($old.Substring(2),16) }
    $added=[Convert]::ToInt64($new.Substring(2),16) -band (-bnot $o)
    $flags=New-Object 'System.Collections.Generic.List[string]'
    foreach ($f in $script:UacRiskFlags) { if (($added -band $f[0]) -ne 0 -and ($f[2] -or -not $StrongOnly)) { $flags.Add($f[1]) } }
    return ($flags.ToArray() -join ', ')
}
function Build-AccountSheet([string]$WorkPath,$Rows) {
    $items=New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $Rows) {
        if ([string]$r.'Провайдер' -ne 'Microsoft-Windows-Security-Auditing') { continue }
        $id=[string]$r.'Event ID'
        $action=$script:AccountActions[$id]
        if (-not $action) { continue }
        $target=Triage-Value $r 'Целевая УЗ'; $targetSid=Triage-Value $r 'SID целевой УЗ'; $group=''; $groupKind=''; $details=''
        $notes=New-Object 'System.Collections.Generic.List[string]'
        if ($id -in @('4728','4732','4756','4729','4733','4757')) {
            $group=$target; if ($targetSid) { $group+=' ('+$targetSid+')' }
            if (Is-PrivilegedGroup $targetSid) { $groupKind='Административная' }
            elseif ($targetSid -eq 'S-1-5-32-555') { $groupKind='Remote Desktop Users (RDP)' }
            elseif ($targetSid -eq 'S-1-5-32-580') { $groupKind='Remote Management Users (WinRM)' }
            $target=Triage-Value $r 'Участник группы'; $targetSid=Triage-Value $r 'SID участника'
            if ($target -match '^CN=((?:\\,|[^,])+)') { $target=$Matches[1] }
            if (-not $target) { $target=$targetSid }
        } elseif ($id -eq '4740') {
            $target=Triage-DataValue $r @('TargetUserName')
            $details='Компьютер-источник блокировки: '+(Triage-DataValue $r @('TargetDomainName'))
        } elseif ($id -eq '4781') {
            $details=(Triage-DataValue $r @('OldTargetUserName'))+' → '+(Triage-DataValue $r @('NewTargetUserName'))
        } elseif ($id -in @('4720','4738')) {
            $changes=New-Object 'System.Collections.Generic.List[string]'
            foreach ($name in $script:AccountChangeFields) { $v=Triage-DataValue $r @($name); if ($v -and $v -ne '-' -and $v -notmatch '^%%\d+$') { $changes.Add($name+'='+$v) } }
            $uac=Triage-DataValue $r @('NewUacValue'); if ($uac) { $changes.Add('UAC '+(Triage-DataValue $r @('OldUacValue'))+' → '+$uac) }
            $details=$changes.ToArray() -join '; '
            if ($details.Length -gt 500) { $details=$details.Substring(0,500)+' [обрезано]' }
            if ($id -eq '4738') { $weak=Get-UacChange $r $false; if ($weak) { $notes.Add('установлены флаги: '+$weak) } }
        } elseif ($id -in @('4765','4766')) { $details='SID History: '+(Triage-DataValue $r @('SidHistory','SourceSid')) }
        if ($targetSid -match '-500$') { $notes.Add('встроенная УЗ Администратор (RID 500)') }
        elseif ($targetSid -match '-501$') { $notes.Add('встроенная УЗ Гость (RID 501)') }
        if ($target.EndsWith('$') -and $id -notin @('4741','4743','4740')) { $notes.Add('имя оканчивается на $: похоже на УЗ компьютера, проверить') }
        if ($groupKind) { $notes.Add('группа: '+$groupKind) }
        $time=[string]$r.'Время UTC'
        $items.Add([pscustomobject]@{Computer=[string]$r.'Компьютер';Ticks=(Get-IsoTicks $time);Row=@((Format-UtcText $time),(Format-LocalText $time),[string]$r.'Компьютер',$action,$target,$targetSid,$group,
            $details,(Triage-Value $r 'Инициатор'),(Triage-Value $r 'SID инициатора'),(Triage-Value $r 'Logon ID инициатора'),(Triage-Value $r 'Результат аудита'),($notes.ToArray() -join '; '),$id,
            (Triage-Value $r 'Номер'),(Triage-Value $r 'Record ID'),(Triage-Value $r 'Полный путь'),(Triage-Value $r 'Папка источника'))})
    }
    $w=New-Writer (Join-Path $WorkPath 'AccountChanges.csv')
    try {
        Write-Row $w @('Время UTC','Время (местное)','Компьютер','Действие','Учетная запись','SID учетной записи','Группа','Изменение / детали','Инициатор','SID инициатора','Logon ID инициатора','Результат','Примечание','Event ID','Номер находки','Record ID','Файл источника','Папка источника')
        foreach ($item in ($items | Sort-Object Computer,Ticks)) { Write-Row $w $item.Row }
    } finally { Close-Writer $w }
    return ,$items
}
# One row per computer: what an auditor reads first.
function Build-HostSheet([string]$WorkPath,$LogonRows,$UsbDevices,$Software,$Accounts,$Rows) {
    $hosts=@{}
    $get={ param([string]$Computer)
        $k=$Computer.ToLowerInvariant()
        $h=$hosts[$k]
        if ($null -eq $h) {
            $h=[pscustomobject]@{Computer=$Computer;Folders=(New-Object 'System.Collections.Generic.List[string]');Channels=(New-Object 'System.Collections.Generic.List[string]');
                First='';Last='';SecurityDays=[double]-1;P1=0;P2=0;Score=0;Scenarios=@{};Sigma=0;Success=[long]0;Failure=[long]0;
                PublicIps=(New-Object 'System.Collections.Generic.List[string]');Rdp=@{};Usb=0;UsbBlocked=$false;Software=0;
                Tools=(New-Object 'System.Collections.Generic.List[string]');Accounts=0;Clears=0;Crashes=0;Fstec=(New-Object 'System.Collections.Generic.List[string]');BadFiles=0}
            $hosts[$k]=$h
        }
        return $h
    }
    $filesPath=Join-Path $WorkPath 'Files.csv'
    if (Test-Path -LiteralPath $filesPath) {
        foreach ($f in (Import-Csv -LiteralPath $filesPath -Delimiter $Delimiter -Encoding UTF8)) {
            $channels=@(([string]$f.'Каналы') -split ' \| ' | Where-Object { $_ })
            $first=[string]$f.'Время первой записи UTC'; $last=[string]$f.'Время последней записи UTC'
            $days=[double]-1
            if (($channels -contains 'Security') -and $first -and $last) { try { $days=((Get-IsoTicks $last)-(Get-IsoTicks $first))/[double][TimeSpan]::TicksPerDay } catch { } }
            foreach ($c in (([string]$f.'Компьютеры') -split ' \| ' | Where-Object { $_ })) {
                $h=& $get $c
                $folder=[IO.Path]::GetDirectoryName([string]$f.'Полный путь')
                if ($folder -and $h.Folders.Count -lt 5 -and -not $h.Folders.Contains($folder)) { $h.Folders.Add($folder) }
                foreach ($ch in $channels) { if (-not $h.Channels.Contains($ch)) { $h.Channels.Add($ch) } }
                if ($first -and (-not $h.First -or [string]::CompareOrdinal($first,$h.First) -lt 0)) { $h.First=$first }
                if ($last -and (-not $h.Last -or [string]::CompareOrdinal($last,$h.Last) -gt 0)) { $h.Last=$last }
                if ($days -gt $h.SecurityDays) { $h.SecurityDays=$days }
                if ([string]$f.'Статус обработки' -in @((Ru-FileStatus 'Partial'),(Ru-FileStatus 'Failed'))) { $h.BadFiles++ }
            }
        }
    }
    foreach ($inc in @($script:TriageIncidents)) {
        if (-not $inc.Computer) { continue }
        $h=& $get $inc.Computer
        if ($inc.Priority -eq $script:P1) { $h.P1++ } elseif ($inc.Priority -eq $script:P2) { $h.P2++ }
        if ($inc.Score -gt $h.Score) { $h.Score=$inc.Score }
    }
    foreach ($g in @($script:TriageGroups.Values)) {
        if (-not $g.Computer) { continue }
        $h=& $get $g.Computer
        if (-not $h.Scenarios.ContainsKey($g.Scenario) -or $h.Scenarios[$g.Scenario] -lt $g.Score) { $h.Scenarios[$g.Scenario]=$g.Score }
        if ($g.Score -gt $h.Score) { $h.Score=$g.Score }
        foreach ($m in ([string]$g.Fstec -split ',\s*')) { if ($m -and -not $h.Fstec.Contains($m)) { $h.Fstec.Add($m) } }
    }
    $sigmaPath=Join-Path $WorkPath 'SigmaAlerts.csv'
    if (Test-Path -LiteralPath $sigmaPath) {
        foreach ($a in (Import-Csv -LiteralPath $sigmaPath -Delimiter $Delimiter -Encoding UTF8)) { if ($a.'Компьютер') { $h=& $get $a.'Компьютер'; $h.Sigma++ } }
    }
    foreach ($l in $LogonRows) {
        if (-not $l.Computer) { continue }
        $h=& $get $l.Computer
        if ($l.Result -eq $script:ResultSuccess) {
            $h.Success+=[long]$l.Count
            $ip=Triage-NormalIp ([string]$l.Source)
            if ((Triage-IsPublicIp $ip) -and $h.PublicIps.Count -lt 10 -and -not $h.PublicIps.Contains($ip)) { $h.PublicIps.Add($ip) }
        } else { $h.Failure+=[long]$l.Count }
    }
    foreach ($t in @($script:RdpTotals.Values)) {
        if (-not $t.Computer) { continue }
        $h=& $get $t.Computer
        # Security and TerminalServices describe the same sessions: totals are kept per data source.
        if (-not $h.Rdp.ContainsKey($t.Source)) { $h.Rdp[$t.Source]=@([long]0,[double]0) }
        $h.Rdp[$t.Source][0]+=[long]$t.Count; $h.Rdp[$t.Source][1]+=[double]$t.Seconds
        $ip=Triage-NormalIp ([string]$t.SourceIP)
        if ((Triage-IsPublicIp $ip) -and $h.PublicIps.Count -lt 10 -and -not $h.PublicIps.Contains($ip)) { $h.PublicIps.Add($ip) }
    }
    foreach ($d in @($UsbDevices.Values)) {
        foreach ($c in $d.Computers) { $h=& $get $c; $h.Usb++; if ($d.Blocked) { $h.UsbBlocked=$true } }
    }
    foreach ($s in $Software) {
        if (-not $s.Computer) { continue }
        $h=& $get $s.Computer; $h.Software++
        if ($s.Tool -and -not $h.Tools.Contains($s.Tool.ToLowerInvariant())) { $h.Tools.Add($s.Tool.ToLowerInvariant()) }
    }
    foreach ($a in $Accounts) { if ($a.Computer) { $h=& $get $a.Computer; $h.Accounts++ } }
    foreach ($r in $Rows) {
        $provider=[string]$r.'Провайдер'; $id=[string]$r.'Event ID'
        if (-not $r.'Компьютер') { continue }
        if ($provider -eq 'Microsoft-Windows-Eventlog' -and ($id -eq '104' -or $id -eq '1102')) { $h=& $get $r.'Компьютер'; $h.Clears++ }
        elseif (($provider -eq 'Microsoft-Windows-Kernel-Power' -and $id -eq '41') -or ($provider -eq 'EventLog' -and $id -eq '6008')) { $h=& $get $r.'Компьютер'; $h.Crashes++ }
    }
    $w=New-Writer (Join-Path $WorkPath 'Hosts.csv')
    try {
        Write-Row $w @('Компьютер','Приоритет','Оценка риска','КИ P1','КИ P2','Главные сценарии','Срабатываний Sigma','Меры ФСТЭК №239 (группы)','Успешных входов','Неудачных входов',
            'Внешние IP (успешные входы, RDP)','RDP-сеансов','RDP суммарно (ч:мм:сс)','Съемных носителей','Изменений ПО','Средства удаленного доступа','Изменений УЗ','Очисток журналов','Аварийных перезагрузок',
            'Журналы (каналы)','Период событий с (UTC)','Период событий по (UTC)','Глубина Security, дней','Папки источника','Замечания')
        foreach ($h in (@($hosts.Values) | Sort-Object @{Expression={$_.Score};Descending=$true},Computer)) {
            $top=@($h.Scenarios.GetEnumerator() | Sort-Object @{Expression={$_.Value};Descending=$true},Name | Select-Object -First 5 | ForEach-Object { $_.Name+' ('+$_.Value+')' })
            $rdpSource=''; if ($h.Rdp.ContainsKey('Security')) { $rdpSource='Security' } elseif ($h.Rdp.Count -gt 0) { $rdpSource=@($h.Rdp.Keys)[0] }
            $rdpCount=''; $rdpTime=''
            if ($rdpSource) { $rdpCount=$h.Rdp[$rdpSource][0]; $rdpTime=Format-Duration $h.Rdp[$rdpSource][1] }
            $notes=New-Object 'System.Collections.Generic.List[string]'
            if (-not $h.Channels.Contains('Security')) { $notes.Add('журнал Security не передан: выводы о входах и УЗ ограничены') }
            elseif ($h.SecurityDays -ge 0 -and $h.SecurityDays -lt 30) { $notes.Add('журнал Security охватывает '+[Math]::Round($h.SecurityDays,1).ToString('0.#',$script:Invariant)+' дн.: проверить размер журнала и централизованный сбор') }
            if ($h.Clears -gt 0) { $notes.Add('журналы очищались: '+$h.Clears) }
            if ($h.Tools.Count -gt 0) { $notes.Add('средства удаленного доступа: проверить согласование и учет') }
            if ($h.PublicIps.Count -gt 0) { $notes.Add('успешные входы с внешних IP') }
            if ($h.UsbBlocked) { $notes.Add('попытка подключить запрещенное устройство (6423)') }
            if ($h.Crashes -gt 0) { $notes.Add('аварийные перезагрузки (41/6008): проверить причины и влияние на технологический процесс') }
            if ($h.BadFiles -gt 0) { $notes.Add('файлов с неполной обработкой: '+$h.BadFiles) }
            $priority=''; if ($h.Score -gt 0) { $priority=Get-PriorityFromScore $h.Score }
            $days=''; if ($h.SecurityDays -ge 0) { $days=[Math]::Round($h.SecurityDays,1).ToString('0.#',$script:Invariant) }
            Write-Row $w @($h.Computer,$priority,$h.Score,$h.P1,$h.P2,($top -join ' | '),$h.Sigma,(($h.Fstec.ToArray() | Sort-Object) -join ', '),$h.Success,$h.Failure,
                ($h.PublicIps.ToArray() -join ' | '),$rdpCount,$rdpTime,$h.Usb,$h.Software,($h.Tools.ToArray() -join ' | '),$h.Accounts,$h.Clears,$h.Crashes,
                ($h.Channels.ToArray() -join ' | '),(Format-UtcText $h.First),(Format-UtcText $h.Last),$days,($h.Folders.ToArray() -join ' | '),($notes.ToArray() -join '; '))
        }
    } finally { Close-Writer $w }
}
function Build-AuditSheets([string]$WorkPath,$LogonRows) {
    $failures=0; $rows=@(); $usb=@{}; $software=@(); $accounts=@()
    try { $rows=Get-AuditRows $WorkPath }
    catch { $failures++; Log-Issue 'Report' $WorkPath '' ('Не прочитаны строки для листов носителей, ПО и УЗ: '+(Get-TriageErrorText $_)) }
    try { $usb=Build-UsbSheets $WorkPath $rows (New-InteractiveIndex $rows) }
    catch { $failures++; Log-Issue 'Report' $WorkPath '' ('Не сформированы листы съемных носителей: '+(Get-TriageErrorText $_)) }
    try { $software=Build-SoftwareSheet $WorkPath $rows }
    catch { $failures++; Log-Issue 'Report' $WorkPath '' ('Не сформирован лист Изменения_ПО: '+(Get-TriageErrorText $_)) }
    try { $accounts=Build-AccountSheet $WorkPath $rows }
    catch { $failures++; Log-Issue 'Report' $WorkPath '' ('Не сформирован лист Учетные_записи: '+(Get-TriageErrorText $_)) }
    try { Build-HostSheet $WorkPath $LogonRows $usb $software $accounts $rows }
    catch { $failures++; Log-Issue 'Report' $WorkPath '' ('Не сформирован лист Хосты: '+(Get-TriageErrorText $_)) }
    return $failures
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
function Get-ParseSamples {
    $sec='Microsoft-Windows-Security-Auditing'
    $ns='http://schemas.microsoft.com/win/2004/08/events/event'
    # Windows ToXml() shape: single quotes, Qualifiers, Security/Execution elements, Binary.
    $win="<Event xmlns='$ns'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-03-01T08:09:10.1234567Z'/><EventRecordID>123456</EventRecordID><Correlation ActivityID='{11111111-2222-3333-4444-555555555555}'/><Execution ProcessID='700' ThreadID='800'/><Channel>Security</Channel><Computer>srv01.lab.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SRV01$</Data><Data Name='SubjectDomainName'>LAB</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='TargetLogonId'>0x1a2b</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>203.0.113.5</Data><Data Name='IpPort'>51234</Data><Data Name='ProcessName'>C:\Windows\System32\svchost.exe</Data><Data Name='Empty'></Data><Data Name='Dash'>-</Data><Data Name='SelfClosed'/><Data Name='Ent'>a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos; &amp;lt;</Data><Data>unnamed</Data><Data Name='LogonType'>dup</Data></EventData></Event>"
    return @(
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
}
function Test-V92Parse {
    $samples=Get-ParseSamples
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
function New-V10Event([string]$Provider,[int]$Id,[string]$Time,[string]$Channel,$Data,[string]$Keywords='0x8020000000000000',[string]$UserId='') {
    $script:V10Rid++
    $security=''; if ($UserId) { $security="<Security UserID='$UserId'/>" }
    if ($Data -is [string]) { $payload=$Data }
    elseif ($Data -is [array]) { $payload='<EventData>'; foreach ($v in $Data) { $payload+='<Data>'+[Security.SecurityElement]::Escape([string]$v)+'</Data>' }; $payload+='</EventData>' }
    else { $payload='<EventData>'; foreach ($k in $Data.Keys) { $payload+="<Data Name='$k'>"+[Security.SecurityElement]::Escape([string]$Data[$k])+'</Data>' }; $payload+='</EventData>' }
    return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='$Provider' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>$Id</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>$Keywords</Keywords><TimeCreated SystemTime='2026-03-02T$($Time).0000000Z'/><EventRecordID>$($script:V10Rid)</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>$Channel</Channel><Computer>WS01.lab.local</Computer>$security</System>$payload</Event>"
}
# Chronological corpus of one workstation: RDP brute force from the Internet, actions in the
# session, removable media, remote-access software, account changes, log clearing.
function New-V10Corpus {
    $sec='Microsoft-Windows-Security-Auditing'; $ip='45.10.20.30'; $op='S-1-5-21-1-2-3-1100'; $admin='S-1-5-21-1-2-3-500'
    $lsm='Microsoft-Windows-TerminalServices-LocalSessionManager'; $serial='4C530001231122115172'
    $script:V10Rid=0
    $l=New-Object 'System.Collections.Generic.List[string]'
    $l.Add((New-V10Event $sec 4624 '08:00:00' 'Security' ([ordered]@{SubjectUserSid='S-1-5-18';TargetUserSid=$op;TargetUserName='operator';TargetDomainName='WS01';TargetLogonId='0x111';LogonType='2';LogonProcessName='User32 ';AuthenticationPackageName='Negotiate';WorkstationName='WS01';IpAddress='127.0.0.1';IpPort='0'})))
    $l.Add((New-V10Event $sec 4624 '08:00:01' 'Security' ([ordered]@{SubjectUserSid='S-1-5-18';TargetUserSid='S-1-5-90-0-1';TargetUserName='DWM-1';TargetDomainName='Window Manager';TargetLogonId='0x112';LogonType='2';IpAddress='-'})))
    for ($i=0; $i -lt 12; $i++) {
        $l.Add((New-V10Event $sec 4625 ('09:00:{0:D2}' -f $i) 'Security' ([ordered]@{SubjectUserSid='S-1-5-18';TargetUserSid='S-1-0-0';TargetUserName='admin';TargetDomainName='WS01';Status='0xc000006d';SubStatus='0xc000006a';LogonType='10';IpAddress=$ip;IpPort='51000'}) '0x8010000000000000'))
    }
    $l.Add((New-V10Event $sec 4624 '09:01:00' 'Security' ([ordered]@{SubjectUserSid='S-1-5-18';TargetUserSid=$admin;TargetUserName='admin';TargetDomainName='WS01';TargetLogonId='0xa1';LogonType='10';LogonProcessName='User32 ';AuthenticationPackageName='Negotiate';IpAddress=$ip;IpPort='51001'})))
    $l.Add((New-V10Event $lsm 21 '09:01:01' "$lsm/Operational" "<UserData><EventXML xmlns='Event_NS'><User>WS01\admin</User><SessionID>2</SessionID><Address>$ip</Address></EventXML></UserData>" '0x1000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event $sec 4720 '09:02:00' 'Security' ([ordered]@{TargetUserName='hidden$';TargetDomainName='WS01';TargetSid='S-1-5-21-1-2-3-1300';SubjectUserSid=$admin;SubjectUserName='admin';SubjectDomainName='WS01';SubjectLogonId='0xa1';SamAccountName='hidden$';DisplayName='%%1793';OldUacValue='0x0';NewUacValue='0x15'})))
    $l.Add((New-V10Event $sec 4738 '09:03:00' 'Security' ([ordered]@{TargetUserName='svc_sql';TargetDomainName='WS01';TargetSid='S-1-5-21-1-2-3-1200';SubjectUserSid=$admin;SubjectUserName='admin';SubjectDomainName='WS01';SubjectLogonId='0xa1';SamAccountName='-';OldUacValue='0x210';NewUacValue='0x10210';UserAccountControl='%%2096'})))
    $l.Add((New-V10Event $sec 4740 '09:04:00' 'Security' ([ordered]@{TargetUserName='buh';TargetDomainName='PC-BUH';TargetSid='S-1-5-21-1-2-3-1400';SubjectUserSid='S-1-5-18';SubjectUserName='WS01$';SubjectDomainName='LAB'})))
    for ($i=0; $i -lt 3; $i++) {
        $l.Add((New-V10Event $sec 4776 ('09:05:0{0}' -f $i) 'Security' ([ordered]@{PackageName='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0';TargetUserName='ghost';Workstation='KALI';Status='0xc0000064'}) '0x8010000000000000'))
    }
    $l.Add((New-V10Event $sec 4776 '09:05:05' 'Security' ([ordered]@{TargetUserName='operator';Workstation='WS01';Status='0x0'})))
    $l.Add((New-V10Event $sec 4771 '09:06:00' 'Security' ([ordered]@{TargetUserName='ivanov';TargetSid='S-1-5-21-1-2-3-1500';ServiceName='krbtgt/LAB';Status='0x18';IpAddress='::ffff:10.0.0.50';IpPort='50000'}) '0x8010000000000000'))
    $l.Add((New-V10Event $sec 4672 '09:07:00' 'Security' ([ordered]@{SubjectUserSid='S-1-5-18';SubjectUserName='SYSTEM';SubjectDomainName='NT AUTHORITY';PrivilegeList='SeDebugPrivilege'})))
    $l.Add((New-V10Event $sec 4634 '09:31:00' 'Security' ([ordered]@{TargetUserSid=$admin;TargetUserName='admin';TargetDomainName='WS01';TargetLogonId='0xa1';LogonType='10'})))
    $l.Add((New-V10Event $lsm 24 '09:31:01' "$lsm/Operational" "<UserData><EventXML xmlns='Event_NS'><User>WS01\admin</User><SessionID>2</SessionID><Address>$ip</Address></EventXML></UserData>" '0x1000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event $sec 6416 '09:50:00' 'Security' ([ordered]@{SubjectUserSid='S-1-5-18';SubjectUserName='WS01$';SubjectDomainName='LAB';SubjectLogonId='0x3e7';DeviceId=('USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\'+$serial+'&0');DeviceDescription='Disk drive';ClassId='{4d36e967-e325-11ce-bfc1-08002be10318}';ClassName='DiskDrive';VendorIds='USBSTOR\DiskSanDisk_Cruzer_Blade___1.00';CompatibleIds='USBSTOR\Disk';LocationInformation='Port_#0001.Hub_#0004'})))
    $l.Add((New-V10Event 'Microsoft-Windows-Kernel-PnP' 400 '09:50:01' 'Microsoft-Windows-Kernel-PnP/Configuration' ([ordered]@{DeviceInstanceId=('USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00\'+$serial+'&0');DriverName='disk.inf';ClassGuid='{4d36e967-e325-11ce-bfc1-08002be10318}';ParentDeviceInstanceId=('USB\VID_0781&PID_5567\'+$serial)}) '0x4000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event 'Microsoft-Windows-Partition' 1006 '09:50:02' 'Microsoft-Windows-Partition/Diagnostic' ([ordered]@{DiskNumber='1';BusType='7';Manufacturer='SanDisk';Model='Cruzer Blade';SerialNumber=$serial;ParentId=('USB\VID_0781&PID_5567\'+$serial);Capacity='16008609792'}) '0x8000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event 'Microsoft-Windows-Partition' 1006 '09:50:03' 'Microsoft-Windows-Partition/Diagnostic' ([ordered]@{DiskNumber='0';BusType='11';Manufacturer='';Model='Samsung SSD';SerialNumber='S1';Capacity='512110190592'}) '0x8000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event 'MsiInstaller' 1033 '10:00:00' 'Application' @('AnyDesk','7.1.0','1033','0','AnyDesk Software GmbH','(NULL)','') '0x80000000000000' $op))
    $l.Add((New-V10Event 'Service Control Manager' 7045 '10:00:05' 'System' ([ordered]@{ServiceName='AnyDesk';ImagePath='"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service';ServiceType='user mode service';StartType='auto start';AccountName='LocalSystem'}) '0x8080000000000000' $op))
    $l.Add((New-V10Event 'Microsoft-Windows-WindowsUpdateClient' 19 '10:10:00' 'System' ([ordered]@{updateTitle='Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.405.1.0)';updateGuid='{a}';updateRevisionNumber='200'}) '0x8000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event 'Microsoft-Windows-WindowsUpdateClient' 19 '10:20:00' 'System' ([ordered]@{updateTitle='2026-03 Cumulative Update for Windows 10 (KB5050000)';updateGuid='{c}';updateRevisionNumber='1'}) '0x8000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event 'Microsoft-Windows-WindowsUpdateClient' 19 '11:10:00' 'System' ([ordered]@{updateTitle='Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.405.9.0)';updateGuid='{b}';updateRevisionNumber='200'}) '0x8000000000000000' 'S-1-5-18'))
    $l.Add((New-V10Event 'Microsoft-Windows-Eventlog' 1102 '11:20:00' 'Security' "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>$admin</SubjectUserSid><SubjectUserName>admin</SubjectUserName><SubjectDomainName>WS01</SubjectDomainName><SubjectLogonId>0xa1</SubjectLogonId></LogFileCleared></UserData>" '0x4020000000000000'))
    # Invalid XML character: compiled parser declines, PowerShell recovers, FromPs hands it over.
    $l.Add((New-V10Event $sec 4725 '11:30:00' 'Security' ([ordered]@{TargetUserName=('bad'+[char]1+'name');TargetDomainName='WS01';TargetSid='S-1-5-21-1-2-3-1600';SubjectUserSid=$op;SubjectUserName='operator';SubjectDomainName='WS01';SubjectLogonId='0x111'})))
    return ,$l
}
function Reset-V10State([string]$Dir,[string]$Evtx) {
    $script:RunPath=$Dir; $script:SpoolPath=Join-Path $Dir 'spool'; [void][IO.Directory]::CreateDirectory($script:SpoolPath)
    $script:Part=0; $script:PartRows=0; $script:Summary=@{}; $script:LogonAgg=@{}; $script:FindingCount=[long]0; $script:BurstCount=0
    $script:RdpCount=0; $script:RdpClosed=@{}; $script:RdpTotals=@{}; $script:EvidenceWriter=$null; $script:FindingWriter=$null; $script:TriageWriter=$null
    $script:RdpWriter=New-Writer (Join-Path $Dir 'RdpIntervals.csv'); Write-Row $script:RdpWriter $script:RdpHeaders
    $script:BurstWriter=New-Writer (Join-Path $Dir 'AuthBursts.csv')
    Write-Row $script:BurstWriter @('Приоритет','Event ID','Событие','Папка источника','Компьютер','Источник','Окно: начало UTC','Окно: конец UTC','Событий в окне','Разных УЗ','Учетные записи','Номера находок (пример)','Файлы и Record ID (пример)','Коды статуса','Комментарий')
    return (New-Object IO.FileInfo($Evtx))
}
# PowerShell branch of the main loop.
function Invoke-V10PowerShell([string]$Dir,[string]$Evtx,$Events) {
    $file=Reset-V10State $Dir $Evtx
    $script:TriageWriter=New-Writer (Join-Path $Dir 'TriageInput.csv'); Write-Row $script:TriageWriter $script:FindingHeaders
    New-FindingFile
    $state=@{}; $spool=@{}
    try {
        foreach ($x in $Events) {
            $e=Parse-Event $x; $r=Match-Event $e $false; $id=[long]0
            if ($r) { $e.Fingerprint=Hash-Text $e.Xml; $id=Save-Finding $e $r $file ''; if ($e.Id -in $script:FailureIds) { Save-Failure $e $file $id $spool } }
            if ($script:RdpRelevant.Contains($e.Provider+'|'+$e.Id)) { Handle-Rdp $e $state $file.FullName $id }
        }
        Reset-Rdp $state '' 'Конец файла'
        foreach ($w in $spool.Values) { Close-Writer $w }
        Close-Writer $script:FindingWriter; Close-Writer $script:TriageWriter
        foreach ($sp in (Get-ChildItem -LiteralPath $script:SpoolPath -Filter '*.jsonl' -File | Sort-Object Name)) { Correlate-Failures $sp.FullName }
    } finally { Close-Writer $script:BurstWriter; Close-Writer $script:RdpWriter; $script:FindingWriter=$null; $script:TriageWriter=$null }
    return [pscustomobject]@{Logons=@($script:LogonAgg.Values);Summary=@($script:Summary.Values);Findings=$script:FindingCount}
}
# Compiled branch of the main loop (same calls and flag handling).
function Invoke-V10Engine([string]$Dir,[string]$Evtx,$Events,$Sigma) {
    $file=Reset-V10State $Dir $Evtx
    $engine=New-AuditEngine $Dir
    try {
        $engine.Open(); $engine.Sigma=$Sigma
        $engine.BeginFile($file.FullName,$file.DirectoryName,$file.Name,$false,'')
        $state=@{}
        foreach ($x in $Events) {
            $e=$engine.Parse($x)
            if ($null -eq $e) {
                $p=Parse-Event $x
                $e=$engine.FromPs($p.Provider,$p.Id,$p.Channel,$p.Computer,$p.RecordId,$p.Level,$p.TimeUtc,$p.Ticks,$p.AuditOutcome,
                    [string[]]@($p.Data.Keys),[string[]]@(foreach ($v in $p.Data.Values) { [string]$v }),$x,$p.XmlRecovery,[string]$p.F['SecurityUserID'])
            }
            $flags=$engine.Commit($e)
            if ($flags -band 4) { continue }
            if ($flags -band 2) { Reset-Rdp $state $e.Computer 'Время пошло назад' }
            if ($flags -band 1) { Handle-Rdp $e $state $file.FullName $engine.LastFindingId }
        }
        Reset-Rdp $state '' 'Конец файла'
        [void]$engine.EndFile()
        $engine.CorrelateFailures($script:BurstWriter)
        $result=[pscustomobject]@{Logons=@($engine.GetLogons());Summary=@($engine.GetSummary());Findings=$engine.FindingCount;Alerts=0}
        if ($Sigma) {
            $sw=New-Writer (Join-Path $Dir 'SigmaAlerts.csv')
            try { $result.Alerts=$Sigma.Finish($sw,[string]$Delimiter) } finally { Close-Writer $sw }
        }
    } finally { $engine.Dispose(); Close-Writer $script:BurstWriter; Close-Writer $script:RdpWriter }
    return $result
}
function Assert-SameText([string]$A,[string]$B,[string]$Name,[int[]]$IgnoreColumns=@()) {
    $la=@([IO.File]::ReadAllLines($A)); $lb=@([IO.File]::ReadAllLines($B))
    $same=$la.Count -eq $lb.Count
    for ($i=0; $same -and $i -lt $la.Count; $i++) {
        $x=$la[$i]; $y=$lb[$i]
        if ($IgnoreColumns.Count -gt 0) {
            $cx=$x -split '";"'; $cy=$y -split '";"'
            foreach ($c in $IgnoreColumns) { if ($c -lt $cx.Count) { $cx[$c]='' }; if ($c -lt $cy.Count) { $cy[$c]='' } }
            $x=$cx -join '|'; $y=$cy -join '|'
        }
        if ($x -cne $y) { $same=$false; Write-Host ('  line '+($i+1)+":`n  PS: "+$la[$i]+"`n  C#: "+$lb[$i]) }
    }
    if ($la.Count -ne $lb.Count) { Write-Host ('  lines: '+$la.Count+' vs '+$lb.Count) }
    Assert-True $same $Name
}
function Test-V10 {
    if ($NoCompiledEngine) { Write-Host 'v10 engine tests skipped: -NoCompiledEngine'; return }
    $null=Get-EngineType
    $events=New-V10Corpus
    $root=Join-Path ([IO.Path]::GetTempPath()) ('EvtxAudit-V10-'+[guid]::NewGuid().ToString('N'))
    $ps=Join-Path $root 'ps'; $cs=Join-Path $root 'cs'; $e2e=Join-Path $root 'e2e'
    # One source path for all runs: outputs are compared byte for byte.
    $evtx=Join-Path $root 'WS01\Security.evtx'
    foreach ($d in @($ps,$cs,$e2e)) { [void][IO.Directory]::CreateDirectory($d) }
    $saved=@{}
    foreach ($name in @('RunPath','SpoolPath','Part','PartRows','Summary','LogonAgg','FindingCount','BurstCount','RdpCount','RdpTotals','RdpClosed','RdpWriter','BurstWriter','ErrorWriter','SigmaSelectors','QueryCache')) { $saved[$name]=Get-Variable -Scope Script -Name $name -ValueOnly -ErrorAction SilentlyContinue }
    try {
        $script:ErrorWriter=New-Writer (Join-Path $root 'Errors.csv'); Write-Row $script:ErrorWriter @('Время UTC','Этап','Файл источника','Record ID','Ошибка')
        # 1. The compiled engine reproduces the PowerShell path byte for byte.
        $a=Invoke-V10PowerShell $ps $evtx $events
        $b=Invoke-V10Engine $cs $evtx $events $null
        Assert-True ($a.Findings -gt 20 -and $a.Findings -eq $b.Findings) ('v10 engine: same number of findings ('+$a.Findings+')')
        foreach ($name in @('Findings-0001.csv','TriageInput.csv','RdpIntervals.csv')) { Assert-SameText (Join-Path $ps $name) (Join-Path $cs $name) ('v10 engine: identical '+$name) }
        # pwsh 7 ConvertFrom-Json turns ISO strings into DateTime: window times differ only there.
        $ignore=@(); if ($PSVersionTable.PSEdition -eq 'Core') { $ignore=@(6,7) }
        Assert-SameText (Join-Path $ps 'AuthBursts.csv') (Join-Path $cs 'AuthBursts.csv') 'v10 engine: identical password-guessing windows' $ignore
        $text={ param($rows) (@($rows | Sort-Object Computer,Account,Result,LogonType,Source,EventId | ForEach-Object { ($_.Computer,$_.Account,$_.Result,$_.LogonType,$_.Source,$_.EventId,$_.Count,$_.First,$_.Last,$_.Codes) -join '|' }) -join "`n") }
        Assert-True ((& $text $a.Logons) -ceq (& $text $b.Logons) -and @($a.Logons).Count -ge 5) 'v10 engine: identical logon summary'
        $sum={ param($rows) (@($rows | Sort-Object Severity,Category,Computer | ForEach-Object { ($_.Severity,$_.Category,$_.Computer,$_.Count) -join '|' }) -join "`n") }
        Assert-True ((& $sum $a.Summary) -ceq (& $sum $b.Summary)) 'v10 engine: identical summary'
        # Compiled fast parser equals the XmlDocument parser wherever it accepts the XML.
        $parser=New-AuditEngine $root; $compared=0
        foreach ($x in @(Get-ParseSamples) + @($events)) {
            $c=$parser.Parse($x)
            if ($null -eq $c) { continue }
            $compared++; $d=Parse-EventDom $x; $same=$true
            foreach ($name in @('Provider','Id','Channel','Computer','RecordId','Level','TimeUtc','Ticks','AuditOutcome','Subject','Target','SourceIP','LogonType','LogonId','SessionName','XmlRecovery')) {
                if ([string]$c.$name -cne [string]$d.$name) { $same=$false; Write-Host ('  differs: '+$name+' '+$c.$name+' / '+$d.$name) }
            }
            if (($c.Keys -join '|') -cne (@($d.Data.Keys) -join '|') -or ($c.Values -join '|') -cne (@($d.Data.Values) -join '|')) { $same=$false; Write-Host ('  differs: Data '+($c.Keys -join ',')) }
            foreach ($k in @(@($script:FieldSpecs | ForEach-Object { $_[0] }) + 'SecurityUserID')) { if ([string]$c.F[$k] -cne [string]$d.F[$k]) { $same=$false; Write-Host ('  differs: F.'+$k) } }
            if (-not $same) { Assert-True $false ('v10 compiled parser equals XML parser: '+$d.Provider+'/'+$d.Id) }
        }
        Assert-True ($compared -ge 25) ('v10 compiled parser equals XML parser on '+$compared+' events')
        # 2. Embedded Sigma pack: every rule is supported; selectors reach the Windows query.
        $sigma=New-SigmaEngine @()
        Assert-True ($sigma.Problems.Count -eq 0 -and $sigma.Skipped -eq 0 -and $sigma.RuleCount -ge 30 -and $sigma.CorrelationCount -ge 15) ('v10 Sigma pack: '+$sigma.RuleCount+' rules, '+$sigma.CorrelationCount+' correlations, nothing skipped')
        $script:SigmaSelectors=New-Object 'System.Collections.Generic.List[string]'; $script:QueryCache=@{}
        foreach ($s in $sigma.GetSelectors($MaxEventId)) { $script:SigmaSelectors.Add($s) }
        $query=Build-Query 'C:\Logs\Security.evtx' $false
        $doc=New-Object Xml.XmlDocument; $doc.LoadXml($query)
        Assert-True ($script:SigmaSelectors.Count -gt 0 -and $query.Contains('EventID=4769') -and -not $query.Contains('{TIME}')) 'v10 Sigma selectors added to the Windows query'
        if ($MaxEventId -lt 7045) { Write-Host 'v10 end-to-end test skipped: -MaxEventId excludes fixture events'; return }
        # 3. End to end: engine + Sigma -> priority sheet, incidents, hosts and audit sheets.
        $c=Invoke-V10Engine $e2e $evtx $events $sigma
        $alerts=@(Import-Csv -LiteralPath (Join-Path $e2e 'SigmaAlerts.csv') -Delimiter $Delimiter -Encoding UTF8)
        $titles=@($alerts | ForEach-Object { $_.'Правило' })
        foreach ($expected in @('Установлено средство удаленного доступа (служба)','Установлено средство удаленного доступа (Windows Installer)','Создана скрытая учетная запись (имя оканчивается на $)',
            'RDP-вход под встроенной учетной записью Администратор','Подключение USB-накопителя и установка службы (Kernel-PnP)','Установка службы с последующей очисткой журнала Security')) {
            Assert-True ($expected -in $titles) ('v10 Sigma alert: '+$expected)
        }
        $chain=@($alerts | Where-Object { $_.'Правило' -eq 'Подключение USB-накопителя и установка службы (Kernel-PnP)' })[0]
        Assert-True ($chain.'Тип' -like 'Корреляция temporal_ordered*' -and $chain.'Ссылки на события' -like '*#*' -and $chain.'Меры ФСТЭК №239 (группы)' -like '*ЗНИ*') 'v10 Sigma correlation: chain, event links and FSTEC groups'
        Write-RdpTotals (Join-Path $e2e 'RdpTotals.csv')
        Write-LogonSummary (Join-Path $e2e 'LogonSummary.csv') $c.Logons
        $fw=New-Writer (Join-Path $e2e 'Files.csv')
        Write-Row $fw @('Полный путь','Размер, байт','Изменен UTC','SHA256 файла','Статус обработки','Прочитано подходящих событий','Находок','Ошибок разбора','Нет описания Windows','Время первой записи UTC','Время последней записи UTC','Каналы','Компьютеры','Способ отбора','Комментарий','Время обработки, сек')
        Write-Row $fw @($evtx,'1','','','OK','40','30','0','0','2026-02-28T08:00:00.0000000Z','2026-03-02T11:30:00.0000000Z','Security','WS01.lab.local','Правила','','1')
        Write-Row $fw @((Join-Path $root 'WS01\System.evtx'),'1','','','OK','5','5','0','0','2026-01-01T00:00:00.0000000Z','2026-03-02T11:10:00.0000000Z','System','WS01.lab.local','Правила','','1')
        Close-Writer $fw
        $script:ErrorWriter.Flush()
        Build-Triage $e2e
        Assert-True (-not $script:TriageHasErrors) 'v10 end to end: triage without errors'
        $triage=@(Import-Csv -LiteralPath (Join-Path $e2e 'Triage.csv') -Delimiter $Delimiter -Encoding UTF8 | Where-Object { $_.'Приоритет' -ne 'Справка' })
        $sigmaRows=@($triage | Where-Object { $_.'Сценарий' -like 'Sigma: *' })
        Assert-True ($sigmaRows.Count -ge 4 -and @($sigmaRows | Where-Object { $_.'Источник правила' -notlike 'Sigma *' }).Count -eq 0) ('v10 priority sheet: Sigma chains and rules ('+$sigmaRows.Count+' rows)')
        $usbChain=@($sigmaRows | Where-Object { $_.'Сценарий' -eq 'Sigma: Подключение USB-накопителя и установка службы' })
        Assert-True ($usbChain.Count -eq 1 -and $usbChain[0].'КИ' -like 'КИ-*' -and $usbChain[0].'Ссылки на находки и EVTX (до 10)' -like '*Security.evtx#*' -and $usbChain[0].'Event ID' -eq '400, 1006, 6416, 7045') 'v10 priority sheet: USB chain variants merged, linked to incident, events and IDs'
        Assert-True (@($sigmaRows | Where-Object { $_.'Сценарий' -like 'Sigma: Подключен съемный носитель*' }).Count -eq 1 -and @($sigmaRows | Where-Object { $_.'Сценарий' -eq 'Sigma: Установлено средство удаленного доступа' }).Count -eq 1) 'v10 priority sheet: one row per fact for media and remote-access rules'
        $scenarios=@($triage | ForEach-Object { $_.'Сценарий' })
        foreach ($expected in @('Ослаблены параметры безопасности УЗ','Отказы RDP с неверным паролем → успешный вход','RDP-сеанс: создание УЗ','Очистка журнала')) {
            Assert-True ($expected -in $scenarios) ('v10 heuristics: '+$expected)
        }
        Build-LogCoverage $e2e
        $coverage=@(Import-Csv -LiteralPath (Join-Path $e2e 'Coverage.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($coverage[0].'Глубина Security, дней' -eq '2.1' -and $coverage[0].'Что это означает / что запросить' -like '*охватывает только 2.1 дн.*') 'v10 coverage: Security depth and retention note'
        $failures=Build-AuditSheets $e2e $c.Logons
        if ($failures -gt 0) { $script:ErrorWriter.Flush(); Get-Content -LiteralPath (Join-Path $root 'Errors.csv') -Encoding UTF8 | Select-Object -Last $failures | ForEach-Object { Write-Host $_ } }
        Assert-True ($failures -eq 0) 'v10 audit sheets built without errors'
        $usb=@(Import-Csv -LiteralPath (Join-Path $e2e 'UsbDevices.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($usb.Count -eq 1 -and $usb[0].'Серийный номер' -eq '4C530001231122115172' -and $usb[0].'Устройство' -eq 'SanDisk Cruzer Blade' -and $usb[0].'VID/PID' -eq 'VID_0781&PID_5567' -and
            $usb[0].'Подключений (оценка)' -eq '1' -and $usb[0].'Емкость, ГБ' -eq '16' -and $usb[0].'Вероятные пользователи' -eq 'WS01\operator') 'v10 removable media: one device merged from 6416, Kernel-PnP and Partition'
        $usbEvents=@(Import-Csv -LiteralPath (Join-Path $e2e 'UsbEvents.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($usbEvents.Count -eq 3 -and @($usbEvents | Where-Object { $_.'Вероятный пользователь (активный вход)' -eq 'WS01\operator (тип 2, вход 2026-03-02 08:00:00 UTC, выход не зафиксирован)' }).Count -eq 3) 'v10 media events: SATA disk ignored, user inferred from console logon'
        $soft=@(Import-Csv -LiteralPath (Join-Path $e2e 'SoftwareChanges.csv') -Delimiter $Delimiter -Encoding UTF8)
        $msi=@($soft | Where-Object { $_.'Event ID' -eq '1033' })[0]; $svc=@($soft | Where-Object { $_.'Event ID' -eq '7045' })[0]
        Assert-True ($msi.'Продукт / служба / обновление' -eq 'AnyDesk' -and $msi.'Версия' -eq '7.1.0' -and $msi.'Производитель' -eq 'AnyDesk Software GmbH' -and $msi.'Риск / примечание' -like 'средство удаленного доступа*' -and $msi.'Инициатор' -eq 'S-1-5-21-1-2-3-1100') 'v10 software: MSI product, version, vendor, user SID and remote-access flag'
        Assert-True ($svc.'Путь / параметры' -like '"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service | запуск: auto start*' -and @($soft | Where-Object { $_.'Результат' -eq 'Успешно: 2' }).Count -eq 1 -and $soft.Count -eq 4) 'v10 software: service row and one summary row for signature updates'
        $acc=@(Import-Csv -LiteralPath (Join-Path $e2e 'AccountChanges.csv') -Delimiter $Delimiter -Encoding UTF8)
        $uac=@($acc | Where-Object { $_.'Event ID' -eq '4738' })[0]; $lock=@($acc | Where-Object { $_.'Event ID' -eq '4740' })[0]
        Assert-True ($uac.'Примечание' -like '*AS-REP Roasting*' -and $uac.'Учетная запись' -eq 'WS01\svc_sql' -and $lock.'Изменение / детали' -eq 'Компьютер-источник блокировки: PC-BUH' -and $lock.'Учетная запись' -eq 'buh') 'v10 accounts: UAC flags decoded, lockout source'
        $logons=@(Import-Csv -LiteralPath (Join-Path $e2e 'LogonSummary.csv') -Delimiter $Delimiter -Encoding UTF8)
        $rdpFail=@($logons | Where-Object { $_.'Event ID' -eq '4625' })[0]; $ntlm=@($logons | Where-Object { $_.'Event ID' -eq '4776' })[0]; $krb=@($logons | Where-Object { $_.'Event ID' -eq '4771' })[0]
        Assert-True ($rdpFail.'Количество' -eq '12' -and $rdpFail.'Внешний IP' -eq 'Да' -and $rdpFail.'Расшифровка кодов' -like '*0xc000006a — неверный пароль*' -and $rdpFail.'Описание типа' -like 'Удаленный интерактивный*' -and
            $ntlm.'Расшифровка кодов' -eq '0xc0000064 — нет такой УЗ' -and $ntlm.'Источник (IP / станция)' -eq 'KALI' -and $krb.'Расшифровка кодов' -eq '0x18 — неверный пароль' -and $krb.'Источник (IP / станция)' -eq '10.0.0.50') 'v10 logons: counts, public IP, decoded failure codes'
        $hosts=@(Import-Csv -LiteralPath (Join-Path $e2e 'Hosts.csv') -Delimiter $Delimiter -Encoding UTF8)
        $h=$hosts[0]
        Assert-True ($hosts.Count -eq 1 -and $h.'Компьютер' -eq 'WS01.lab.local' -and $h.'Приоритет' -eq $script:P1 -and [int]$h.'КИ P1' -ge 1 -and [int]$h.'Срабатываний Sigma' -ge 5 -and
            $h.'Средства удаленного доступа' -eq 'anydesk' -and $h.'Съемных носителей' -eq '1' -and $h.'Внешние IP (успешные входы, RDP)' -eq '45.10.20.30' -and $h.'RDP-сеансов' -eq '1' -and
            $h.'RDP суммарно (ч:мм:сс)' -eq '0:30:00' -and $h.'Очисток журналов' -eq '1' -and $h.'Глубина Security, дней' -eq '2.1' -and $h.'Меры ФСТЭК №239 (группы)' -like '*ЗНИ*' -and $h.'Замечания' -like '*журналы очищались*') 'v10 hosts: one row with incidents, Sigma, RDP, media, software and notes'
        $plan=Get-ExcelSheetPlan $e2e
        $names=@($plan | ForEach-Object { $_.Name })
        Assert-True (($names[0..5] -join ',') -eq 'Хосты,Инциденты,Приоритетные,Sigma,Подбор_пароля,Входы' -and 'Съемные_носители' -in $names -and 'Изменения_ПО' -in $names -and 'Учетные_записи' -in $names) 'v10 Excel sheet order'
        Assert-True ($plan[0].Freeze -eq 1 -and $plan[0].PriorityColumn -eq 2 -and $plan[0].Types[2] -eq 1 -and $plan[3].Freeze -eq 5) 'v10 Excel plan for hosts and Sigma'
        New-FallbackOverview $e2e (Join-Path $e2e 'overview.csv')
        $overview=@(Import-Csv -LiteralPath (Join-Path $e2e 'overview.csv') -Delimiter $Delimiter -Encoding UTF8)
        Assert-True ($overview[0].'Тип строки' -eq 'Хост' -and @($overview | Where-Object { $_.'Тип строки' -eq 'Sigma' }).Count -eq $alerts.Count) 'v10 CSV fallback: hosts first, Sigma rows included'
    } finally {
        foreach ($k in $saved.Keys) { Set-Variable -Scope Script -Name $k -Value $saved[$k] }
        foreach ($w in @($script:Writers)) { try { $w.Dispose() } catch { } }
        $script:Writers.Clear()
        Remove-Item -LiteralPath $root -Recurse -Force
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
    Test-V10
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
$script:ErrorWriter=New-Writer (Join-Path $script:RunPath 'Errors.csv')
Write-Row $script:ErrorWriter @('Время UTC','Этап','Файл источника','Record ID','Ошибка')
$inventoryWriter=New-Writer (Join-Path $script:RunPath 'Files.csv')
Write-Row $inventoryWriter @('Полный путь','Размер, байт','Изменен UTC','SHA256 файла','Статус обработки','Прочитано подходящих событий','Находок','Ошибок разбора','Нет описания Windows','Время первой записи UTC','Время последней записи UTC','Каналы','Компьютеры','Способ отбора','Комментарий','Время обработки, сек')
$script:RdpWriter=New-Writer (Join-Path $script:RunPath 'RdpIntervals.csv')
Write-Row $script:RdpWriter $script:RdpHeaders
$script:BurstWriter=New-Writer (Join-Path $script:RunPath 'AuthBursts.csv')
Write-Row $script:BurstWriter @('Приоритет','Event ID','Событие','Папка источника','Компьютер','Источник','Окно: начало UTC','Окно: конец UTC','Событий в окне','Разных УЗ','Учетные записи','Номера находок (пример)','Файлы и Record ID (пример)','Коды статуса','Комментарий')
# Compiled engine (fast path) or the PowerShell compatibility path.
$script:EngineMode='PowerShell'; $script:TriageWriter=$null
if ($NoCompiledEngine) { $script:EngineNote='Задан -NoCompiledEngine: совместимый режим PowerShell (медленнее, без Sigma).' }
else {
    try { $script:Engine=New-AuditEngine $script:RunPath; $script:EngineMode='C#' }
    catch {
        $script:Engine=$null
        $script:EngineNote='C#-ядро не скомпилировано ('+$_.Exception.Message+'). Используется совместимый режим PowerShell: медленнее, без Sigma.'
        Write-Warning $script:EngineNote
        Log-Issue 'Engine' '' '' $script:EngineNote
    }
}
if ($script:Engine) {
    $script:Engine.Open()
    if ($NoSigma) { $script:EngineNote='Правила Sigma отключены параметром -NoSigma.' }
    else {
        try {
            $script:Sigma=New-SigmaEngine $SigmaRulesPath
            $script:Engine.Sigma=$script:Sigma
            foreach ($selector in $script:Sigma.GetSelectors($MaxEventId)) { $script:SigmaSelectors.Add($selector) }
            foreach ($problem in $script:Sigma.Problems) { Log-Issue 'Sigma' '' '' $problem }
            $script:SigmaProblemsLogged=$script:Sigma.Problems.Count
            Write-Host ('Sigma: правил {0}, корреляций {1}; пропущено (неподдерживаемые): {2}.' -f $script:Sigma.RuleCount,$script:Sigma.CorrelationCount,$script:Sigma.Skipped)
        } catch {
            $script:Sigma=$null; $script:Engine.Sigma=$null
            Log-Issue 'Sigma' '' '' ('Правила Sigma не загружены: '+$_.Exception.Message)
            Write-Warning ('Правила Sigma не загружены: '+$_.Exception.Message)
        }
    }
} else {
    New-FindingFile
    $script:TriageWriter=New-Writer (Join-Path $script:RunPath 'TriageInput.csv')
    Write-Row $script:TriageWriter $script:FindingHeaders
}
Write-Host ('Режим обработки: '+$(if($script:Engine){'C# (скомпилированное ядро)'}else{'PowerShell (совместимый)'}))
$runStatus='Running'; $files=@(); $processed=0; $warningFiles=0; $failedFiles=0; $processingWarnings=0; $correlationErrors=0; $fatalError=$null
$metaPath=Join-Path $script:RunPath 'Run.json'
$metadata=[ordered]@{ScriptVersion=$script:Version;StartedUtc=$started.ToString('o');FinishedUtc=$null;Status='Running';InputPath=$inputItem.FullName;OutputPath=$outputRoot;
    PowerShell=$PSVersionTable.PSVersion.ToString();Parameters=[ordered]@{FailureThreshold=$FailureThreshold;WindowMinutes=$WindowMinutes;SprayUserThreshold=$SprayUserThreshold;MaxRdpHours=$MaxRdpHours;RowsPerCsv=$RowsPerCsv;Delimiter=[string]$Delimiter;IncludeNoise=[bool]$IncludeNoise;IncludeAllErrors=[bool]$IncludeAllErrors;MaxEventId=$MaxEventId;StartTimeUtc=$(if($script:HasStart){$StartTime.ToUniversalTime().ToString('o')}else{''});EndTimeUtc=$(if($script:HasEnd){$EndTime.ToUniversalTime().ToString('o')}else{''});IncludeMessages=[bool]$script:FormatMessages;SkipMessages=[bool]$SkipMessages;IncludeNetworkLogons=[bool]$IncludeNetworkLogons;DeepScriptScan=[bool]$DeepScriptScan;IncludeProcessCreation=[bool]$IncludeProcessCreation;HashFiles=[bool]$HashFiles;SkipCorrelation=[bool]$SkipCorrelation;SkipTriage=[bool]$SkipTriage;TriageWindowMinutes=$TriageWindowMinutes;NoExcel=[bool]$NoExcel;KeepTechnicalFiles=[bool]$KeepTechnicalFiles;IncludeAllAntivirusEvents=[bool]$IncludeAllAntivirusEvents;ExtraAvFilePattern=$ExtraAvFilePattern;SigmaRulesPath=(@($SigmaRulesPath | Where-Object { $_ }) -join ' | ');NoSigma=[bool]$NoSigma;NoCompiledEngine=[bool]$NoCompiledEngine;IncidentGapHours=$IncidentGapHours};EngineMode=$script:EngineMode;EngineNote=$script:EngineNote;SigmaRules=0;SigmaCorrelations=0;SigmaSkipped=0;SigmaAlerts=0;FilesDiscovered=0;FilesProcessed=0;WarningFiles=0;FailedOrPartialFiles=0;Findings=0;RdpRows=0;AuthBursts=0;Issues=0;ProcessingWarnings=0;CorrelationErrors=0}
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
        $first=''; $last=''; $reader=$null; $filteredError=''; $state=@{}; $spoolWriters=@{}; $lastTimes=@{}; $script:RdpClosed=@{}
        $channels=New-Object 'System.Collections.Generic.HashSet[string]'
        $computers=New-Object 'System.Collections.Generic.HashSet[string]'
        $xmlRecovered=0
        $xmlRecoveryIds=New-Object 'System.Collections.Generic.List[string]'
        $vendorFile=$file.Name -match $ExtraAvFilePattern
        $evidenceName=''
        $script:EvidenceWriter=$null
        if ($KeepTechnicalFiles) { $evidenceName='Evidence-{0:D5}.jsonl' -f ($index+1) }
        if ($script:Engine) {
            $evidencePath=''; if ($evidenceName) { $evidencePath=Join-Path $script:RunPath $evidenceName }
            $script:Engine.BeginFile($file.FullName,$file.DirectoryName,$file.Name,[bool]$vendorFile,$evidencePath)
            $script:FindingCount=$script:Engine.FindingCount; $before=$script:FindingCount
        } elseif ($evidenceName) { $script:EvidenceWriter=New-Writer (Join-Path $script:RunPath $evidenceName) }
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
                $filteredError=$_.Exception.Message
                $reader=$null
                # First fallback: the same query without the selectors of Sigma rules
                # (an added -SigmaRulesPath rule set can exceed Windows query limits).
                if ($script:SigmaSelectors.Count -gt 0 -and -not $vendorFile) {
                    try {
                        $q=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($file.FullName,[System.Diagnostics.Eventing.Reader.PathType]::FilePath,(Build-Query $file.FullName $vendorFile $true))
                        $q.ReverseDirection=$false; $q.TolerateQueryErrors=$false
                        $reader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
                        $reader.BatchSize=1024
                        $note+=' Запрос с селекторами Sigma отклонен Windows: события, нужные только правилам Sigma, не читались. Причина: '+$filteredError
                        $selectionMethod='Правила (без селекторов Sigma)'
                        Log-Issue 'Sigma' $file.FullName '' ('Запрос с селекторами Sigma отклонен; файл прочитан без них. '+$filteredError)
                    } catch { $reader=$null }
                }
            }
            if (-not $reader -and $status -ne 'Failed' -and $filteredError) {
                # Safety fallback: if the optimized structured query is rejected by this
                # Windows/.NET build, read the EVTX sequentially and apply the same rules
                # in PowerShell. Slower, but it avoids treating an unread file as clean.
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
                    if ($script:Engine) {
                        # Compiled path: parse, rules, findings, failures and Sigma in one call.
                        try {
                            $flags=0
                            try {
                                $xml=$record.ToXml()
                                $e=$script:Engine.Parse($xml)
                                if ($null -eq $e) {
                                    # Unusual XML (UserData variants, invalid characters): full XML parser in PowerShell.
                                    $p=Parse-Event $xml
                                    $e=$script:Engine.FromPs($p.Provider,$p.Id,$p.Channel,$p.Computer,$p.RecordId,$p.Level,$p.TimeUtc,$p.Ticks,$p.AuditOutcome,
                                        [string[]]@($p.Data.Keys),[string[]]@(foreach ($v in $p.Data.Values) { [string]$v }),$xml,$p.XmlRecovery,[string]$p.F['SecurityUserID'])
                                }
                                if ($e.XmlRecovery) {
                                    $xmlRecovered++
                                    if ($xmlRecoveryIds.Count -lt 10) { $xmlRecoveryIds.Add([string]$e.RecordId) }
                                }
                                if ($script:FormatMessages -and $script:Engine.WantsMessage($e)) {
                                    try {
                                        $e.Message=[string]$record.FormatDescription()
                                        $e.MessageStatus='Available'
                                        if (-not $e.Message) { $e.MessageStatus='Unavailable'; $messageMissing++ }
                                    } catch { $e.MessageStatus='Unavailable'; $messageMissing++ }
                                }
                                $flags=$script:Engine.Commit($e)
                            } catch {
                                $parseErrors++; $status='Partial'
                                Log-Issue 'ParseOrRule' $file.FullName ([string]$record.RecordId) $_.Exception.Message
                                Reset-Rdp $state '' 'Пропущено событие из-за ошибки разбора: корреляция разорвана.'
                                continue
                            }
                            if ($flags -band 4) { continue }
                            if ($flags -band 2) {
                                Reset-Rdp $state $e.Computer 'Время событий существенно пошло назад; корреляция разорвана.'
                                Log-Issue 'ClockOrder' $file.FullName $e.RecordId ('Предупреждение, не ошибка чтения: время события меньше предыдущего выбранного события на '+$script:Engine.LastRollbackSeconds+' сек. Проверить Security 4616, синхронизацию времени и порядок записей.')
                            }
                            if ($flags -band 1) { Handle-Rdp $e $state $file.FullName $script:Engine.LastFindingId }
                        } finally { $record.Dispose() }
                        if ($selected % 10000 -eq 0) {
                            Write-Progress -Activity 'Offline EVTX audit' -Status ($file.Name+': selected '+$selected) -PercentComplete (100*$index/$files.Count)
                            $script:Engine.Flush()
                        }
                        continue
                    }
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
                        $script:FindingWriter.Flush(); if ($script:EvidenceWriter) { $script:EvidenceWriter.Flush() }; if ($script:TriageWriter) { $script:TriageWriter.Flush() }
                    }
                }
            }
            Reset-Rdp $state '' 'Конец файла; конец сеанса неизвестен. Между файлами RDP автоматически не объединяется.'
            if ($script:Engine) {
                $fileResult=$script:Engine.EndFile()
                foreach ($c in $fileResult.Channels) { [void]$channels.Add($c) }
                foreach ($c in $fileResult.Computers) { [void]$computers.Add($c) }
                $script:FindingCount=$script:Engine.FindingCount
            }
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
            if ($script:FindingWriter) { $script:FindingWriter.Flush() }
            if ($script:Engine) { $script:Engine.Flush() }
            $script:ErrorWriter.Flush()
        }
    }
    Write-RdpTotals (Join-Path $script:RunPath 'RdpTotals.csv')
    if (-not $SkipCorrelation) {
        $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
        Write-Host 'Корреляция неудачных аутентификаций...'
        if ($script:Engine) {
            try { $script:Engine.CorrelateFailures($script:BurstWriter); $script:BurstCount=$script:Engine.BurstCount }
            catch { $correlationErrors++; Log-Issue 'Correlation' $script:RunPath '' $_.Exception.Message }
        } else {
            foreach ($spool in (Get-ChildItem -LiteralPath $script:SpoolPath -Filter '*.jsonl' -File | Sort-Object Name)) {
                try { Correlate-Failures $spool.FullName }
                catch { $correlationErrors++; Log-Issue 'Correlation' $spool.FullName '' $_.Exception.Message }
            }
        }
        Write-Host ('Корреляция отказов: {0:N1} сек.' -f $phaseTimer.Elapsed.TotalSeconds)
    }
    if ($script:Engine) { $script:FindingCount=$script:Engine.FindingCount; $summaryRows=@($script:Engine.GetSummary()); $logonRows=@($script:Engine.GetLogons()) }
    else { $summaryRows=@($script:Summary.Values); $logonRows=@($script:LogonAgg.Values) }
    $summaryWriter=New-Writer (Join-Path $script:RunPath 'Summary.csv')
    Write-Row $summaryWriter @('Приоритет','Категория','Компьютер','Количество')
    foreach ($row in ($summaryRows | Sort-Object -Property @('Computer','Category','Severity'))) { Write-Row $summaryWriter @((Ru-Severity $row.Severity),$row.Category,$row.Computer,$row.Count) }
    Close-Writer $summaryWriter
    try { Write-LogonSummary (Join-Path $script:RunPath 'LogonSummary.csv') $logonRows }
    catch { $correlationErrors++; Log-Issue 'Report' $script:RunPath '' ('Не сформирован лист Входы: '+(Get-TriageErrorText $_)) }
    if ($script:Sigma) {
        $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
        Write-Host 'Корреляции Sigma...'
        $sigmaWriter=New-Writer (Join-Path $script:RunPath 'SigmaAlerts.csv')
        try { $script:SigmaAlertCount=$script:Sigma.Finish($sigmaWriter,[string]$Delimiter) }
        catch { $correlationErrors++; Log-Issue 'Sigma' $script:RunPath '' ('Корреляции Sigma не выполнены: '+$_.Exception.Message) }
        finally { Close-Writer $sigmaWriter }
        foreach ($problem in @($script:Sigma.Problems | Select-Object -Skip $script:SigmaProblemsLogged)) { Log-Issue 'Sigma' '' '' $problem }
        Write-Host ('Sigma: срабатываний {0}; {1:N1} сек.' -f $script:SigmaAlertCount,$phaseTimer.Elapsed.TotalSeconds)
    }
    if (-not $SkipTriage) {
        $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
        Write-Host 'Формирование листов Приоритетные и Качество_выгрузки...'
        if ($script:FindingWriter) { $script:FindingWriter.Flush() }
        if ($script:TriageWriter) { $script:TriageWriter.Flush() }
        if ($script:Engine) { $script:Engine.Flush() }
        $inventoryWriter.Flush(); $script:ErrorWriter.Flush()
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
    $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
    Write-Host 'Листы Хосты, Съемные_носители, Изменения_ПО, Учетные_записи...'
    if ($script:Engine) { $script:Engine.Flush() }
    if ($script:TriageWriter) { $script:TriageWriter.Flush() }
    $sheetFailures=Build-AuditSheets $script:RunPath $logonRows
    if ($sheetFailures -gt 0) { $correlationErrors++; Write-Warning 'Часть дополнительных листов не сформирована; подробности на листе Ошибки.' }
    Write-Host ('Дополнительные листы: {0:N1} сек.' -f $phaseTimer.Elapsed.TotalSeconds)
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
    if ($script:Engine) { try { $script:FindingCount=$script:Engine.FindingCount; $script:Engine.Dispose() } catch { } }
    $metadata.Findings=$script:FindingCount
    $metadata.EngineMode=$script:EngineMode; $metadata.EngineNote=$script:EngineNote; $metadata.SigmaAlerts=$script:SigmaAlertCount
    if ($script:Sigma) { $metadata.SigmaRules=$script:Sigma.RuleCount; $metadata.SigmaCorrelations=$script:Sigma.CorrelationCount; $metadata.SigmaSkipped=$script:Sigma.Skipped }
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
