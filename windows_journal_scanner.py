import asyncio
import time
import requests
import win32evtlog
from datetime import datetime, timedelta, timezone
from telegram import Bot
from telegram.error import TelegramError
import json
import subprocess
import xml.etree.ElementTree as ET
import re
import os
import json


with open('keys.json', 'r', encoding='utf-8') as file:
    data = json.load(file)

TELEGRAM_BOT_TOKEN = data['TELEGRAM_BOT_TOKEN']
TELEGRAM_CHAT_ID = data['TELEGRAM_CHAT_ID']
VIRUSTOTAL_API_KEY = data['VIRUSTOTAL_API_KEY']
MESSAGE_STORAGE_FILE = "pending_messages.json"

# Инициализация бота
bot = Bot(token=TELEGRAM_BOT_TOKEN)
script_start_time = datetime.now() - timedelta(minutes=2)
script_start_time_uts = datetime.now() - timedelta(hours=3) - timedelta(minutes=2)
path_to_this_dir = r'\Users\Oleeeg\PycharmProjects\People_detectioon'



def load_last_record_id(log_type):
    """Загружает последний Record ID из файла для указанного журнала."""
    try:
        with open(f"last_record_id_{log_type}.json", "r") as file:
            return json.load(file).get("last_record_id", 0)
    except (FileNotFoundError, ValueError):
        return 0


def load_pending_messages():
    """Загружает сообщения из файла."""
    if not os.path.exists(MESSAGE_STORAGE_FILE):
        return []

    try:
        with open(MESSAGE_STORAGE_FILE, "r") as file:
            content = file.read()
            if not content.strip():
                return []
            return json.loads(content)
    except (json.JSONDecodeError, Exception) as e:
        print(f"Ошибка при загрузке сообщений: {e}")
        return []


def save_pending_messages(messages):
    """Сохраняет сообщения в файл."""
    try:
        with open(MESSAGE_STORAGE_FILE, "w") as file:
            json.dump(messages, file)
    except Exception as e:
        print(f"Ошибка при сохранении сообщений: {e}")

def clear_pending_messages():
    """Очищает файл с сообщениями."""
    if os.path.exists(MESSAGE_STORAGE_FILE):
        os.remove(MESSAGE_STORAGE_FILE)

def check_virustotal(file_hash):
    """Проверяет хеш файла на VirusTotal."""
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            return f"{result['positives']} из {result['total']} антивирусов обнаружили угрозу"
    return "No results found."

async def send_telegram_message(message):
    """Отправляет сообщение в Telegram или сохраняет его, если нет интернета."""
    try:
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)
        return True
    except TelegramError as e:
        print(f"Ошибка отправки сообщения: {e}")
        return False

async def send_pending_messages():
    """Отправляет накопленные сообщения."""
    messages = load_pending_messages()
    if not messages:
        return

    for message in messages:
        success = await send_telegram_message(message)
        if not success:
            break

    if success:
        clear_pending_messages()


async def monitor_sysmon():
    """Мониторит журнал Sysmon"""
    ps_command = '''
    # ps_command
    $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath '*[System[EventID=1]]' -MaxEvents 50 | 
    ForEach-Object {
    $eventXml = ([xml]$_.ToXml()).Event.EventData.Data
    $props = @{
        TimeCreated = $_.TimeCreated
        ProcessPath = ($eventXml | Where-Object Name -eq "Image").'#text'
        CommandLine = ($eventXml | Where-Object Name -eq "CommandLine").'#text'
        Hash = ($eventXml | Where-Object Name -eq "Hashes").'#text'
    }
    New-Object -TypeName PSObject -Property $props
} | ConvertTo-Json
    '''
    last_event_time = script_start_time - timedelta(hours=99999)
    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command", ps_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await proc.communicate()

            if stderr:
                print(f"PowerShell Error: {stderr.decode()}")
                await asyncio.sleep(10)
                continue

            try:
                events = json.loads(stdout.decode())
                if not isinstance(events, list):
                    events = [events] if events else []

                for event in events:
                    try:
                        uts_time_str = event.get("TimeCreated", "")
                        if not uts_time_str:
                            continue

                        # Парсим время из строки PowerShell
                        timestamp_ms = int(re.search(r'\d+', uts_time_str).group())
                        uts_time = datetime.fromtimestamp(timestamp_ms / 1000.0)
                        # uts_time = datetime.strptime(uts_time_str.split('+')[0], '%m/%d/%Y %H:%M:%S %p')

                        process_path = event.get("ProcessPath", "N/A")
                        command_line = event.get("CommandLine", "N/A")

                        if (
                                (path_to_this_dir in process_path) or
                                ('-FilterXPath' in command_line) or
                                (last_event_time >= uts_time)
                        ):
                                    continue

                        file_hash = event.get("Hash", "N/A").split("SHA256=")[-1]
                        vt_result = await asyncio.to_thread(check_virustotal, file_hash)

                        message = (
                            f"⚠️ Запущен процесс:\n"
                            f"• Путь: {process_path}\n"
                            f"• Аргументы: {command_line}\n"
                            f"• SHA256: {file_hash}\n"
                            f"• VirusTotal: {vt_result}\n"
                            f"• Time: {uts_time}"
                        )

                        success = await send_telegram_message(message)
                        last_event_time = uts_time
                        if not success:
                            messages = load_pending_messages()
                            messages.append(message)
                            save_pending_messages(messages)

                    except Exception as e:
                        print(f"Error processing event: {e}")

            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}, output: {stdout.decode()}")

        except Exception as e:
            print(f"Unexpected error in monitor_sysmon: {e}")

        await asyncio.sleep(1)

async def main():
    await asyncio.gather(
        monitor_security_log(),
        # send_pending_messages(),
        monitor_system_log(),
        monitor_sysmon()
    )


async def monitor_security_log():
    """Мониторит журнал безопасности (Security)."""
    server = 'localhost'
    logtype = 'Security'
    hand = win32evtlog.OpenEventLog(server, logtype)
    login_types = {
        2: 'локальный вход (тип 2)',
        10: 'вход по RDP (тип 10)',
        7: 'разблокировка (тип 7)',
    }
    service_start_types = {
        0: 'запуск загрузчиком системы (тип 0)',
        1: 'запуск драйвера устройства функцией IOInitSystem (тип 1)',
        2: 'автоматический запуск (тип 2)',
        3: 'ручной запуск (тип 3)',
        4: 'отключенная служба (тип 4)',
    }

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        for event in events:
            if event.TimeGenerated < script_start_time:
                continue

            event_id = event.EventID
            time_generated = event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S")
            if event_id == 4624:
                user = event.StringInserts[5]
                login_type = event.StringInserts[8]
                login_type = login_types.get(int(login_type), False)
                if not login_type:
                    continue
                message = f"🔑 Успешный вход! \nПользователь: {user} \nТип: {login_type} \nВремя: {time_generated}."


            elif event_id == 4672:
                user = event.StringInserts[1]
                message = f"🔑 Повышение привилегий! \nПользователь: {user} \nВремя: {time_generated}."
            elif event_id == 4698:
                task_name = event.StringInserts[4]
                namespace = {"ns": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
                task_command = ET.fromstring(event.StringInserts[5]).find(".//ns:Command", namespace).text
                message = f"📅 Создана задача: {task_name} \nКоманда: {task_command} \nВремя: {time_generated}."
            elif event_id == 4697 or event_id == 7045:
                service_name = event.StringInserts[4]
                service_type = event.StringInserts[7]
                service_type = service_start_types.get(int(service_type), service_type)
                message = f"⚙️ Изменена служба: {service_name} \nТип: {service_type} \nВремя: {time_generated}."
            else:
                continue

            success = await send_telegram_message(message)
            if not success:
                messages = load_pending_messages()
                messages.append(message)
                save_pending_messages(messages)

        await asyncio.sleep(1)


async def monitor_system_log():
    """Мониторит журнал безопасности"""
    ps_command = '''
            # ps_command
           $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8

            Get-WinEvent -LogName "System" -FilterXPath '*[System[EventID=6005]]' | 
            ForEach-Object {
                $eventXml = ([xml]$_.ToXml()).Event.EventData.Data
                $props = @{
                    TimeCreated = $_.TimeCreated
                    EventID = $_.Id
                    EventSource = $_.ProviderName
                    Message = $_.Message
                }
                New-Object -TypeName PSObject -Property $props
            } | ConvertTo-Json
           '''
    script_start_time = datetime.now()
    last_event_time = script_start_time - timedelta(minutes=5)
    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command", ps_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if stderr:
                print(f"PowerShell Error: {stderr}")
                continue

            events = json.loads(stdout)
            for event in events:
                time_data = event.get("TimeCreated", {}).strip('/')
                timestamp_ms = int(re.search(r'\d+', time_data).group())
                uts_time = datetime.fromtimestamp(timestamp_ms / 1000.0)
                if not time_data:
                    continue

                event_id = event.get("EventID")
                if event_id == 6005 and uts_time > last_event_time:
                    message = f"🖥 Компьютер включен! Время: {uts_time}."
                    print(message)
                    await send_telegram_message(message)
                    last_event_time = uts_time


        except Exception as e:
            print(f"Ошибка: {str(e)}")
            await asyncio.sleep(1)
        await asyncio.sleep(1)
if __name__ == "__main__":
    asyncio.run(main())