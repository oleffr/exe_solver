import os
import solve
import pefile
import angr
import lief
import subprocess
from colorama import Fore, Style, init

# Инициализация colorama
init(autoreset=True)

def patch_instruction_with_lief(filepath, virtual_address, new_bytes):
    """
    Патчинг бинарного файла с помощью библиотеки lief.
    :param filepath: Путь к PE-файлу
    :param virtual_address: Виртуальный адрес инструкции
    :param new_bytes: Новые байты, которые заменят старые
    """
    try:
        print(f"Загрузка файла {filepath}...")

        # Загружаем файл с помощью pefile
        pe = pefile.PE(filepath)
        print("Файл успешно загружен. Это корректный PE-файл.")

        # Проверяем ImageBase
        image_base = pe.OPTIONAL_HEADER.ImageBase
        print(f"ImageBase: {hex(image_base)}")

        # Ищем секцию, содержащую виртуальный адрес
        section = None
        for sec in pe.sections:
            sec_start = sec.VirtualAddress + image_base
            sec_end = sec_start + sec.Misc_VirtualSize
            if sec_start <= virtual_address < sec_end:
                section = sec
                break

        if not section:
            print(f"Ошибка: Виртуальный адрес {hex(virtual_address)} не найден в секциях PE-файла.")
            return

        # Переводим виртуальный адрес в файловое смещение
        file_offset = (virtual_address - section.VirtualAddress - image_base) + section.PointerToRawData
        print(f"Файловое смещение для патчинга: {hex(file_offset)}")

        # Загружаем файл с помощью lief
        binary = lief.parse(filepath)
        if binary is None:
            print("Ошибка: файл не удалось загрузить с помощью lief. Проверьте формат и доступность файла.")
            return

        # Патчим байты
        print(f"Патчинг файла {filepath} по смещению {hex(file_offset)}...")
        # Обновляем сырые данные файла
        binary.patch_address(file_offset, new_bytes)

        # Сохраняем изменения в новом файле
        patched_filepath = filepath.replace(".exe", "_patched.exe")
        binary.write(patched_filepath)
        print(f"Файл успешно пропатчен. Сохранено как {patched_filepath}.")

        return patched_filepath
    except Exception as e:
        print(f"Ошибка при патчинге: {e}")

def search_for_anti_debug_interrupts(cfg, interrupts, filepath):
    """
    Поиск и (по желанию) патчинг антиотладочных прерываний и инструкций виртуализации с использованием lief.
    """
    print(f"\n{Fore.YELLOW}==================== Поиск антиотладочных прерываний ====================")
    
    # Загружаем бинарный файл с помощью lief
    binary = lief.parse(filepath)
    if not binary:
        print(f"{Fore.RED}[Ошибка] Не удалось загрузить бинарный файл: {filepath}")
        return

    found_interrupts = []
    for func in cfg.functions.values():
        for block in func.blocks:
            block_data = block.bytes  # Получаем байты блока
            if not block_data:
                continue

            for interrupt, description in interrupts.items():
                try:
                    interrupt_bytes = bytes.fromhex(interrupt)
                except ValueError:
                    print(f"{Fore.RED}[Ошибка] Неверный формат данных для инструкции: {interrupt}")
                    continue

                if interrupt_bytes in block_data:
                    block_offset = block.addr - cfg.project.loader.min_addr
                    found_interrupts.append((block.addr, interrupt_bytes, description))
                    print(f"{Fore.YELLOW}  [Найдено антиотладочное прерывание]: {Style.BRIGHT}{description} ")

    if not found_interrupts:
        print(f"{Fore.CYAN}[Информация] Антиотладочные инструкции не найдены.")
        return

    # Спросить пользователя, выполнять ли патчинг
    patch_choice = input(f"{Fore.MAGENTA}Хотите выполнить патчинг найденных инструкций? (да/нет): ").strip().lower()
    if patch_choice in ['да', 'yes', 'y']:
        # Запрос на ввод имени файла для сохранения изменений
        output_filepath = input(f"{Fore.MAGENTA}Введите имя файла для сохранения пропатченного бинарника: ").strip()
        
        print(f"\n{Fore.GREEN}==================== Выполнение патчинга ====================")
        for addr, interrupt_bytes, description in found_interrupts:
            # Патчим найденный участок (заменяем на NOP инструкции)
            nop_bytes = b'\x90' * len(interrupt_bytes)
            nop_list = list(nop_bytes)  # Преобразуем байты в список целых чисел
            binary.patch_address(addr, nop_list)
            print(f"{Fore.GREEN}  [Патч применен]: {description} на {addr:#x}")
        
        # Сохраняем изменения в указанный файл
        try:
            binary.write(output_filepath)
            print(f"{Fore.GREEN}[Успех] Пропатченный файл сохранен в {output_filepath}")
        except Exception as e:
            print(f"{Fore.RED}[Ошибка] Не удалось сохранить файл: {e}")
    else:
        print(f"{Fore.CYAN}[Информация] Патчинг отменен. Вывод завершен.")

def search_for_anti_debug_vm_mechanisms(cfg, filepath):
    """
    Поиск антиотладочных и анти-ВМ механизмов в CFG.
    """
    anti_debug_keywords = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "DebugBreak", "ZwQueryInformationProcess",
        "NtSetInformationThread", "SetThreadContext", "NtClose",
        "NtTerminateProcess", "NtTerminateThread", "NtSuspendThread",
        "RtlQueryEnvironmentVariable", "NtYieldExecution", "GetThreadContext",
        "Wow64GetThreadContext", "ZwGetContextThread", "ZwSetContextThread",
        "NtContinue", "FindWindow", "FindWindowEx", "CreateMutex",
        "GetLastError", "Sleep", "SwitchToThread", "QueryPerformanceCounter",
        "NtQueryObject", "OpenProcess", "OpenThread", "TerminateProcess",
        "GetProcessHeap", "VirtualProtect", "VirtualQuery", "HeapSetInformation",
        "SetUnhandledExceptionFilter", "RaiseException", 
    ]

    anti_vm_keywords = [
    # Виртуальные машины и их компоненты
    "RedPill", "BluePill", "VMware", "VirtualBox", "QEMU", "Xen",
    "Hyper-V", "Parallels", "Virtual PC", "inl", "VMCheck",

    # Характерные вызовы API для обнаружения ВМ
    "GetSystemFirmwareTable", "RegOpenKeyEx", "RegQueryValueEx", 
    "NtQuerySystemInformation", "NtQueryObject", "DeviceIoControl",
    "GetAdapterAddresses", "GetModuleHandleA", "GetProcAddress",

    # Регистры и специфика виртуализации
    "sgdt", "sidt", "sldt", "cpuid", "in", "out",
    "str", "smsw", "rdtsc", "rdpmc", "vmcall", "vmlaunch",
    "vmresume", "vmxoff", "vmxon",

    # Поиск известных драйверов и служб виртуальных машин
    "vmtoolsd.exe", "vmmouse.sys", "vmhgfs.sys", "vm3dmp.dll", 
    "vboxservice.exe", "vboxtray.exe", "vboxguest.sys", 
    "VBoxSF", "VBoxMiniRdr", "VBoxMouse", "VBoxVideo", "VBoxDisp",
    "VBoxGuestAdditions",

    # Дополнительные тесты на ВМ
    "vmware", "vbox", "qemu", "xen", "vmmouse", "virtualbox",
    "svga", "virtual_cdrom", "virtual_storage",
    "SCSI Disk Device", "IDE Disk Device", "VBOX_HARDDISK", 
    "QEMU_HARDDISK", "Xen_HARDDISK", "VMware_Virtual_SCSI_Hard_Drive"
    ]

    anti_debug_interrupts = {
    "CC": "Breakpoint (int 3)",
    "CD03": "Software interrupt (int 3)",
    "F4": "Halt instruction (hlt)",
    "0F0B": "Undefined instruction (ud2)",
    "0F31": "Read timestamp counter (rdtsc)",
    "0F33": "Read performance monitoring counters (rdpmc)",
    "CD2D": "Anti-debug interrupt (int 2d)",
    "0F01D0": "Store Global Descriptor Table Register (sgdt)",
    "0F01D2": "Store Interrupt Descriptor Table Register (sidt)",
    "0F01D4": "Store Local Descriptor Table Register (sldt)",
    "0F01C0": "Store Task Register (str)",
    "0F01F8": "Store Machine Status Word (smsw)",
    "0F01C9": "Virtual Machine Call (vmcall)",
    "0F01C2": "Launch Virtual Machine (vmlaunch)",
    "0F01C3": "Resume Virtual Machine (vmresume)",
    "0F01C4": "Turn off VMX operation (vmxoff)",
    "0F01C5": "Enter VMX operation (vmxon)",
    }

    print(f"\n{Fore.YELLOW}==================== Поиск антиотладочных механизмов ====================")
    for keyword in anti_debug_keywords:
        search_for_specific_mechanisms(cfg, keyword, "антиотладочный механизм")

    print(f"\n{Fore.YELLOW}==================== Поиск анти-ВМ механизмов ====================")
    for keyword in anti_vm_keywords:
        search_for_specific_mechanisms(cfg, keyword, "анти-ВМ механизм")

    print(f"\n{Fore.YELLOW}==================== Поиск антиотладочных прерываний ====================")
    search_for_anti_debug_interrupts(cfg, anti_debug_interrupts, filepath)

def search_for_specific_mechanisms(cfg, keyword, mechanism_type):
    """
    Поиск конкретного механизма в CFG.
    """
    for func in cfg.functions.values():
        if keyword.lower() in func.name.lower():
            print(f"{Fore.YELLOW}  [Найден {mechanism_type}]: {Style.BRIGHT}{keyword} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")

def search_for_output_function_in_cfg(cfg, function_name):
    for func in cfg.functions.values():
        if function_name.lower() in func.name.lower():
            print(f"{Fore.GREEN}  [Найдена функция для вывода]: {Style.BRIGHT}{function_name} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")
        
def search_for_source_function_in_cfg(cfg, function_name):
    """
    Поиск источников данных (source) в CFG.
    """
    for func in cfg.functions.values():
        if function_name.lower() in func.name.lower():
            print(f"{Fore.RED}  [Источник данных (source)]: {Style.BRIGHT}{function_name} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")

def search_for_file_write_function_in_cfg(cfg, function_name):
    for func in cfg.functions.values():
        if function_name.lower() in func.name.lower():
            print(f"{Fore.YELLOW}  [Найдена функция для записи в файл]: {Style.BRIGHT}{function_name} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")

def search_for_network_function_in_cfg(cfg, function_name):
    for func in cfg.functions.values():
        if function_name.lower() in func.name.lower():
            print(f"{Fore.CYAN}  [Найдена сетевая функция]: {Style.BRIGHT}{function_name} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")

def search_for_exec_function_in_cfg(cfg, function_name):
    for func in cfg.functions.values():
        if function_name.lower() in func.name.lower():
            print(f"{Fore.MAGENTA}  [Найден системный вызов]: {Style.BRIGHT}{function_name} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")

def search_for_ipc_function_in_cfg(cfg, function_name):
    for func in cfg.functions.values():
        if function_name.lower() in func.name.lower():
            print(f"{Fore.YELLOW}  [Найден вызов IPC]: {Style.BRIGHT}{function_name} "
                  f"в функции {func.name} - Адрес: {hex(func.addr)}")
            
def analyze_file_info(pe, filepath):
    """
    Вывод основной информации о PE-файле.
    """
    print(f"\n{Fore.GREEN}{Style.BRIGHT}==================== Основная информация о файле ====================")
    print(f"{Fore.CYAN}Файл: {Style.BRIGHT}{filepath}")  # Используем путь к файлу вместо pe.filename
    print(f"{Fore.CYAN}Архитектура: {Style.BRIGHT}{'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
    print(f"{Fore.CYAN}Точка входа: {Style.BRIGHT}0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"{Fore.CYAN}Размер изображений: {Style.BRIGHT}{pe.OPTIONAL_HEADER.SizeOfImage} байт")
    print(f"{Fore.CYAN}Число секций: {Style.BRIGHT}{pe.FILE_HEADER.NumberOfSections}")
    print(f"{Fore.CYAN}Время компиляции: {Style.BRIGHT}{pe.FILE_HEADER.TimeDateStamp}")
    print(f"{Fore.CYAN}Подсистема: {Style.BRIGHT}{pe.OPTIONAL_HEADER.Subsystem}")
    print(f"{Fore.CYAN}DLL характеристики: {Style.BRIGHT}{pe.OPTIONAL_HEADER.DllCharacteristics}")
    
    print(f"{Fore.GREEN}{Style.BRIGHT}==================== Секции файла ====================")
    for section in pe.sections:
        print(f"{Fore.YELLOW}Секция: {Style.BRIGHT}{section.Name.decode().strip()}")
        print(f"  Виртуальный адрес: 0x{section.VirtualAddress:X}")
        print(f"  Размер: {section.Misc_VirtualSize} байт")
        print(f"  Характеристики: 0x{section.Characteristics:X}")

def analyze_cfg(pe_path):
    proj = angr.Project(pe_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    output_functions = [
    "printf",         # Форматированный вывод
    "puts",           # Вывод строки
    "write",          # Запись в файл или поток
    "fprintf",        # Форматированный вывод в файл
    "fputs",          # Вывод строки в файл
    "sprintf",        # Форматированный вывод в строку
    "snprintf",       # Безопасный форматированный вывод в строку
    "vprintf",        # Форматированный вывод с va_list
    "vfprintf",       # Форматированный вывод в файл с va_list
    "vsprintf",       # Форматированный вывод в строку с va_list
    "vsnprintf",      # Безопасный форматированный вывод в строку с va_list
    "putchar",        # Вывод символа
    "putc",           # Вывод символа в файл
    "fwrite",         # Запись данных в файл
    "WriteFile",      # Windows API для записи в файл
    "OutputDebugString", # Вывод отладочной строки
    "MessageBox",     # Отображение окна с сообщением в Windows
    "SendMessage",    # Отправка сообщения (возможно, для вывода информации)
    "printf_s",       # Безопасный printf
    "sprintf_s",      # Безопасный sprintf
    "snprintf_s",     # Безопасный snprintf
    "wprintf",        # Форматированный вывод для широких строк
    "fwprintf",       # Форматированный вывод в файл для широких строк
    "swprintf",       # Форматированный вывод в строку для широких строк
    "vswprintf",      # Форматированный вывод в строку для широких строк с va_list
    ]

    file_write_functions = [
    "fwrite",            # Запись данных в файл (C стандарт)
    "write",             # Запись в файл или поток (POSIX)
    "CreateFile",        # Создание или открытие файла (Windows API)
    "WriteFile",         # Запись данных в файл (Windows API)
    "open",              # Открытие файла (POSIX/C стандарт)
    "close",             # Закрытие файла
    "lseek",             # Изменение позиции в файле
    "pwrite",            # Запись в файл с указанием позиции (POSIX)
    "fopen",             # Открытие файла (C стандарт)
    "fclose",            # Закрытие файла
    "freopen",           # Переоткрытие файла (C стандарт)
    "fseek",             # Изменение позиции в файле (C стандарт)
    "ftell",             # Получение текущей позиции в файле
    "fputc",             # Запись символа в файл
    "fputs",             # Запись строки в файл
    "fprintf",           # Форматированный вывод в файл
    "chmod",             # Изменение прав доступа к файлу
    "ftruncate",         # Укорочение файла до указанного размера (POSIX)
    "CreateFileW",       # Создание файла с поддержкой широких символов (Windows API)
    "OpenFile",          # Открытие файла (Windows API, устаревшая)
    "OpenFileMapping",   # Открытие отображения файла (Windows API)
    "MapViewOfFile",     # Отображение файла в память (Windows API)
    "UnmapViewOfFile",   # Удаление отображения файла из памяти (Windows API)
    "fsync",             # Синхронизация изменений в файле с диском (POSIX)
    "fflush",            # Очистка буфера записи (C стандарт)
    "SetEndOfFile",      # Установить конец файла (Windows API)
    "WriteConsole",      # Запись в консоль (Windows API)
    "WriteProcessMemory",# Запись памяти процесса (Windows API)
    "CopyFile",          # Копирование файлов (Windows API)
    "CopyFileEx",        # Копирование файлов с расширенными опциями (Windows API)
    "NtWriteFile",       # Низкоуровневая запись в файл (Windows Native API)
    "ZwWriteFile",       # Альтернативное название NtWriteFile (Windows Native API)
    ]

    network_functions = [
    "send",             # Отправка данных через сокет (POSIX/Windows API)
    "sendto",           # Отправка данных на конкретный адрес (POSIX)
    "recv",             # Получение данных через сокет (POSIX/Windows API)
    "recvfrom",         # Получение данных с указанием источника (POSIX)
    "socket",           # Создание сокета (POSIX/Windows API)
    "connect",          # Установка соединения через сокет (POSIX/Windows API)
    "accept",           # Принятие входящего соединения (POSIX/Windows API)
    "bind",             # Привязка сокета к адресу (POSIX/Windows API)
    "listen",           # Перевод сокета в режим прослушивания (POSIX/Windows API)
    "gethostbyname",    # Получение IP-адреса по имени хоста (устаревшая POSIX/Windows API)
    "gethostbyaddr",    # Получение имени хоста по IP-адресу (устаревшая POSIX/Windows API)
    "getaddrinfo",      # Получение адресной информации (современный стандарт POSIX/Windows API)
    "freeaddrinfo",     # Освобождение адресной информации
    "inet_ntoa",        # Преобразование адреса из двоичного формата в строку (POSIX/Windows API)
    "inet_aton",        # Преобразование адреса из строки в двоичный формат (POSIX)
    "inet_pton",        # Преобразование адреса из строки в двоичный формат (IPv4/IPv6)
    "inet_ntop",        # Преобразование адреса из двоичного формата в строку (IPv4/IPv6)
    "shutdown",         # Закрытие соединения (POSIX/Windows API)
    "closesocket",      # Закрытие сокета (Windows API)
    "WSAStartup",       # Инициализация сетевого API в Windows
    "WSACleanup",       # Очистка сетевого API в Windows
    "sendmsg",          # Отправка сообщения (POSIX)
    "recvmsg",          # Получение сообщения (POSIX)
    "poll",             # Опрос состояния сокетов (POSIX)
    "select",           # Мультиплексирование ввода/вывода (POSIX/Windows API)
    "setsockopt",       # Установка параметров сокета (POSIX/Windows API)
    "getsockopt",       # Получение параметров сокета (POSIX/Windows API)
    "ioctl",            # Управление параметрами сокета (POSIX)
    "WSAIoctl",         # Управление параметрами сокета (Windows API)
    "getpeername",      # Получение адреса удалённого узла (POSIX/Windows API)
    "getsockname",      # Получение адреса локального сокета (POSIX/Windows API)
    "ntohs",            # Преобразование числа из сетевого в хостовый порядок байтов (POSIX/Windows API)
    "htons",            # Преобразование числа из хостового в сетевой порядок байтов (POSIX/Windows API)
    "ntohl",            # Преобразование числа из сетевого в хостовый порядок байтов (POSIX/Windows API)
    "htonl",            # Преобразование числа из хостового в сетевой порядок байтов (POSIX/Windows API)
    "SSL_connect",      # Установка защищённого соединения (OpenSSL)
    "SSL_accept",       # Принятие защищённого соединения (OpenSSL)
    "SSL_write",        # Отправка данных через защищённое соединение (OpenSSL)
    "SSL_read",         # Получение данных через защищённое соединение (OpenSSL)
    "SSL_shutdown",     # Завершение защищённого соединения (OpenSSL)
    "curl_easy_perform",# Выполнение сетевого запроса (libcurl)
    "libssh2_session_startup", # Инициализация SSH-сессии (libssh2)
    "libssh2_channel_read",    # Чтение данных через SSH-канал (libssh2)
    "libssh2_channel_write",   # Запись данных через SSH-канал (libssh2)
    ]

    exec_functions = [
    "exec",             # Запуск программы (POSIX)
    "execv",            # Запуск программы с массивом аргументов (POSIX)
    "execve",           # Запуск программы с массивом аргументов и окружением (POSIX)
    "execl",            # Запуск программы с указанием аргументов в списке (POSIX)
    "execlp",           # Запуск программы с поиском в PATH (POSIX)
    "execvp",           # Запуск программы с массивом аргументов и поиском в PATH (POSIX)
    "execvpe",          # Запуск программы с массивом аргументов, окружением и поиском в PATH (POSIX)
    "CreateProcess",    # Создание нового процесса (Windows API)
    "CreateProcessA",   # Версия CreateProcess для ANSI-строк (Windows API)
    "CreateProcessW",   # Версия CreateProcess для Unicode-строк (Windows API)
    "WinExec",          # Запуск программы или команды (Windows API)
    "ShellExecute",     # Запуск программы или файла (Windows API)
    "ShellExecuteA",    # Версия ShellExecute для ANSI-строк (Windows API)
    "ShellExecuteW",    # Версия ShellExecute для Unicode-строк (Windows API)
    "system",           # Выполнение команды через системный интерпретатор (POSIX/Windows)
    "popen",            # Открытие потока для выполнения команды (POSIX/Windows)
    "spawn",            # Создание нового процесса (POSIX)
    "spawnl",           # Версия spawn с передачей списка аргументов (POSIX)
    "spawnlp",          # Версия spawn с поиском в PATH (POSIX)
    "spawnv",           # Версия spawn с передачей массива аргументов (POSIX)
    "spawnvp",          # Версия spawn с массивом аргументов и поиском в PATH (POSIX)
    "spawnve",          # Версия spawn с массивом аргументов и окружением (POSIX)
    "spawnvpe",         # Версия spawn с массивом аргументов, окружением и поиском в PATH (POSIX)
    "LoadLibrary",      # Загрузка библиотеки (Windows API)
    "LoadLibraryA",     # Версия LoadLibrary для ANSI-строк (Windows API)
    "LoadLibraryW",     # Версия LoadLibrary для Unicode-строк (Windows API)
    "LoadLibraryEx",    # Загрузка библиотеки с расширенными возможностями (Windows API)
    "dlopen",           # Загрузка динамической библиотеки (POSIX)
    "fork",             # Создание нового процесса (POSIX)
    "vfork",            # Создание нового процесса с оптимизацией (POSIX)
    "clone",            # Создание нового процесса или потока (Linux-specific)
    "CreateThread",     # Создание нового потока (Windows API)
    "RtlCreateUserThread", # Создание пользовательского потока (Windows Native API)
    "QueueUserAPC",     # Добавление функции для выполнения в потоке (Windows API)
    ]

    ipc_functions = [
    # Pipe (каналы)
    "CreatePipe",           # Создание анонимного канала (Windows API)
    "ReadFile",             # Чтение данных из канала (Windows API)
    "WriteFile",            # Запись данных в канал (Windows API)
    "PeekNamedPipe",        # Просмотр содержимого канала без чтения (Windows API)
    "SetNamedPipeHandleState", # Настройка состояния канала (Windows API)
    "CreateNamedPipe",      # Создание именованного канала (Windows API)
    # Shared Memory (общая память)
    "CreateFileMapping",    # Создание объекта отображения файлов (Windows API)
    "OpenFileMapping",      # Открытие объекта отображения файлов (Windows API)
    "MapViewOfFile",        # Отображение области файла в память (Windows API)
    "MapViewOfFileEx",      # Расширенное отображение области файла в память (Windows API)
    "UnmapViewOfFile",      # Снятие отображения области файла (Windows API)
    # Synchronization (синхронизация)
    "CreateMutex",          # Создание объекта синхронизации (мьютекса) (Windows API)
    "OpenMutex",            # Открытие существующего мьютекса (Windows API)
    "ReleaseMutex",         # Освобождение мьютекса (Windows API)
    "CreateEvent",          # Создание объекта события (Windows API)
    "OpenEvent",            # Открытие объекта события (Windows API)
    "SetEvent",             # Установка события (Windows API)
    "ResetEvent",           # Сброс события (Windows API)
    "WaitForSingleObject",  # Ожидание объекта синхронизации (Windows API)
    "WaitForMultipleObjects", # Ожидание нескольких объектов синхронизации (Windows API)
    # Message Passing (обмен сообщениями)
    "PostMessage",          # Отправка сообщения в очередь сообщений (Windows API)
    "SendMessage",          # Отправка сообщения и ожидание ответа (Windows API)
    "BroadcastSystemMessage", # Отправка сообщения всем приложениям (Windows API)
    "RegisterWindowMessage", # Регистрация пользовательского сообщения (Windows API)
    # Sockets & Network IPC (сокеты и сетевая IPC)
    "socket",               # Создание сокета (POSIX/Windows API)
    "bind",                 # Привязка сокета к адресу (POSIX/Windows API)
    "listen",               # Прослушивание подключений (POSIX/Windows API)
    "accept",               # Принятие подключения (POSIX/Windows API)
    "connect",              # Подключение к серверу (POSIX/Windows API)
    "recv",                 # Получение данных (POSIX/Windows API)
    "send",                 # Отправка данных (POSIX/Windows API)
    "shutdown",             # Завершение работы сокета (POSIX/Windows API)
    # Advanced IPC
    "NtCreateSection",      # Создание объекта секции (Windows Native API)
    "NtMapViewOfSection",   # Отображение секции в память (Windows Native API)
    "NtUnmapViewOfSection", # Снятие отображения секции (Windows Native API)
    "NtCreateEvent",        # Создание объекта события (Windows Native API)
    "NtOpenEvent",          # Открытие существующего объекта события (Windows Native API)
    "NtCreateSemaphore",    # Создание семафsора (Windows Native API)
    "NtOpenSemaphore",      # Открытие существующего семафора (Windows Native API)
    ]


    # Объединяем все функции в один набор
    all_sink_functions = set(output_functions + file_write_functions + network_functions + exec_functions + ipc_functions)

    for func in cfg.functions.values():
        for block in func.blocks:
            for insn in block.capstone.insns:  # Проходим по всем инструкциям блока
                if insn.mnemonic == "call":  # Проверяем, является ли инструкция вызовом функции
                    target_addr = insn.op_str  # Адрес или имя вызываемой функции

                    # Проверяем, является ли target_addr числовым адресом
                    if target_addr.startswith("0x"):
                        try:
                            target_addr_int = int(target_addr, 16)
                        except ValueError:
                            continue  # Пропускаем некорректные значения
                    
                        if target_addr_int in cfg.functions:
                            target_func = cfg.functions[target_addr_int]
                            # Выводим только sink-функции
                            if target_func.name in all_sink_functions:
                                print(f"{Fore.RED}Вызов sink-функции: {target_func.name} - Адрес: {hex(target_addr_int)}")
                                print(f"    Адрес вызова: {hex(insn.address)} - Инструкция: {insn.mnemonic} {insn.op_str}")
                                print(f"    Блок вызова: {hex(block.addr)} в функции: {func.name}")
                    else:
                        # Если target_addr — имя функции
                        if target_addr in all_sink_functions:
                            print(f"{Fore.RED}Вызов sink-функции по имени: {target_addr}")
                            print(f"    Адрес вызова: {hex(insn.address)} - Инструкция: {insn.mnemonic} {insn.op_str}")
                            print(f"    Блок вызова: {hex(block.addr)} в функции: {func.name}")


    print("\n==================== Поиск функций для вывода данных ====================")
    for function in output_functions:
        search_for_output_function_in_cfg(cfg, function)
    
    print("\n==================== Поиск функций для записи в файл ====================")

    for function in file_write_functions:
        search_for_file_write_function_in_cfg(cfg, function)
    
    print("\n==================== Поиск сетевых функций ====================")
    
    for function in network_functions:
        search_for_network_function_in_cfg(cfg, function)
    
    print("\n==================== Поиск системных вызовов ====================")
    
    for function in exec_functions:
        search_for_exec_function_in_cfg(cfg, function)
    
    print("\n==================== Поиск IPC функций ====================")
    
    
    sinks = []
    for function in ipc_functions:
        for func in cfg.functions.values():
            if function.lower() in func.name.lower():
                sinks.append(func.addr)
                print(f"{Fore.GREEN}  [Приемник данных (sink)]: {Style.BRIGHT}{function} "
                      f"в функции {func.name} - Адрес: {hex(func.addr)}")

    return sinks

def analyze_sources(pe_path):
    """
    Анализ источников данных.
    """
    proj = angr.Project(pe_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    source_functions = [
    # Стандартные функции ввода (Standard Input)
    "scanf",         # Чтение форматированных данных из stdin
    "fscanf",        # Чтение форматированных данных из файла
    "gets",          # Чтение строки из stdin (небезопасно)
    "fgets",         # Чтение строки из файла (безопаснее, чем gets)
    "sscanf",        # Чтение данных из строки
    "cin",           # Чтение с использованием потоков C++
    "istream::getline", # Чтение строки из потока C++
    # Функции чтения из файлов (File Input)
    "ReadFile",      # Чтение данных из файла (Windows API)
    "fread",         # Чтение блока данных из файла
    "open",          # Открытие файла (POSIX)
    "read",          # Чтение данных из файла (POSIX)
    "pread",         # Чтение с указанием смещения (POSIX)
    # Функции чтения из сети (Network Input)
    "recv",          # Получение данных из сокета
    "recvfrom",      # Получение данных с указанием источника
    "recvmsg",       # Получение сообщения из сокета
    "WSARecv",       # Получение данных через сокет (Windows API)
    # Функции работы с общей памятью (Shared Memory)
    "MapViewOfFile",       # Чтение из общей памяти (Windows API)
    "shmat",               # Присоединение к разделяемой памяти (POSIX)
    "mmap",                # Чтение через отображение файлов в память (POSIX)
    # Функции для чтения данных окружения (Environment Input)
    "getenv",        # Получение значения переменной окружения
    "GetEnvironmentVariable", # Windows API для получения переменных окружения
    "getpwuid",      # Получение информации о пользователе
    "getgrgid",      # Получение информации о группе
    # Специфические функции для драйверов и низкоуровневого ввода
    "DeviceIoControl",   # Управление устройствами и чтение данных (Windows API)
    "ioctl",             # Управление устройствами (POSIX)
    "NtReadFile",        # Нативное чтение из файла (Windows Native API)
    # Функции работы с базами данных (Database Input)
    "sqlite3_exec",       # Выполнение запросов к SQLite
    "mysql_query",        # Запросы к MySQL
    "PQexec",             # Запросы к PostgreSQL
    "OCIStmtExecute",     # Запросы к Oracle
    "MongoDB_read",       # Обращение к данным MongoDB
    # Функции работы с пользовательским вводом
    "readline",           # Чтение строки с обработкой истории
    "kbhit",              # Проверка наличия ввода с клавиатуры
    "getch",              # Получение символа без ожидания Enter
    "GetAsyncKeyState",   # Windows API для получения состояния клавиш
    ]
    sources = []
    for function in source_functions:
        for func in cfg.functions.values():
            if function.lower() in func.name.lower():
                sources.append(func.addr)
                print(f"{Fore.RED}  [Источник данных (source)]: {Style.BRIGHT}{function} "
                      f"в функции {func.name} - Адрес: {hex(func.addr)}")

    return sources

def find_paths_with_addresses(cfg, sources, sinks):
    """
    Находит пути между источниками (sources) и приемниками (sinks) с выводом адресов переходов.
    """
    print(f"\n{Fore.BLUE}==================== Поиск путей между source и sink ====================")
    for source in sources:
        for sink in sinks:
            try:
                # Получаем путь (sequence of basic blocks) между source и sink
                path = cfg.get_any_path(source, sink)
                if path:
                    print(f"{Fore.GREEN}Путь найден: {Style.BRIGHT}{hex(source)} -> {hex(sink)}")
                    print("Адреса переходов:")
                    for block in path:
                        print(f"  Блок: {hex(block.addr)} -> Следующий блок: {hex(block.successors[0].addr) if block.successors else 'None'}")
            except Exception as e:
                print(f"{Fore.RED}[Ошибка] Не удалось найти путь от {hex(source)} до {hex(sink)}: {e}")

def analyze_anti_debug_vm(pe_path):
    """
    Запуск анализа антиотладочных и анти-ВМ механизмов.
    """
    proj = angr.Project(pe_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    search_for_anti_debug_vm_mechanisms(cfg, pe_path)

def menu():
    while True:
        print(f"{Fore.CYAN}{Style.BRIGHT}==================== Меню программы ====================")
        print("1. Выполнить статический анализ (поиск sink) ")
        print("2. Выполнить анализ источников данных (поиск source) ")
        print("3. Выполнить анализ антиотладочных и анти-ВМ механизмов файла")
        print("4. Выполнить полный анализ")
        print("5. Символьный анализ (через triton)")
        print("0. Выход")
        print("========================================================")

        choice = input("Выберите пункт меню: ")
        if choice in ["1", "2", "3", "4", "5"]:
            exe_path = input("Введите путь к EXE файлу для анализа: ")
            if not os.path.exists(exe_path):
                print(f"{Fore.RED}[Ошибка] Файл {exe_path} не найден.")
                continue

            if choice == "5":
                print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== Поиск решения через символьный анализ {exe_path} ====================")
                script_path = "solve.py"
                subprocess.run(["python", script_path, exe_path])
            else:
                try:
                    pe = pefile.PE(exe_path)
                except pefile.PEFormatError:
                    print(f"{Fore.RED}[Ошибка] Файл {exe_path} не является корректным PE-файлом.")
                    continue

                if choice == "1":
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== Статический анализ файла {exe_path} ====================")
                    analyze_cfg(exe_path)  # Вызов функции для статического анализа
                elif choice == "2":
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== Анализ источников данных файла {exe_path} ====================")
                    analyze_sources(exe_path)  
                elif choice == "3":
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== Анализ антиотладочных и анти-ВМ механизмов файла {exe_path} ====================")
                    analyze_anti_debug_vm(exe_path)     
                elif choice == "4":
                    print(f"\n{Fore.WHITE}{Style.BRIGHT}==================== Полный анализ файла {exe_path} ====================")
                    analyze_file_info(pe, exe_path)  # Передаем путь к файлу для отображения
                    analyze_cfg(exe_path)
                    analyze_sources(exe_path)
                    analyze_anti_debug_vm(exe_path)
                    script_path = "solve.py"
                    subprocess.run(["python", script_path, exe_path])
        elif choice == "0":
            print("Выход из программы.")
            break
        else:
            print(f"{Fore.RED}[Ошибка] Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    menu()
