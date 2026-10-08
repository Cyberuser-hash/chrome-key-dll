# chrome_key.dll

Автономная x64 DLL для извлечения **мастер-ключей App-Bound Encryption (ABE)** из браузеров на Chromium: **Google Chrome, Chrome Beta, Microsoft Edge (включая Copilot-ключ), Brave, Avast Secure Browser**.

Ключ возвращается в виде hex-строки (64 символа) — тот же ключ, который браузер использует для защиты паролей/куки в `Local State`.

> DLL **не** содержит функций расшифровки данных (паролей, cookie и т.п.) — только добыча мастер-ключей.

## Как это работает

При вызове экспортируемой функции из приложения DLL:

1. Находит процесс целевого браузера (или запускает его в suspended-режиме и убивает после получения ключа);
2. Инжектит саму себя в процесс браузера (`CreateRemoteThread` + `LoadLibraryW`);
3. Уже внутри браузера читает `<User Data>\Local State` и вызывает COM Elevator (`DecryptData`) — официальный механизм браузера для расшифровки ABE-ключа;
4. Возвращает ключ hex-строкой через именованный канал.

Если браузер уже запущен — инжект идёт в живой процесс; ключ можно запрашивать многократно.

## Использование

Положить `chrome_key.dll` рядом с исполняемым exe.

```cpp
#include <windows.h>
#include <cstdio>

using GetKeyFn = int(__cdecl*)(char* out, int cap);
using GetErrFn = int(__cdecl*)(char* out, int cap);

int main()
{
    HMODULE h = LoadLibraryW(L"chrome_key.dll");
    if (!h) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }

    auto GetChromeKey = (GetKeyFn)GetProcAddress(h, "GetChromeKeyHex");
    auto GetLastErr   = (GetErrFn)GetProcAddress(h, "GetLastKeyError");

    char key[128] = {};
    if (GetChromeKey(key, sizeof key) == 1) {
        printf("Master key: %s\n", key);          // напр. DDD7069C...880CC
    } else {
        char err[512] = {};
        GetLastErr(err, sizeof err);
        printf("Error: %s\n", err);
    }

    FreeLibrary(h);
    return 0;
}
```

Альтернатива — линковка через `chrome_key.lib`:

```cpp
extern "C" {
    int __cdecl GetChromeKeyHex(char* out, int cap);
    int __cdecl GetChromeBetaKeyHex(char* out, int cap);
    int __cdecl GetBraveKeyHex(char* out, int cap);
    int __cdecl GetEdgeKeyHex(char* out, int cap);
    int __cdecl GetEdgeCopilotKeyHex(char* out, int cap);
    int __cdecl GetAvastKeyHex(char* out, int cap);
    int __cdecl GetLastKeyError(char* out, int cap);
}
// cl myapp.cpp /EHsc /link chrome_key.lib
```

## Экспорты

| Функция | Что возвращает |
|---|---|
| `GetChromeKeyHex` | мастер-ключ Chrome |
| `GetChromeBetaKeyHex` | мастер-ключ Chrome Beta |
| `GetBraveKeyHex` | мастер-ключ Brave |
| `GetEdgeKeyHex` | мастер-ключ Edge |
| `GetEdgeCopilotKeyHex` | aster-ключ Edge (Copilot) |
| `GetAvastKeyHex` | мастер-ключ Avast |
| `GetLastKeyError` | текст ошибки последнего вызова |

`out` — буфер вызывающего (нужен минимум 66 байт для ключа), `cap` — его размер. Ключ — NUL-terminated hex-строка.

## Коды возврата

| Код | Значение |
|---|---|
| `1` | успех, ключ в `out` |
| `0` | неверные аргументы (например, `cap < 65`) |
| `-1` | браузер не найден / не запустился |
| `-2` | архитектура процесса не x64 |
| `-3` | ошибка инъекции (детали в `GetLastKeyError`) |
| `-4` | нет ответа от модуля внутри браузера |
| `-5` | ошибка извлечения ключа (детали в `GetLastKeyError`) |

## Сборка

Нужен Visual Studio (x64) — открыть **x64 Native Tools Command Prompt** и выполнить:

```
build.bat
```

Результат — `chrome_key.dll` + `chrome_key.lib` в текущей папке. Прекомпилированная DLL уже лежит рядом.

## Требования и заметки

- Windows 10/11 **x64**, вызывающее приложение тоже x64.
- Целевой браузер должен быть установлен (путь определяется через реестр).
- Ключ действителен, пока браузер не перезапущен (хранится в памяти процесса).
- Если браузер запускался DLL в suspended-режиме — он завершается после получения ключа. Если браузер уже работал — DLL остаётся загруженной в нём (резондер бездействует на именованном канале до следующего запроса).
- Зависимости: только системные DLL Windows (CRT статический, `/MT`).

## Структура

```
chrome_key.dll / chrome_key.lib   — готовые бинарники
build.bat                         — автономная сборка
src/keydll/                       — экспорт- API + инъекция/клиент канала + резпондер
src/com/                          — COM Elevator (DecryptData)
src/core/, src/payload/           — общие заголовки (пути/CLSID браузеров)
```
## P.S Огромное спасибо opensource сообществу и лично `https://github.com/xaitax/` за исходники.
