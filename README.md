# DDD — Doomsday Detector

Консольная проверка `javaw.exe` под Doomsday. Windows, запуск от имени администратора.

Один скан: сигнатуры в памяти и имена классов из JVM.

## Что проверяет

- 46 сигнатур из `data/signatures.json` в памяти `javaw.exe`. База вшита в exe через `include_str!`.
- Имена классов из живой JVM: явный рандом (`v5wx2kx`), рандомный короткий пакет с хаотичным именем (`2h73/KUOW...`), vanilla-маскировка (аномальная плотность коротких имён в начале списка). Vanilla-маскировка считается красным светом.

Дамп классов на диск не пишется. Системные службы не сканируются.

## Сборка

```
cargo build --release
```

Результат: `target\release\ddd.exe`.

## Готовый билд

`ddd.exe` для Windows x64: [Releases](https://github.com/glassprincess/DoomsdayDetector3000/releases).

SHA-256:

```
AFAB1576CA86738B221679652BDE0F396F386B778F588F182088411F9B4DC417  ddd.exe
```

Сверка в PowerShell:

```
Get-FileHash .\ddd.exe -Algorithm SHA256
```

Хеш должен совпасть с указанным выше.
