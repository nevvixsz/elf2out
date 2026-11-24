# elf2out — ELF → `.out` для 9front

`elf2out` — автономная утилита на Rust (без внешних crate'ов), которая берёт
статический ELF-исполняемый файл, собранный из Zig без libc, и собирает из него
нативный исполняемый файл Plan 9 / 9front формата `a.out(6)`.

Поддерживаются целевые архитектуры:

| ELF `e_machine` | Выходной формат | Magic | Выравнивание данных | Размер заголовка |
|-----------------|-----------------|-------|---------------------|------------------|
| `EM_X86_64` (62) | amd64 | `S_MAGIC` = `0x8a97` | 2 МиБ | 40 байт |
| `EM_AARCH64` (183) | arm64 | `R_MAGIC` = `0x8c47` | 64 КиБ | 40 байт |
| `EM_386` (3) | i386 | `I_MAGIC` = `0x1eb` | 4 КиБ | 32 байта |
| `EM_ARM` (40) | arm | `E_MAGIC` = `0x647` | 4 КиБ | 32 байта |

## ⚠️ Важно: контейнер ≠ ABI

Утилита переводит **формат файла**. Она не может превратить программу, которая
вызывает **Linux-системные вызовы**, в программу для 9front:

* у Linux `syscall`: номер в `RAX`, аргументы в `RDI/RSI/RDX/R10/R8/R9`;
* у 9front amd64 `SYSCALL`: номер в `RBP`, аргументы лежат на стеке по
  `RSP+8`, `RSP+16`, …; результат в `RAX`. Номера вызовов тоже другие
  (`_WRITE = 20`, `EXITS = 8`, … — см. `sys/src/libc/9syscall/sys.h`).
* стек на входе в программу у 9front другой (`argc`, `argv[]`, `Tos`), а не
  Linux `auxv`/`envp`;
* TLS, сигналы, `fork`, `mmap`, `/proc` и т.п. у 9front свои.

Поэтому **правильный рецепт**: freestanding Zig-код, свои обёртки syscall под
9front, `-fPIE`, сборка ELF как промежуточного звена, затем `elf2out`.
Готовый минимальный пример — [`examples/hello9.zig`](examples/hello9.zig).
Если просто сконвертить `zig build-exe main.zig -target x86_64-linux-musl` с
обычным `std.posix.write`, файл получится корректным a.out, но при запуске
упадёт: первое же обращение к Linux-syscall уйдёт в несуществующий номер
9front-системного вызова.

## Сборка

```sh
cargo build --release
# бинарник: target/release/elf2out
```

Rust 1.70+, без сетевых зависимостей (`Cargo.toml` не содержит зависимостей).

## Использование

```sh
./target/release/elf2out -v -o hello9.out hello9.elf
# или
./target/release/elf2out hello9.elf      # получится hello9.elf.out

# модель работы без записи файла:
./target/release/elf2out --dry-run hello9.elf
```

Опции:

```
-o, --output <FILE>   имя выходного .out (по умолчанию <input>.out)
-a, --arch <ARCH>     amd64 | arm64 | 386 | arm (по умолчанию из e_machine)
    --entry <ADDR>    переопределить виртуальный адрес точки входа
    --base <ADDR>     принудительно разместить первый байт ELF по этому адресу
    --symbols         конвертировать символы ELF в символьную таблицу Plan 9
    --patch-abs       эвристически залатать абсолютные адреса в non-PIE ELF
    --ignore-tls      не предупреждать про ELF TLS
    --dry-run         только напечатать раскладку
-v, --verbose         подробный отчёт
-h, --help
-V, --version
```

Адреса принимаются в десятичном и `0x`-шестнадцатеричном виде.

### Рекомендованная сборка Zig

```sh
zig build-exe main.zig \
  -target x86_64-linux-musl \
  -OReleaseSmall \
  -fPIE \
  -fno-entry -fentry=_start \
  -femit-bin=main.elf

elf2out -v -o main.out main.elf
chmod +x main.out
```

* `-fPIE` (в Zig — именно `-fPIE`, а не `-pie`) даёт `ET_DYN` и таблицу
  `R_X86_64_RELATIVE`. `elf2out` применяет эти релокации сам, поэтому
  адреса (GOT, указатели на функции, строки) будут правильными после переноса
  образа по другому адресу.
* `-fno-entry -fentry=_start` убирает стандартный Linux `_start`, который
  разбирает auxv и вызывает `exit_group`.
* Не используйте `std.fs`, `std.process`, `std.Thread`, `std.heap.page_allocator`
  и другие части `std`, которые опираются на Linux-ABI. `brk` в 9front есть
  (`BRK_` = 24), но поведение другое.
* TLS в 9front работает через собственный регистр/слот `Tos`; ELF `.tbss`
  просто включится в образ, но его семантика не сохранится. Утилита предупредит.

### Что внутри: раскладка 9front a.out

Ядро 9front (`sys/src/9/port/sysproc.c`, функция `sysexec`) читает 32-байтный
заголовок `Exec` в **big endian** и для `HDR_MAGIC` ещё 8 байт виртуального
`entry`. Текст отображается с `UTZERO` (0x200000 на amd64), а данные начинаются
с ближайшего граничного адреса, выровненного по `INITRND` (2 МиБ на amd64).

Пусть:

* `first` — младший `p_vaddr` среди `PT_LOAD`;
* `split` — младший `p_vaddr` среди writable `PT_LOAD`;
* `H` — размер заголовка a.out (40 для amd64/arm64);
* `A` — выравнивание данных (2 МиБ для amd64).

`elf2out` выбирает "`pad`" так, чтобы после переноса образа на `X = UTZERO+H+pad`
адрес данных `split + (X - first)` был кратен `A`:

```
pad = (-(split - first + UTZERO + H)) mod A
bias = X - first
aout.text = pad + (split - first)
aout.entry = elf.e_entry + bias    (64-битное поле в расширенном заголовке)
```

Всё, что лежит до `split`, попадает в текстовый сегмент, всё после — в
сегмент данных; `.bss` ELF превращается в поле `bss`. Один и тот же `bias`
применяется ко всему образу, поэтому RIP-relative инструкции остаются
рабочими. Для `ET_EXEC` с абсолютными адресами без релокаций такой сдвиг опасен —
поэтому утилита потребует `-fPIE` либо явно указанный `--patch-abs`.

Формат заголовка (все u32 big-endian):

```
magic, text, data, bss, syms, entry(phys), spsz, pcsz
[если HDR_MAGIC: entry(u64, virtual)]
далее: text bytes, data bytes, symbols
```

Символьная таблица (опция `--symbols`) записывается в формате, который читает
`sys/src/libmach/sym.c`: `u64 value (BE)`, `type | 0x80`, имя с NUL.

## Проверка на 9front

```sh
# на 9front
cpu% chmod +x /tmp/hello9.out
cpu% /tmp/hello9.out
hello from zig on 9front
cpu% file /tmp/hello9.out   # должен показать "amd64 plan 9 executable"
```

Если ядро говорит `exec: bad executable`:

1. проверьте `readelf -lW input.elf` — должны быть `PT_LOAD` и не должно быть
   `PT_INTERP`;
2. проверьте `elf2out -v` — `entry` обязан попадать в диапазон text;
3. для `ET_EXEC` добавьте `--patch-abs` или пересоберите с `-fPIE`.

## Ограничения

* Динамическая линковка (`DT_NEEDED`, `PT_INTERP`) не поддерживается.
* `R_*_IRELATIVE` (IFUNC), `R_*_COPY`, TLS-релокации не поддерживаются — это
  требует загрузчика.
* `--patch-abs` — эвристика: он патчит `mov $imm, reg`, `movabs`, `push $imm`,
  `mov $imm, mem` и выровненные указатели в данных. Это не замена настоящим
  релокациям; предпочитайте `-fPIE`.
* Конвертер не эмулирует Linux-syscalls и не «приклеивает» рантайм 9front.
* Для arm64/386/arm формат заголовка выбран по исходникам 9front, но проверка
  загрузки на реальном железе/QEMU 9front не проводилась в этом окружении.

## Исходные данные по формату

* `9front/sys/include/a.out.h` — magic и `struct Exec`;
* `9front/sys/src/9/port/sysproc.c` — `sysexec()`, проверки заголовка и layouts;
* `9front/sys/src/cmd/6l/obj.c` и `asm.c` — `HEADR = 32+8`, `INITTEXT = 0x200000+HEADR`,
  `INITRND = 0x200000`, запись `entry`;
* `9front/sys/src/libmach/sym.c` — формат символьной таблицы;
* `9front/sys/src/libc/9syscall/mkfile` и `amd64/include/ureg.h` — syscall ABI.

## Тесты

```sh
cargo test
```

Тесты покрывают парсер ELF, big-endian запись заголовка, расчёт `pad`/bias,
релокации, патчер абсолютных адресов и разбор аргументов командной строки.
