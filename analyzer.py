import re
from dataclasses import dataclass


# ponytail: Simple regex heuristics engine with 8 core patterns. Add AST/LLM stacktrace parsing when pattern coverage drops below 80%.
@dataclass
class Issue:
    id: str
    title: str
    severity: str  # CRITICAL, ERROR, WARNING
    cause: str
    solution: str


RULES = [
    {
        "id": "eula_not_accepted",
        "pattern": re.compile(
            r"You need to agree to the EULA in order to run the server", re.IGNORECASE
        ),
        "title": "Не принято соглашение EULA",
        "severity": "CRITICAL",
        "cause": "В файле eula.txt параметр eula установлен в false.",
        "solution": "Откройте файловый менеджер в панели Mars Host, найдите eula.txt и смените на eula=true.",
    },
    {
        "id": "port_bind_failure",
        "pattern": re.compile(
            r"(FAILED TO BIND TO PORT|Address already in use: bind|BindException: Address already in use)",
            re.IGNORECASE,
        ),
        "title": "Порт уже занят (Port Bind Failure)",
        "severity": "CRITICAL",
        "cause": "Выделенный порт сервера занят зависшим процессом или контейнером.",
        "solution": "1. Перезапустите сервер через панель управления.\n2. Проверьте параметр server-port в server.properties.",
    },
    {
        "id": "java_version_mismatch",
        "pattern": re.compile(
            r"has been compiled by a more recent version of the Java Runtime \(class file version (\d+\.\d+)\), this version of the Java Runtime only recognizes class file versions up to (\d+\.\d+)",
            re.IGNORECASE,
        ),
        "title": "Несовместимость версии Java",
        "severity": "CRITICAL",
        "cause": "Ядро или плагин требуют более свежую версию Java Runtime.",
        "solution": "В настройках сервера в панели Mars Host выберите Java 21 (или требуемую версию).",
    },
    {
        "id": "oom_heap",
        "pattern": re.compile(
            r"(java\.lang\.OutOfMemoryError:\s*Java heap space|Out of memory: Kill process)",
            re.IGNORECASE,
        ),
        "title": "Нехватка оперативной памяти (Heap OOM)",
        "severity": "CRITICAL",
        "cause": "Сервер потребил всю выделенную оперативную память (Heap Space).",
        "solution": "1. Увеличьте объем RAM кнопкой 'Улучшить' в панели Mars Host.\n2. Уменьшите view-distance до 4-6 чанков или удалите ресурсоемкие плагины.",
    },
    {
        "id": "oom_metaspace",
        "pattern": re.compile(
            r"java\.lang\.OutOfMemoryError:\s*Metaspace", re.IGNORECASE
        ),
        "title": "Переполнение памяти классов (Metaspace)",
        "severity": "CRITICAL",
        "cause": "Загружено слишком много классов плагинов, исчерпан лимит Metaspace JVM.",
        "solution": "Удалите избыточные плагины или увеличьте лимит RAM сервера.",
    },
    {
        "id": "missing_plugin_dependency",
        "pattern": re.compile(
            r"(?:Could not load '[^']*' in folder 'plugins'|UnknownDependencyException|Plugin '[^']+' requires|depends on: )",
            re.IGNORECASE,
        ),
        "title": "Отсутствует зависимость плагина",
        "severity": "ERROR",
        "cause": "Плагин требует наличие базовой библиотеки (Vault, ProtocolLib, PlaceholderAPI и др.).",
        "solution": "Установите недостающие зависимые плагины через вкладку 'Плагины' в панели управления.",
    },
    {
        "id": "corrupted_chunk",
        "pattern": re.compile(
            r"(Chunk file at .*? is in the wrong location|Corrupt chunk detected|RegionFileException|Corrupted chunk data)",
            re.IGNORECASE,
        ),
        "title": "Повреждение файлов мира (Corrupted Region)",
        "severity": "CRITICAL",
        "cause": "Аварийная остановка повредила .mca файл региона карты.",
        "solution": "1. Восстановите мир из бэкапа в панели Mars Host.\n2. Либо удалите поврежденный файл региона из папки world/region/.",
    },
    {
        "id": "sqlite_db_locked",
        "pattern": re.compile(
            r"(database is locked|sqlite3\.OperationalError:\s*database is locked)",
            re.IGNORECASE,
        ),
        "title": "База данных заблокирована (SQLite Lock)",
        "severity": "ERROR",
        "cause": "Параллельные потоки плагинов заблокировали файл SQLite.",
        "solution": "Перезапустите сервер или переключите плагины на внешний MySQL/PostgreSQL.",
    },
]


def analyze_log(text: str) -> list[Issue]:
    issues: list[Issue] = []
    seen = set()
    for rule in RULES:
        if rule["id"] in seen:
            continue
        # @ts-ignore : mypy is complaining about object typed rules, just cast it or use a proper TypeDict
        if rule["pattern"].search(text):  # type: ignore
            seen.add(rule["id"])
            issues.append(
                Issue(
                    id=str(rule["id"]),
                    title=str(rule["title"]),
                    severity=str(rule["severity"]),
                    cause=str(rule["cause"]),
                    solution=str(rule["solution"]),
                )
            )
    return issues


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Detect common Minecraft server log issues via regex heuristics."
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        type=argparse.FileType("r", encoding="utf-8", errors="replace"),
        default=sys.stdin,
        help="Path to log file or '-' for stdin (default: stdin).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    args = parser.parse_args()
    text = args.logfile.read()
    issues = analyze_log(text)
    if args.format == "json":
        import json

        json.dump(
            [i.__dict__ for i in issues],
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        if not issues:
            print("No issues detected.")
        for i in issues:
            print(f"[{i.severity}] {i.id}: {i.title}")
            print(f"  cause: {i.cause}")
            print(f"  fix:   {i.solution}")
    # ponytail: smoke check survives — keep a sentinel assertion in the CLI path.
    sample = "java.lang.OutOfMemoryError: Java heap space\nAddress already in use: bind"
    assert len(analyze_log(sample)) == 2
