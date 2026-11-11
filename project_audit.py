#!/usr/bin/env python3
"""Offline, non-executing source triage. Python 3.10+, standard library only."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SKIP = {'.git', '.venv', 'venv', 'node_modules', 'vendor', '__pycache__', 'dist', 'build', '.next'}
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.env', '.php', '.rb', '.go', '.java', '.cs', '.sh', '.sql'}
MAX_BYTES = 1_000_000
RULES = [
    ('TLS-VERIFY', 'Medium', r'\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b', 'Отключена проверка TLS', 'Проверьте достижимость настройки в рабочем окружении. Включите проверку сертификата; используйте доверенный CA.', 'Внешняя интеграция может быть уязвима к подмене при наличии сетевого атакующего.'),
    ('JWT-VERIFY', 'High', r'[\x27\x22]verify_signature[\x27\x22]\s*:\s*False\b|\bverify_signature\s*=\s*False\b', 'Отключена проверка подписи JWT', 'Проследите использование результата декодирования. Проверяйте подпись, алгоритм, issuer, audience и срок действия.', 'Если результат используется для авторизации, возможна подделка личности.'),
    ('SHELL', 'High', r'\bshell\s*=\s*True\b', 'Вызов через командную оболочку', 'Проверьте происхождение команды. Передавайте программу и аргументы без shell, ограничьте разрешённые операции.', 'При попадании недоверенных данных возможна командная инъекция.'),
    ('DESERIALIZE', 'High', r'\bpickle\.(?:loads|load)\s*\(', 'Десериализация pickle', 'Установите источник данных. Не принимайте pickle из недоверенных источников; используйте формат данных с валидацией схемы.', 'Недоверенный pickle может выполнить код.'),
    ('EVAL', 'High', r'\beval\s*\(', 'Динамическое выполнение выражения', 'Проследите источник выражения и доступные полномочия. Замените разбором данных или ограниченным набором операций.', 'Недоверенное выражение может привести к выполнению кода.'),
    ('SQL-DYNAMIC', 'High', r'\b(?:execute|executemany)\s*\(\s*f[\x27\x22]', 'SQL сформирован через f-string', 'Проверьте подставляемые значения. Для данных используйте параметры драйвера, для идентификаторов — разрешённый список.', 'При подстановке пользовательского ввода возможна SQL-инъекция.'),
    ('DEBUG', 'Medium', r'\bdebug\s*=\s*True\b', 'Включён debug', 'Проверьте окружение и способ запуска. Отключите debug в рабочем сервисе.', 'Публичный debug может раскрыть внутренние данные или возможности отладчика.'),
    ('DOM-HTML', 'Medium', r'\.innerHTML\s*=', 'Присваивание innerHTML', 'Проследите источник значения и очистку HTML. Для текста используйте textContent; для HTML — подходящий sanitizer.', 'При недоверенном HTML возможен XSS.'),
]
SECRET_ASSIGN = re.compile(r'''(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password|client[_-]?secret)\b\s*[:=]\s*([\x27\x22])([^\x27\x22\r\n]{8,})\1''')
SECRET_TOKEN = re.compile(r'\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')


def is_env_file(path):
    name = Path(path).name.lower()
    return name.startswith('.env') or name.endswith('.env')


def request_env_access(relative):
    if not sys.stdin.isatty():
        return False
    # repr escapes control characters from untrusted filenames in the prompt.
    try:
        answer = input(f'Разрешить чтение env-файла {relative!r} для анализа? '
                       'Значения не попадут в отчёт. [да/нет, по умолчанию нет]: ')
    except EOFError:
        return False
    return answer.strip().lower() in {'да', 'д', 'yes', 'y'}


def scan(root, *, env_approval=None):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Цель должна быть каталогом')
    findings, files, skipped, errors, env_access = [], [], [], [], []
    for current, directories, names in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(directories):
            path = Path(current) / name
            if name in SKIP or path.is_symlink():
                skipped.append({'path': path.relative_to(root).as_posix(), 'reason': 'excluded directory or symlink'})
            else:
                kept.append(name)
        directories[:] = kept
        for name in sorted(names):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.append({'path': relative, 'reason': 'symlink'})
                continue
            if is_env_file(path):
                allowed = env_approval is not None and env_approval(relative) is True
                env_access.append({'path': relative, 'approved': allowed})
                if not allowed:
                    skipped.append({'path': relative, 'reason': 'env access not approved; configuration not checked'})
                    continue
            if path.suffix.lower() not in EXTENSIONS and not is_env_file(path) and name != 'Dockerfile':
                skipped.append({'path': relative, 'reason': 'unsupported file type'})
                continue
            try:
                # O_NOFOLLOW prevents following a replaced final-component symlink.
                if not stat.S_ISREG(path.lstat().st_mode):
                    skipped.append({'path': relative, 'reason': 'not a regular file'})
                    continue
                fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
                with os.fdopen(fd, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        skipped.append({'path': relative, 'reason': 'not a regular file'})
                        continue
                    data = stream.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    skipped.append({'path': relative, 'reason': 'size limit'})
                    continue
                content = data.decode('utf-8')
                if '\x00' in content:
                    skipped.append({'path': relative, 'reason': 'binary content'})
                    continue
            except (OSError, UnicodeError) as exc:
                errors.append({'path': relative, 'reason': type(exc).__name__})
                continue
            files.append({'path': relative, 'sha256': hashlib.sha256(data).hexdigest()})
            for number, line in enumerate(content.splitlines(), 1):
                # Never include source text in output: secrets can occur on any line.
                if SECRET_TOKEN.search(line) or (SECRET_ASSIGN.search(line) and not re.search(r'(?i)example|placeholder|changeme|your[_-]|process\.env|os\.environ', line)):
                    findings.append(finding('SECRET', 'High', relative, number, 'Возможный секрет в исходниках', 'Проверьте, является ли значение секретом. При подтверждении отзовите его, удалите из кода и проверьте историю; используйте хранилище секретов.', 'Возможен доступ с полномочиями утёкшего секрета. Значение не проверялось и не выводится.'))
                if line.lstrip().startswith(('#', '//', '*')):
                    continue
                for rule, severity, pattern, title, fix, impact in RULES:
                    if re.search(pattern, line):
                        findings.append(finding(rule, severity, relative, number, title, fix, impact))
            if path.suffix == '.py':
                try:
                    ast.parse(content)
                except (SyntaxError, ValueError, RecursionError):
                    errors.append({'path': relative, 'reason': 'Python syntax could not be parsed; lexical results only'})
    return {'schema_version': 1, 'mode': 'offline-static-triage', 'root': str(root), 'findings': findings, 'files': files, 'skipped': skipped, 'errors': errors, 'env_access': env_access, 'limitations': ['Все находки — кандидаты для ручной проверки, а не подтверждённые уязвимости.', 'Env-файлы читаются только после отдельного согласия; отказ или отсутствие ответа означает непроверенную конфигурацию.', 'Код, тесты, зависимости и сервисы не запускались; сеть не использовалась.', 'CVE и актуальные версии зависимостей не проверялись.', 'Правила не анализируют потоки данных, авторизацию, бизнес-логику платежей и все языковые конструкции.', 'Проверка не доказывает отсутствие уязвимостей. Используйте неизменяемую копию исходников для защиты от конкурентной подмены файлов.']}


def finding(rule, severity, path, line, title, fix, impact):
    return {'rule': rule, 'severity': severity, 'status': 'requires-review', 'path': path, 'line': line, 'title': title, 'recommendation': fix, 'impact': impact}


def markdown(report):
    def safe(value):
        return str(value).replace('`', '\\`').replace('<', '&lt;').replace('>', '&gt;').replace('\n', ' ').replace('\r', ' ')
    out = ['# SECURITY-REPORT', '', '## Результат', '', f"Прочитано файлов: {len(report['files'])}. Кандидатов: {len(report['findings'])}. Пропущено: {len(report['skipped'])}. Ошибок чтения/разбора: {len(report['errors'])}.", '', '## Ограничения', '']
    out.extend('- ' + item for item in report['limitations'])
    out.extend(['', '## Кандидаты для проверки', ''])
    if not report['findings']:
        out.append('По реализованным правилам кандидатов не найдено. Это не заключение о безопасности проекта.')
    for i, item in enumerate(report['findings'], 1):
        out.extend([f"### SEC-{i:03d} — {item['title']}", '', f"- Правило: {item['rule']}; потенциальная серьёзность: {item['severity']}; статус: требует проверки.", f"- Место: `{safe(item['path'])}:{item['line']}`.", '- Доказательство: совпадение статического шаблона; контекст и достижимость не установлены. Исходная строка скрыта для защиты секретов.', '- Возможные последствия: ' + item['impact'], '- Проверка и исправление: ' + item['recommendation'], '- Проверка исправления: после ручного анализа повторите сканирование и отдельно проверьте поведение регрессионным тестом. Тесты этим инструментом не выполнялись.', ''])
    out.extend(['## Покрытие', ''])
    out.extend(f"- `{safe(item['path'])}` — SHA-256 `{item['sha256']}`" for item in report['files'])
    out.extend(['', '## Пропуски и ошибки', ''])
    out.extend(f"- `{safe(item['path'])}`: {safe(item['reason'])}" for item in report['skipped'] + report['errors'])
    return '\n'.join(out) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--output', required=True, type=Path, help='Новый каталог вне проверяемого проекта')
    args = parser.parse_args()
    root, output = args.project.resolve(), args.output.resolve()
    if output == root or root in output.parents:
        parser.error('--output должен находиться вне проекта')
    if output.exists():
        parser.error('--output уже существует; выберите новый каталог, чтобы сохранить прежние отчёты')
    try:
        report = scan(root, env_approval=request_env_access)
        output.mkdir(parents=True, exist_ok=False)
        (output / 'SECURITY-REPORT.md').write_text(markdown(report), encoding='utf-8')
        (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        parser.exit(2, f'Аудит не завершён: {type(exc).__name__}\n')
    env_skipped = sum(not item['approved'] for item in report['env_access'])
    print(f"Кандидатов: {len(report['findings'])}; ошибок: {len(report['errors'])}; env без согласия: {env_skipped}. Отчёт: {output / 'SECURITY-REPORT.md'}")
    return 2 if report['errors'] else 1 if report['findings'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
