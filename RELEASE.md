# Инструкция по созданию релиза

## Создание тега релиза

### Шаг 1: Создайте тег локально

```bash
# Аннотированный тег (рекомендуется)
git tag -a v1.0.0 -m "Release v1.0.0: Описание изменений"

# Или легковесный тег
git tag v1.0.0
```

**Формат версий:**
- `v1.0.0` - первый стабильный релиз
- `v1.0.1` - патч (исправления багов)
- `v1.1.0` - минорное обновление (новые функции)
- `v2.0.0` - мажорное обновление (breaking changes)

### Шаг 2: Отправьте тег на GitHub

```bash
# Отправить один тег
git push origin v1.0.0

# Или отправить все теги
git push origin --tags
```

### Шаг 3: Проверьте установку

После отправки тега, `@latest` должен заработать:

```bash
go install github.com/t-i-r-e-l/eget/cmd/server@latest
go install github.com/t-i-r-e-l/eget/cmd/client@latest
```

## Создание релиза на GitHub (опционально)

1. Перейдите на страницу релизов: https://github.com/t-i-r-e-l/eget/releases
2. Нажмите "Draft a new release"
3. Выберите созданный тег (например, `v1.0.0`)
4. Заполните:
   - **Title:** `v1.0.0` или `Release v1.0.0`
   - **Description:** Описание изменений (можно использовать changelog)
5. Нажмите "Publish release"

## Примеры команд

```bash
# Создать и отправить тег v1.0.0
git tag -a v1.0.0 -m "Release v1.0.0: Initial release"
git push origin v1.0.0

# Создать и отправить тег v1.0.1
git tag -a v1.0.1 -m "Release v1.0.1: Bug fixes"
git push origin v1.0.1

# Просмотреть все теги
git tag -l

# Просмотреть информацию о теге
git show v1.0.0

# Удалить тег (если нужно)
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
```

## Changelog для релиза

Пример описания для GitHub Release:

```markdown
## Что нового в v1.0.0

### Основные функции
- HTTP/HTTPS туннелирование SOCKS5 трафика
- AES-GCM шифрование
- Гибкая маршрутизация по доменам
- Поддержка множественных upstream

### Установка

```bash
go install github.com/t-i-r-e-l/eget/cmd/server@latest
go install github.com/t-i-r-e-l/eget/cmd/client@latest
```

### Документация

См. [README.md](README.md) и [INSTALL.md](INSTALL.md) для подробной информации.
```

