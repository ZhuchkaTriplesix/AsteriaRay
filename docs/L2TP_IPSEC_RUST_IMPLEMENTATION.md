# Спецификация реализации автономного L2TP/IPsec клиента на Rust для AsteriaRay

## 1. Введение и цели

Данный документ описывает архитектуру, протокольный стек и план интеграции автономного **Userspace L2TP/IPsec клиента** на **Rust** (`asteriaray-l2tp`) в VPN-клиент AsteriaRay.

### Почему автономный Userspace демон на Rust?
* **Независимость от ОС и дистрибутива:** В отличие от использования системных демонов (`xl2tpd`, `strongswan`, `pppd`), пользователю не требуется ничего доустанавливать. Демон поставляется единым статическим бинарником в составе бандла AsteriaRay (по аналогии с `xray` и `amneziawg-go`).
* **Нулевая зависимость от модулей ядра:** Работает полностью в пространстве пользователя через виртуальный TUN-интерфейс (`/dev/net/tun`).
* **Повторное использование кода:** Основное ядро протоколов (IKEv1 + L2TPv2 + PPP) может быть скомпилировано под Android NDK (`cargo-ndk`) через JNI, что решает проблему удаления поддержки L2TP из Android 12+.
* **Надежность и безопасность памяти:** Rust гарантирует безопасность работы с сырыми сетевыми пакетами и криптографическими примитивами без риска buffer overflow или use-after-free.

---

## 2. Архитектура сетевого стека

Туннель L2TP/IPsec строится из четырёх уровней инкапсуляции:

```
+-------------------------------------------------------------+
|               Приложения ОС / Трафик системы               |
+-------------------------------------------------------------+
                              |
                     [TUN Device: asteria-l2tp0]
                              |
+-------------------------------------------------------------+
| 1. PPP (Point-to-Point Protocol, RFC 1661)                  |
|    - LCP (0xC021): Согласование параметров канала (MRU)     |
|    - MS-CHAPv2 (0xC223): Аутентификация пользователя        |
|    - IPCP (0x8021): Согласование IP-адресов и DNS           |
|    - IPv4 (0x0021): Сырые IP-пакеты трафика                 |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 2. L2TPv2 (Layer 2 Tunneling Protocol, RFC 2661)            |
|    - Control: SCCRQ/SCCRP/SCCCN, ICRQ/ICRP/ICCN, ZLB, Hello |
|    - Data: Инкапсуляция PPP фреймов                         |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 3. IPsec ESP (Encapsulating Security Payload, RFC 4303)     |
|    - Шифрование: AES-128-CBC / AES-256-CBC / 3DES           |
|    - Аутентификация / ICV: HMAC-SHA1 / HMAC-SHA256          |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 4. IPsec IKEv1 (Internet Key Exchange, RFC 2409)            |
|    - Phase 1 (Main Mode): Согласование ISAKMP SA + PSK      |
|    - NAT-Traversal: Детекция NAT, порт UDP 4500             |
|    - Phase 2 (Quick Mode): Согласование ESP SA для UDP 1701 |
+-------------------------------------------------------------+
                              |
               [Физическая сеть / Интернет]
```

---

## 3. Детали протоколов

### 3.1. IKEv1 & IPsec ESP
1. **IKEv1 Phase 1 (Main Mode):**
   * **Сообщения 1 & 2:** Согласование параметров SA (Шифрование: AES-CBC / 3DES, Хэш: SHA1 / SHA256, Аутентификация: Pre-Shared Key, Diffie-Hellman: Group 2 (MODP 1024) или Group 14 (MODP 2048)).
   * **Сообщения 3 & 4:** Обмен публичными ключами DH (`g^x`, `g^y`) и псевдослучайными Nonce (`Ni`, `Nr`). Детекция NAT через хэши `NAT-D`.
   * **Вычисление ключей:**
     $$\text{SKEYID} = \text{HMAC-Hash}(\text{PSK}, N_i \mid N_r)$$
     $$\text{SKEYID}_d = \text{HMAC-Hash}(\text{SKEYID}, g^{xy} \mid \text{CKY-I} \mid \text{CKY-R} \mid 0)$$
     $$\text{SKEYID}_a = \text{HMAC-Hash}(\text{SKEYID}, \text{SKEYID}_d \mid g^{xy} \mid \text{CKY-I} \mid \text{CKY-R} \mid 1)$$
     $$\text{SKEYID}_e = \text{HMAC-Hash}(\text{SKEYID}, \text{SKEYID}_a \mid g^{xy} \mid \text{CKY-I} \mid \text{CKY-R} \mid 2)$$
   * **Сообщения 5 & 6 (зашифрованные):** Передача Identity (`IDi`) и проверка хэшей `HASH_I` / `HASH_R`. При наличии NAT соединение мигрирует на порт UDP 4500.

2. **IKEv1 Phase 2 (Quick Mode):**
   * Согласование ESP SA для инкапсуляции L2TP (протокол UDP, порт 1701).
   * Выделение `SPI_in` и получение `SPI_out`.
   * Генерация симметричных ключей шифрования и аутентификации ESP из $\text{SKEYID}_d$.

3. **ESP (RFC 4303) в режиме NAT-Traversal:**
   * Пакеты передаются через UDP 4500.
   * Пакеты IKE предваряются 4 нулевыми байтами `0x00000000` (Non-ESP Marker).
   * Пакеты ESP содержат 32-битный SPI, 32-битный номер последовательности (Seq No), вектор инициализации (IV), зашифрованное тело (UDP 1701 + L2TP), выравнивание, длину выравнивания, Next Header (17 = UDP) и HMAC ICV.

### 3.2. L2TPv2 (RFC 2661)
1. **Управляющий канал (Control Connection):**
   * Заголовок L2TP с флагом `T = 1`.
   * Каждое сообщение содержит `Ns` (исходящий счетчик) и `Nr` (ожидаемый входящий счетчик).
   * Последовательность хэндшейка:
     1. Клиент $\rightarrow$ `SCCRQ` (Start-Control-Connection-Request) с AVP: Protocol Version (1.0), Hostname, Framing Capabilities, Assigned Tunnel ID.
     2. Сервер $\rightarrow$ `SCCRP` (Start-Control-Connection-Reply) с Tunnel ID сервера.
     3. Клиент $\rightarrow$ `SCCCN` (Start-Control-Connection-Connected).
     4. Клиент $\rightarrow$ `ICRQ` (Incoming-Call-Request) с Assigned Session ID.
     5. Сервер $\rightarrow$ `ICRP` (Incoming-Call-Reply) с Session ID сервера.
     6. Клиент $\rightarrow$ `ICCN` (Incoming-Call-Connected).
   * `ZLB` (Zero Length Body): отправка пустого пакета для подтверждения получения (`Nr`), когда нет полезных данных для отправки.
   * Периодические `Hello`-пакеты (keep-alive) каждые 30 секунд.

2. **Канал данных (Data Packets):**
   * Заголовок L2TP с флагом `T = 0`: флаги, Tunnel ID, Session ID.
   * Полезная нагрузка — PPP фрейм.

### 3.3. PPP (Point-to-Point Protocol)
1. **LCP (Link Control Protocol, 0xC021):**
   * Согласование MRU (1400 байт для исключения фрагментации из-за заголовков ESP/L2TP).
   * Согласование метода аутентификации (`0xC223` для MS-CHAPv2).
2. **MS-CHAPv2 Аутентификация (0xC223, RFC 2759):**
   * Сервер присылает `Challenge` (16 байт).
   * Клиент генерирует `Peer Challenge` (16 байт).
   * Вычисление ответа:
     * $\text{NT-Hash} = \text{MD4}(\text{UTF-16LE}(\text{password}))$
     * $\text{ChallengeHash} = \text{SHA-1}(\text{PeerChallenge} \mid \text{ServerChallenge} \mid \text{username})[0..8]$
     * Вычисление стандартного 24-байтного ответа DES на основе NT-Hash.
   * Клиент отправляет `Response`.
   * Сервер подтверждает аутентификацию сообщением `Success`.
3. **IPCP (IP Control Protocol, 0x8021, RFC 1332):**
   * Клиент отправляет `Configure-Request` с запросом IP `0.0.0.0`, Primary DNS `0.0.0.0`, Secondary DNS `0.0.0.0`.
   * Сервер возвращает `Configure-Nak`, в котором указаны назначенный IP-адрес клиента, шлюз и DNS.
   * Клиент отправляет `Configure-Request` с подтверждением этих адресов.
   * Сервер отвечает `Configure-Ack`. Соединение готово к передаче трафика.

---

## 4. Архитектура Rust-демона (`asteriaray-l2tp`)

### 4.1. Структура проекта
```text
asteriaray-l2tp/
├── Cargo.toml
└── src/
    ├── main.rs                  # Точка входа, CLI парсинг, запуск Tokio, обработка SIGINT/SIGTERM
    ├── config.rs                # Структура конфигурации (server, username, password, psk, tun_name)
    ├── engine.rs                # Оркестратор хэндшейков и главный цикл пересылки пакетов
    ├── tun.rs                   # Открытие и работа с /dev/net/tun
    ├── ipsec/
    │   ├── mod.rs
    │   ├── isakmp.rs            # Парсинг и сборка пакетов IKEv1
    │   ├── phase1.rs            # State machine IKEv1 Main Mode & детекция NAT
    │   ├── phase2.rs            # State machine IKEv1 Quick Mode
    │   └── esp.rs               # Инкапсуляция и дешифрование ESP
    ├── l2tp/
    │   ├── mod.rs
    │   ├── packet.rs            # L2TPv2 заголовки и AVP атрибуты
    │   └── control.rs           # Надежный управляющий канал (SCCRQ, ICRQ, ZLB, Ns/Nr, Hello)
    ├── ppp/
    │   ├── mod.rs
    │   ├── lcp.rs               # LCP согласование
    │   ├── mschapv2.rs          # Аутентификация MS-CHAPv2
    │   └── ipcp.rs              # IPCP согласование адресов и DNS
    └── crypto/
        ├── mod.rs
        ├── dh.rs                # Diffie-Hellman MODP Group 2 (1024) и Group 14 (2048)
        └── kdf.rs               # Вычисление SKEYID, HASH_I, HMAC
```

### 4.2. Рекомендуемые зависимости `Cargo.toml`
```toml
[package]
name = "asteriaray-l2tp"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
tun2 = "3.1"
aes = "0.8"
cbc = "0.1"
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"
md4 = "0.10"
hmac = "0.12"
crypto-bigint = "0.5"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.5", features = ["derive"] }
```

### 4.3. IPC протокол взаимодействия с Flutter
Демон запускается процессом AsteriaRay:
```bash
asteriaray-l2tp --server <IP/Host> --user <Login> --password <Password> --psk <Secret> --tun asteria-l2tp0
```
И выводит в `stdout` структурированные события в формате JSON:
* При успешном подключении:
  ```json
  {"event":"connected","tun":"asteria-l2tp0","client_ip":"10.10.10.2","gateway":"10.10.10.1","dns":["1.1.1.1","8.8.8.8"]}
  ```
* При разрыве или ошибке:
  ```json
  {"event":"error","message":"MS-CHAPv2 authentication failed"}
  ```

---

## 5. Интеграция в AsteriaRay

### 5.1. Модели и хранилище
1. В `lib/models/vpn_protocol.dart`: включить `l2tp` в enum `VpnProtocol`.
2. Создать `lib/models/l2tp_profile.dart`: модель с полями `id`, `name`, `server`, `username`, `password`, `presharedKey`.
3. В `lib/models/stored_vpn_profile.dart`: добавить `L2tpStoredVpnProfile extends StoredVpnProfile`.
4. В `lib/services/stored_profile_codec.dart`: сериализация/десериализация профиля с `'protocol': 'l2tp'`.

### 5.2. Платформенный слой Linux
1. **Sudoers (`linux_sudoers_bootstrap_io.dart`):**
   Добавить `asteriaray-l2tp` в список утилит рядом с `asteriaray-vpn-routes.sh` и `awg-quick`, чтобы процесс запускался через `sudo -n` без ввода пароля.
2. **Сборка (`linux/CMakeLists.txt`):**
   Добавить установку бинарника `asteriaray-l2tp` в директорию бандла:
   ```cmake
   if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/asteriaray-l2tp")
     install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/asteriaray-l2tp"
       DESTINATION "${CMAKE_INSTALL_PREFIX}"
       COMPONENT Runtime)
   endif()
   ```
3. **Маршрутизация (`vpn_platform_linux.dart`):**
   * При получении события `connected`:
     Вызвать существующий `_linuxFullTunnelRoutes.apply(...)`, передав имя интерфейса `asteria-l2tp0` и IP-адрес сервера.
   * При отключении:
     Вызвать `_linuxFullTunnelRoutes.remove(...)` и послать `SIGTERM` процессу.

### 5.3. Пользовательский интерфейс
1. Создать `lib/screens/l2tp_form_screen.dart` (форма ввода Server, Username, Password, PSK).
2. В `lib/screens/home_screen.dart` добавить пункт в меню добавления конфигурации.
3. В `lib/widgets/protocol_slide_tabs.dart` добавить вкладку L2TP.
4. Добавить строки локализации в `app_en.arb` и `app_ru.arb`.

---

## 6. Чек-лист реализации

- [ ] **Фаза 1: Rust Демон**
  - [ ] Реализация IKEv1 Phase 1 (Main Mode, DH Group 2/14, PSK, NAT-D).
  - [ ] Реализация IKEv1 Phase 2 (Quick Mode, согласование ESP).
  - [ ] Модуль шифрования/дешифрования ESP (UDP 4500).
  - [ ] Реализация L2TPv2 Control Channel (SCCRQ $\rightarrow$ SCCCN, ICRQ $\rightarrow$ ICCN, ZLB, keep-alive).
  - [ ] Реализация PPP (LCP MRU negotiation, MS-CHAPv2 Auth, IPCP address negotiation).
  - [ ] Интеграция с Linux TUN устройством и forwarding loop.
  - [ ] Тестирование на тестовом сервере (MikroTik / accel-ppp).
- [ ] **Фаза 2: Интеграция во Flutter**
  - [ ] Модель данных `L2tpProfile` и кодек `StoredProfileCodec`.
  - [ ] `L2tpRunner` и интеграция в `VpnNotifier`.
  - [ ] Запуск и перехват событий в `VpnPlatformLinux`.
  - [ ] Экраны формы добавления/редактирования L2TP.
  - [ ] Обновление скриптов сборки и CMake.
