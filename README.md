# 2N Access Center - Webové odemykání dveří

Kontejner s moderním webovým rozhraním a backendovým API pro bezpečné dálkové odemykání dveří přes 2N IP interkomy a přístupové jednotky.

---

## Nastavení prostředí a přihlašovacích údajů

Vytvořte lokální konfiguraci z bezpečné šablony:
```bash
cp .env.example .env
```

Upravte `.env`. Je ignorován Gitem a není součástí Docker build kontextu. Nikdy do repozitáře nevkládejte skutečná hesla ani klíče.
Pro publikování portu pouze na tomto stroji ponechte `HOST_BIND_IP=127.0.0.1`; veřejné rozhraní nastavujte pouze pokud je záměrné a chráněné firewallem nebo reverzní proxy.
Příklad konfigurace:
```env
HOST_BIND_IP=127.0.0.1
INITIAL_ADMIN_PASSWORD=<silne-jedinecne-heslo-admina>
DEVICE_IP=
DEVICE_PORT=443
DEVICE_PROTOCOL=https
API_USERNAME=
API_PASSWORD=
AUTH_TYPE=digest
SWITCH_ID=1
SWITCH_ACTION=trigger
ALLOWED_SUBNETS=<povolene-CIDR-podsítě>
```

Při inicializaci zcela nové databáze je nutné nastavit silné `INITIAL_ADMIN_PASSWORD`. Proměnná se používá pouze při vytvoření prvního účtu `admin`; stávající účty se při restartu nemění. Tajný klíč aplikace a klíče Web Push se automaticky vygenerují do připojené složky `data/`, která není verzována.

### Registrace dalších jednotek
Administrátor může v aplikaci otevřít sekci **Jednotky** a přidat 2N zařízení podle názvu, typu, IP adresy a API přihlašovacích údajů. Aplikace před uložením otestuje připojení k API a heslo uloží šifrovaně. Stávající jednotka z konfigurace `.env` se při prvním spuštění převede do registru automaticky; po jejím úmyslném odebrání se znovu nevytvoří.

Každý uživatel si v **Nastavení účtu → Zobrazené jednotky** vybere, které jednotky uvidí na Home a ze kterých chce dostávat push oznámení. Oprávnění, rozvrhy a trvalé odemčení se nastavují pro každou jednotku samostatně. Šifrovaná hesla jednotek závisejí na stabilním `SECRET_KEY`; při jeho změně je potřeba údaje jednotek znovu zadat.

---

## ⚙️ Nastavení v administraci 2N Access Unit M

Aby 2N jednotka přijímala požadavky na odemčení:
1. Přihlaste se do webové administrace 2N jednotky.
2. Přejděte do **Služby (Services)** -> **HTTP API**.
3. V sekci **Ovládání spínačů (Switch API)**:
   - Nastavte přístup: **Povoleno (Enabled)**
   - Autentizace: **Digest** (nebo **Basic**)
4. V sekci **Uživatelské účty (Account)** vytvořte nebo použijte účet s oprávněním pro **Ovládání spínačů (Switch Control)**.

---

## 🚀 Spuštění a správa kontejneru

### Sestavení a spuštění:
```bash
git clone https://github.com/havraneknetwork/2N-Acess-center.git
cd 2N-Acess-center
cp .env.example .env
# Upravte .env před spuštěním.
# Pokud ještě neexistuje externí Docker síť proxy-public:
docker network create proxy-public
docker compose up -d --build
```

### Přístup k webové stránce:
Při výchozím nastavení je stránka dostupná pouze lokálně na adrese:
```
http://127.0.0.1:3091
```

### Zobrazení logů:
```bash
docker compose logs -f
```

### Zastavení kontejneru:
```bash
docker compose down
```
