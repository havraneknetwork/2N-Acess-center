# 2N Access Center

Webová aplikace pro správu přístupu a ovládání dveřních zámků připojených k 2N IP interkomům a přístupovým jednotkám. Aplikace podporuje více jednotek, účty s různými oprávněními, časové rozvrhy, auditní log a bezpečnostní RFID karty.

## Obsah

- [Požadavky](#požadavky)
- [Instalace pomocí Docker Compose](#instalace-pomocí-docker-compose)
- [První přihlášení](#první-přihlášení)
- [Připojení jednotky 2N](#připojení-jednotky-2n)
- [Přiřazování a zobrazení jednotek](#přiřazování-a-zobrazení-jednotek)
- [Uživatelé a oprávnění](#uživatelé-a-oprávnění)
- [Funkce aplikace](#funkce-aplikace)
- [Nastavení prostředí](#nastavení-prostředí)
- [Aktualizace, zastavení a zálohování](#aktualizace-zastavení-a-zálohování)
- [Zabezpečení a provozní doporučení](#zabezpečení-a-provozní-doporučení)
- [Řešení problémů](#řešení-problémů)

## Požadavky

- Linuxový server nebo jiné prostředí s Docker Engine a Docker Compose v2.
- Síťové spojení serveru s každou 2N jednotkou.
- 2N jednotka s povoleným HTTP API a účtem s oprávněním ovládat spínač dveřního zámku.
- Pro přístup z jiných zařízení doporučujeme HTTPS přes reverzní proxy.

## Instalace pomocí Docker Compose

Naklonujte projekt a vytvořte lokální konfiguraci:

```bash
git clone https://github.com/havraneknetwork/2N-Acess-center.git
cd 2N-Acess-center
cp .env.example .env
```

Otevřete `.env` a nastavte alespoň:

```env
HOST_BIND_IP=127.0.0.1
INITIAL_ADMIN_PASSWORD=vase-dlouhe-jedinecne-heslo
```

`INITIAL_ADMIN_PASSWORD` je potřeba při vytvoření nové prázdné databáze. Zvolte jedinečné silné heslo a po prvním přihlášení ho můžete změnit v nastavení účtu. Tato proměnná již nemění heslo existujícího účtu.

Compose soubor používá externí Docker síť `proxy-public`. Pokud ještě na serveru neexistuje, vytvořte ji jednou:

```bash
docker network create proxy-public
```

Poté aplikaci sestavte a spusťte:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f
```

Výchozí `HOST_BIND_IP=127.0.0.1` zpřístupní port `3091` pouze lokálně na serveru. Otevřete-li aplikaci na stejném stroji, použijte `http://127.0.0.1:3091`. Pro bezpečné vzdálené použití nastavte reverzní proxy s HTTPS a nakonfigurujte její přístup k aplikaci. Port nevystavujte přímo do nedůvěryhodné sítě. Při HTTPS nastavte v `.env` také `COOKIE_SECURE=true`.

## První přihlášení

Po spuštění otevřete aplikaci a přihlaste se:

- uživatelské jméno: `admin`
- heslo: hodnota `INITIAL_ADMIN_PASSWORD`, kterou jste nastavili před prvním startem

Změňte výchozí heslo, pokud jste při nasazení použili dočasné heslo, a vytvořte další osobní účty v sekci **Správa uživatelů**. Nesdílejte administrátorský účet.

## Připojení jednotky 2N

Jednotky se běžně přidávají přes webové rozhraní, nikoliv pomocí `.env`:

1. Přihlaste se jako administrátor.
2. Otevřete sekci **Jednotky**.
3. Na každé 2N jednotce ověřte, že je zapnuté HTTP API a ovládání spínačů.
4. V aplikaci vyplňte název pro rozpoznání místa, typ zařízení, IP adresu a přihlašovací údaje API účtu.
5. Zvolte **Ověřit a přidat jednotku**. Aplikace zkusí dostupné varianty HTTP/HTTPS, portů a Digest/Basic autentizace; při úspěchu uloží zjištěné spojení a jednotku přidá.
6. V seznamu jednotek zkontrolujte stav připojení. Stav se průběžně obnovuje. Jednotku lze přejmenovat nebo odebrat.

Přihlašovací údaje musí být platným účtem na dané 2N jednotce. V administraci 2N v části **Služby → HTTP API** povolte příslušné API a ovládání spínačů. Účet musí mít právo ovládat relé/spínač zámku. Konkrétní názvy voleb se mohou lišit podle modelu a verze firmwaru; ověřte je v dokumentaci pro své zařízení.

Při neúspěšném ověření zkontrolujte IP adresu, dostupnost jednotky ze serveru, účet, heslo a oprávnění API. Jednotka musí být dosažitelná z hostitele/kontejneru aplikace, ne pouze z počítače, na kterém používáte prohlížeč.

### Proč existují `DEVICE_*` proměnné

Starší verze aplikace používala jednu jednotku nakonfigurovanou v `.env`. Proměnné jako `DEVICE_IP`, `API_USERNAME`, `API_PASSWORD`, `DEVICE_PORT` a `DEVICE_PROTOCOL` zůstaly v kódu jen pro **jednorázovou migraci** takové instalace. Při startu se z nich jednotka převede do databáze, pokud databáze ještě žádnou jednotku nemá a migrace dosud neproběhla.

V nové instalaci je nevyplňujte: ponechte registraci v administraci. Po migraci nebo po přidání jednotek přes aplikaci jsou údaje v `.env` pouze starým zdrojem pro prvotní převod; změny provádějte v sekci **Jednotky**. Jakmile je migrace označena nebo existuje jednotka v databázi, odstraněná jednotka se při restartu z těchto proměnných znovu nevytvoří. `DEVICE_*` proměnné proto nejsou součástí běžné šablony [`.env.example`](./.env.example).

## Přiřazování a zobrazení jednotek

Připojení jednotky v sekci **Jednotky** znamená její registraci v celé aplikaci. Neznamená automaticky, že ji každý uživatel uvidí nebo smí ovládat.

- Administrátor jednotku přidává, přejmenovává a odebírá.
- Každý uživatel si v nabídce účtu otevře **Nastavení** a vybere **Zobrazené jednotky**. Výběr určuje, které jednotky se mu zobrazí na hlavní stránce a ze kterých dostává oznámení.
- Oprávnění k odemykání, network bypass, trvalé odemčení a časový rozvrh se nastavují pro uživatele a konkrétní jednotku.
- Bezpečnostní RFID klíč lze přiřadit ke konkrétní jednotce, případně nastavit jeho platnost pro všechny jednotky.
- Odebráním jednotky se odstraní i její navázaná nastavení a přiřazení.

## Uživatelé a oprávnění

V sekci **Správa uživatelů** může administrátor vytvářet a spravovat účty, jejich role a přístupy. Dostupná oprávnění se mohou lišit podle role a nastavení administrátora.

- **Administrátor (`admin`)**: spravuje jednotky, uživatele a systémová oprávnění.
- **Správce (`správce`)**: provozní správa v rozsahu přidělených práv, například logy, stav jednotek, rozvrhy nebo bezpečnostní klíče.
- **Uživatel (`user`)**: běžný přístup k hlavní stránce a pouze k povoleným funkcím.

Oprávnění pro odemykání a trvalé odemčení lze nastavit zvlášť pro každou jednotku. Network bypass umožňuje odemykat i mimo běžně povolenou síť; udělujte ho jen účtům, které ho skutečně potřebují. Role ani skrytá položka v menu nenahrazují udělení příslušného oprávnění.

## Funkce aplikace

- **Home**: zobrazuje dostupné jednotky a jejich ovládání podle výběru a oprávnění přihlášeného uživatele.
- **Log**: auditní záznamy lze filtrovat podle konkrétní jednotky nebo systémových událostí.
- **Informace**: stavové a technické informace o vybrané jednotce; přístup závisí na roli a nastaveném menu.
- **Správa uživatelů**: správa účtů a jejich oprávnění.
- **Jednotky**: registrace a přejmenování zařízení, kontrola stavu a odebrání; pouze administrátor.
- **Bezpečnostní klíče**: registrace čipové karty po jejím přiložení k jednotce a určení funkce. Dostupné akce zahrnují odemknutí, zazvonění, přepnutí trvalého odemčení a blokování webového odemykání. Klíč lze navázat na konkrétní jednotku nebo na všechny.
- **Trvalé odemčení**: oprávněný uživatel může pro příslušnou jednotku aktivovat časově omezené trvalé odemčení; limit určuje přidělené oprávnění. Stav lze ukončit také ovládáním jednotky.
- **Rozvrh**: časová pravidla přístupu se konfigurují pro uživatele a jednotku.
- **Nastavení účtu**: osobní nastavení a volba jednotek zobrazovaných na Home a pro oznámení.

Oznámení v prohlížeči vyžadují souhlas uživatele s oznámeními. Vzdálená použití webových push notifikací obvykle vyžadují bezpečný kontext HTTPS.

## Nastavení prostředí

Všechny instance používají svůj lokální `.env`, který není součástí repozitáře ani Docker build kontextu. Vzorové hodnoty jsou popsány v [`.env.example`](./.env.example).

| Proměnná | Význam |
|---|---|
| `HOST_BIND_IP` | Rozhraní, na kterém Docker zveřejní port `3091`. Výchozí `127.0.0.1` je pouze lokální přístup. |
| `INITIAL_ADMIN_PASSWORD` | Heslo pro vytvoření prvního účtu `admin` v nové databázi. Po inicializaci existující heslo nemění. |
| `ALLOWED_SUBNETS` | Seznam povolených síťových rozsahů v CIDR notaci, pokud používáte omezení podle sítě. |
| `COOKIE_SECURE` | Nastavte `true`, pokud aplikaci používáte přes HTTPS. |
| `VERIFY_SSL` | Ověření certifikátu při HTTPS spojení s jednotkou. V produkční síti preferujte důvěryhodný certifikát a ověřování zapnuté. |
| `SECRET_KEY` | Volitelný stabilní tajný klíč. Pokud není nastaven, aplikace ho vygeneruje a uloží do `data/`. |
| `WEBHOOK_SECRET` | Volitelný tajný údaj pro konfiguraci webhooku 2N, pokud tuto ochranu používáte. |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN` | Volitelné parametry domény/originu pro WebAuthn. Musí odpovídat adrese webu. |
| `VAPID_EMAIL` | Kontaktní e-mailová identita pro Web Push. |

Ostatní proměnné aplikace mají výchozí hodnoty v kódu. Nastavujte je pouze pokud víte, jak jejich změna ovlivní nasazení.

## Aktualizace, zastavení a zálohování

Aktualizace na novější verzi:

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
```

Zobrazení logů a zastavení:

```bash
docker compose logs -f
docker compose down
```

Databáze, tajný klíč relací a klíče Web Push jsou v připojené složce `data/`. Tato složka není verzována. Před zálohou nebo obnovou zastavte aplikaci, aby se kopírovala konzistentní databáze:

```bash
docker compose down
tar -czf ../2n-access-center-data-backup.tar.gz data
docker compose up -d
```

Archiv obsahuje citlivé údaje, proto jej uložte mimo veřejný web a zabezpečte. Při obnově zachovejte databázi spolu se stabilním `SECRET_KEY` (z proměnné `.env`, pokud ji používáte, nebo ze souboru v `data/`). Hesla API jednotek jsou šifrovaná klíčem odvozeným od `SECRET_KEY`; při ztrátě nebo změně klíče se uložená hesla nedají dešifrovat a bude nutné je zadat znovu.

## Zabezpečení a provozní doporučení

- Nikdy necommitujte `.env`, databázi, obsah `data/`, zálohy, hesla ani soukromé klíče.
- Vystavujte aplikaci vzdáleně pouze přes HTTPS a důvěryhodnou reverzní proxy; nastavte odpovídající `HOST_BIND_IP` a `COOKIE_SECURE=true`.
- Používejte oddělený API účet s minimálními potřebnými oprávněními na každé 2N jednotce.
- Používejte silná individuální hesla, oddělené uživatelské účty a nejnižší potřebná oprávnění.
- `SECRET_KEY` i složku `data/` zálohujte a chraňte jako tajné údaje. Nepublikujte jejich obsah.
- `VERIFY_SSL=false` vypíná ověření TLS certifikátu u spojení s jednotkou. Je určeno jen pro důvěryhodné lokální prostředí se self-signed certifikátem; bezpečnější je použít důvěryhodný certifikát a ověřování zapnout.
- Nastavení `ALLOWED_SUBNETS` a network bypassu ovlivňuje, odkud lze dveře odemykat. Před změnou ověřte, že odpovídá vaší síťové topologii.

## Řešení problémů

### Nelze se přihlásit

- Při prvním spuštění ověřte `INITIAL_ADMIN_PASSWORD` v lokálním `.env`.
- Tato proměnná se používá pouze při založení účtu v nové databázi; po změně hesla existujícího admina nastavte nové heslo v aplikaci.
- Zkontrolujte logy pomocí `docker compose logs -f`.

### Jednotku se nepodaří přidat nebo zobrazuje nedostupný stav

- Ověřte, že IP adresa je dosažitelná z Docker hostitele a že jednotka je zapnutá.
- Zkontrolujte povolení HTTP API, účet, heslo a právo ovládat spínač.
- Ověřte firewall, VLAN a směrování mezi serverem a jednotkou.
- Zkontrolujte stav kontejneru a logy aplikace.

### Změna `.env` se neprojevila

Po změně prostředí kontejner znovu vytvořte:

```bash
docker compose up -d --force-recreate
```

Změna `INITIAL_ADMIN_PASSWORD` nezmění již existující účet. Jednotky již uložené v databázi upravujte v sekci **Jednotky**, nikoliv přes staré `DEVICE_*` proměnné.

### Aplikace se po smazání nebo restartu chová, jako by ztratila nastavení

Zkontrolujte, že `./data` je dostupná a připojená jako Docker volume. Při obnově ze zálohy ověřte, že obnovujete stejnou databázi a původní `SECRET_KEY`.
