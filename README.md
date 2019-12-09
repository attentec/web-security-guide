# Webbsäkerhetsguide

Detta är en guide om webbsäkerhet som går in på vanliga säkerhetshål, ger exempel på hur dessa kan utnyttjas och vad som går att göra för att undvika dem. Tanken är att guiden ska vara en inspiration till att hitta säkerhetshål i webbapplikationer och få ett systematiskt tänk kring säkerhet.

## Begränsning

Denna guide ger exempel på attacker och hur det går att skydda sig mot dem, men den är inte och kommer aldrig vara komplett då det kommer nya system med nya sårbarheter. För detaljer får du följa de länkar som finns i guiden.

## Innehåll

<!-- toc -->

- [Grundläggande principer för utveckling av säkra webbsystem](#grundl%C3%A4ggande-principer-f%C3%B6r-utveckling-av-s%C3%A4kra-webbsystem)
	* [Säkerhetsprinciper från OWASP:](#s%C3%A4kerhetsprinciper-fr%C3%A5n-owasp)
- [OWASP Topp 10](#owasp-topp-10)
	* [A1 - Injektion / Injection](#a1---injektion--injection)
	* [A2 - Trasig autentisering / Broken authentication](#a2---trasig-autentisering--broken-authentication)
	* [A3 - Exponering av känslig data / Sensitive data exposure](#a3---exponering-av-k%C3%A4nslig-data--sensitive-data-exposure)
	* [A4 - Externa XML-entiteter (XXE) / XML external Entities (XXE)](#a4---externa-xml-entiteter-xxe--xml-external-entities-xxe)
	* [A5 - Trasig åtkomstkontroll / Broken access control](#a5---trasig-%C3%A5tkomstkontroll--broken-access-control)
	* [A6 - Felkonfigurerad säkerhet / Security misconfiguration](#a6---felkonfigurerad-s%C3%A4kerhet--security-misconfiguration)
	* [A7 - Korssideskriptning (XSS) / Cross-site scripting (XSS)](#a7---korssideskriptning-xss--cross-site-scripting-xss)
	* [A8 - Osäker deserialisering / Insecure deserialization](#a8---os%C3%A4ker-deserialisering--insecure-deserialization)
	* [A9 - Använda komponenter med kända sårbarheter / Using components with known vulnerabilities](#a9---anv%C3%A4nda-komponenter-med-k%C3%A4nda-s%C3%A5rbarheter--using-components-with-known-vulnerabilities)
	* [A10 - Otillräcklig loggning och övervakning / Insufficient Logging & Monitoring](#a10---otillr%C3%A4cklig-loggning-och-%C3%B6vervakning--insufficient-logging--monitoring)
- [OWASP Topp 10 från tidigare år](#owasp-topp-10-fr%C3%A5n-tidigare-%C3%A5r)
	* [2013-A8 Korssidesförfrågningsförfalskning (CSRF) / Cross-Site Request Forgery (CSRF)](#2013-a8-korssidesf%C3%B6rfr%C3%A5gningsf%C3%B6rfalskning-csrf--cross-site-request-forgery-csrf)
	* [2013-A10 Ovaliderade omdirigeringar och vidarebefordringar / Unvalidated Redirects and Forwards](#2013-a10-ovaliderade-omdirigeringar-och-vidarebefordringar--unvalidated-redirects-and-forwards)
- [Fler sårbarheter](#fler-s%C3%A5rbarheter)
	* [Buffer Overflow](#buffer-overflow)
	* [Pinning av publik nyckel i IoT-klienter](#pinning-av-publik-nyckel-i-iot-klienter)
	* [Skiftlägesokänsliga URL:er](#skiftl%C3%A4gesok%C3%A4nsliga-urler)
	* [Denial of Service (DoS)](#denial-of-service-dos)
- [Verktyg](#verktyg)
- [Länkar](#l%C3%A4nkar)
- [Författare och licens](#f%C3%B6rfattare-och-licens)

<!-- tocstop -->

<div style="page-break-after: always;"></div>

## Grundläggande principer för utveckling av säkra webbsystem

Några grundläggande tips för att öka sannolikheten att hitta säkerhetshål under utvecklingen:

1. Test
    - Testa all funktionalitet ur ett säkerhetsperspektiv.
    - Testa manuellt med webbläsaren samt dess utvecklingsverktyg.
    - Skriv automatiska tester som testar olika scenarion som användare inte ska få göra och att systemet stoppar användaren från att göra dessa.
    - Försök att få med hörnfall i testerna, dvs scenarier där flera ovanliga eller extrema tillstånd inträffar samtidigt.
1. Kodgranskning
    - Kodgranska all kod som läggs in i systemet.
    - När du granskar någon annans kod, tänk på hur du skulle förstöra eller få tillgång till data du inte borde ha tillgång till. Går det det bara göra det som funktionen är tänkt att göra eller går det att göra mer?

### Säkerhetsprinciper från OWASP:
För detaljer, se [OWASP – Security by Design Principles](https://www.owasp.org/index.php/Security_by_Design_Principles).

* Minimera attackytan ([Minimize attack surface area](https://www.owasp.org/index.php/Minimize_attack_surface_area))
    - Begränsa åtkomst till funktionalitet och ta bort funktionalitet som inte används för att skydda mot eventuella attacker i denna.
* Låt säkra inställningar vara standard ([Establish secure defaults](https://www.owasp.org/index.php/Establish_secure_defaults))
    - Om användare använder din applikation eller andra utvecklare använder din kod så bör säkra inställningar vara standard som eventuellt går att konfigurera till en lägre säkerhetsnivå om användaren/utvecklaren har behov av det.
* Principen om minsta möjliga privilegium ([Principle of Least privilege](https://www.owasp.org/index.php/Least_privilege))
    - Minimera användares tilldelade rättigheter och tillgång till filsystem, nätverk, etc, till lägsta möjliga för att användaren ska kunna utföra sin uppgift.
* Principen om skydd på djupet ([Principle of Defense in depth](https://www.owasp.org/index.php/Defense_in_depth))
    - Det skadar inte heller att ha både ha både hängslen och livrem. Flera åtgärder för att motverka samma sårbarhet ger ett extra lager av skydd om nya applikationer/funktioner läggs till där skydd saknas, eller om något av skydden fallerar. Exempel:
        - Tänk oss att vi har en applikations-backend (server A) samt nginx framför den applikationen. Även om frontend-applikationen har skydd mot XSS skadar det inte att lägga till en CSP-header i nginx samt att begränsa användarindata till enbart bokstäver och siffror i server A om vi inte har behov av annat. En ny applikation, server B, läggs till. Den ligger bakom samma nginx och använder samma användarindata men har inte skydd mot XSS. Då skyddar fortfarande CSP-headern och den strikta valideringen av användarindata även den nya applikationen.
        - Ett administratörsgränssnitt som bara används från fasta platser kan begränsas till administratörernas IP-adress(er). Då är eventuella andra sårbarheter inte direkt tillgängliga via internet.
* Misslycka säkert ([Fail securely](https://www.owasp.org/index.php/Fail_securely))
    - Om t.ex. en applikation kastar ett undantag får inte det leda till ökade rättigheter, se [detta exempel](https://www.owasp.org/index.php/Fail_securely).
* Lita inte på tjänster ([Don’t trust services](https://www.owasp.org/index.php/Don’t_trust_services))
    - Indata som kommer från tredjepartstjänster är ur systemets perspektiv inte säkrare än indata som kommer direkt från användaren.
* Separation av plikter ([Separation of duties](https://www.owasp.org/index.php/Separation_of_duties))
    - Exempelvis en administratör för en webbshop ska kunna sätta lösenordspolicy men inte köpa varor i en användares namn.
* Undvik säkerhet genom hemlighetsfullhet ([Avoid security by obscurity](https://www.owasp.org/index.php/Security_by_Design_Principles#Avoid_security_by_obscurity))
    - Exempelvis en applikation ska inte förlita sig på att applikationen är säker för att källkoden hålls hemlig. Istället ska korrekta säkerhetslösningar implementeras. Linux är ett bra exempel där det är hög säkerhet och källkoden är öppen. Se även [Kerckhoffs princip](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle) och denna [XKCD](http://3.bp.blogspot.com/-XvR6VFp9nTk/T9lqbf_E7NI/AAAAAAAAAE0/AUilvXkwzJM/s1600/code_talkers.png).
* Håll det enkelt ([Keep security simple](https://www.owasp.org/index.php/Keep_security_simple))
    - Skapa inte en komplex arkitektur utan försök hålla det så enkelt som möjligt. Kodgranskning kan motverka att koden blir för komplex; om den som granskar inte kan förstå koden bör den förenklas.
* Fixa säkerhetsproblem korrekt ([Fix security issues correctly](https://www.owasp.org/index.php/Fix_security_issues_correctly))
    - Så fort ett säkerhetsproblem har hittats är det viktigt att testa det och förstå vad grundproblemet är och att kolla om problemet finns på mer än ett ställe. Se även till att skriva automatiska integrationstester för att motverka att säkerhetshålet kommer tillbaka.

En annan viktig princip är att all säkerhet som rör servern måste ligga i serverapplikationen. Validering av data eller åtkomstkontroller i frontend-applikationer är aldrig ett riktigt skydd.

Välj alltid välrenommerade, välanvända och välgranskade färdiga bibliotek för säkerhetsfunktioner i ditt språk eller ramverk i så stor utsträckning som möjligt, de är garanterat* bättre och säkrare än något du försöker uppfinna själv. Se även [denna diskussion](https://security.stackexchange.com/questions/18197/why-shouldnt-we-roll-our-own) på Security StackExchange.

<small>* Såvida ni inte är en grupp säkerhetsexperter med många års samlad erfarenhet.</small>

## OWASP Topp 10

OWASP har sammanställt topp 10-lista med vanliga attacker och sårbarheter i webbapplikationer. Denna lista uppdateras med jämna mellanrum och uppdaterade senast 2017. För mer ingående beskrivning av varje sårbarhet rekommenderas att läsa [OWASP Top Ten](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project).

### A1 - Injektion / Injection
 - För detaljer, se [OWASP - Injection](https://www.owasp.org/index.php/Top_10-2017_A1-Injection).

Varje gång indata kommer in i ett interpreterat programflöde finns det en risk för injektion av kod från indatan.

#### Exempel

SQL-injektion där datan kommer ofiltrerat från sidans URL:

```php
<?php
$query = "SELECT * FROM accounts WHERE custID='" .
$_GET["id"] . "'";

// id=1
"SELECT * FROM accounts WHERE custID='1'";

// id=1' or '1'='1
"SELECT * FROM accounts WHERE custID='1' OR '1'='1'";
?>
```

---

Exempel på kommandorads-injektion:

```php
<?php
$file=$_GET['filename'];
system("rm $file");
// Input:
// http://127.0.0.1/delete.php?filename=bob.txt;id
//
// Output:
// uid=33(www-data) gid=33(www-data) groups=33(www-data)
?>
```

---

PHP Array/Hash-injektion. Förvänta dig inte att du bara kan få in strängar i en GET/POST-query i PHP. Se även exempel där det går att använda mot [Mongo](https://www.php.net/manual/en/mongo.security.php) och eller mot [hash_hmac-funktionen](https://www.securify.nl/nl/blog/SFY20180101/spot-the-bug-challenge-2018-warm-up.html).

Motsvarande problem kan du få i t.ex. en Node.js applikaktion där du tar in JSON och konverterar den till ett javascriptobjekt utan att validera/begränsa typ av värden i JSON-objektet. ORM:en Sequelize i Node hade detta problem förut likt exemplet med Mongo ovan.

```php
<?php
// ?fruit=banana
//   => {"fruit":"banana"}
echo json_encode(array("fruit" => $_GET['fruit']));

// ?fruit[]=banana
//   => {"fruit":["banana"]}

// ?fruit[]=banana&fruit[]=pear
//   => {"fruit":["banana","pear"]}

// ?fruit[banana]=chocolate
//   => {"fruit":{"banana":"chocolate"}}

// ?fruit[x][y]=1&fruit[x][z][]=2&fruit[x][z][]=3
//   => {"fruit":{"x":{"y":"1","z":["2","3"]}}}
?>
```

#### Hur skyddar du systemet?

Lägg aldrig ihop kod med indata genom att bara slå ihop strängarna. Blanda aldrig osanerad indata med kod, utan se alltid till att filtrera, sanera eller koda om datan innan datan slås ihop med programkoden.
    - Detta gäller oavsett om datan kommer direkt från en användare eller från ett annat system.
    - Detta gäller oavsett om var datan kommer ifrån; exempelvis URL-query, POST-data, HTTP-headers, filuppladdning eller andra sätt som användaren kan få in datan i systemet.
    - Detta gäller oavsett vilket format datan kommer i; exempelvis SQL, JS, HTML, CSS, JSON, XML.
    - Det gäller även när kodavsnitt nästlas i varandra, ex. JSON i ett JS-block i HTML. Även om datan i är korrekt kodad för att inte hoppa ur JSON kan en `</script>`-tagg hoppa ur hela JS-blocket till HTML-nivån.

Använd gärna ett parametriserat API mot en databas eller en ORM (Object-Relational Mapper).

Undvik att anropa skalkommandon; använd istället ett bibliotek om möjligt.

Se även [OWASP - Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) och
[OWASP - Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

### A2 - Trasig autentisering / Broken authentication
 - För detaljer, se [OWASP - Broken authentication](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication).

Brister i autentiseringsförfarandet gör det möjligt för en angripare att komma åt användares konton. T.ex:

* Attack med tidigare läckta uppgifter (credential stuffing)
* Servern tillåter oändligt antal gissningar, vilket möjliggör online-råstyrkeattacker (online brute-force attacks)
* Servern tillåter svaga eller välkända lösenord
    - Exempel: admin, Password1, p@33w0Rd, qwerty123456
* Svaga eller dåliga "Jag har glömt lösenordet"-processer
    - Exempel: Säkerhetsfrågor
* Dåligt skyddade lösenord (i kombination med OWASP-A3), vilket möjliggör offline-råstyrkeattacker (offline brute-force attacks)
* Dålig eller avsaknad av multifaktorsautentisering
* Dålig sessionshantering

<div style="page-break-after: always;"></div>

#### Exempel

Om lösenorden sparas som MD5-hashar går det oftast att enkelt återskapa lösenordet. [Googla](https://lmgtfy.com/?q=85064efb60a9601805dcea56ec5402f7&s=g) exempelvis på denna MD5-hash:

 `85064efb60a9601805dcea56ec5402f7`

 Notera att skyddandet av lösenord är ett distinkt skiljt problem från det som vanligt förekommande hashfunktioner såsom MD5 och SHA-1/2/3 är gjorda för att lösa. I det senare fallet har du indata med hög entropi som du vill reducera till ett irreversibelt "fingeravtryck" så snabbt som möjligt; i det tidigare fallet har du indata med relativt låg entropi (beroende på valt lösenord förstås), som du vill reducera till ett irreversibelt "fingeravtryck" så pass långsamt att de omöjliggör uttömmande sökningar. Att utan vidare enbart hasha lösenordet en gång genom en sådan funktion ger inte bra säkerhet.

#### Hur skyddar du systemet?

- Implementera multifaktorautentisering.
- Använd inte standardlösenord som är svaga och/eller samma för flera användare.
- Implementera kontroller som blockerar användandet av svaga lösenord.
- Skydda lösenord med vältestade funktioner avsedda för syftet. Funktionen ska innehålla åtminstone ett salt och en faktor för att bestämma funktionens tidsåtgång.
- Begränsa online-råstyrkeattacker attacker genom att öka tiden det tar att försöka logga in efter ett felaktigt inloggningsförsök och/eller begränsa maximala antalet försök under en viss tidsrymd. Logga alla inloggningsförsök.
- Använd en säker sessionshantering. Spara aldrig sessions-ID:n i URL:er.
- Sätt attributen [`Secure`](https://www.owasp.org/index.php/SecureFlag) och [`HttpOnly`](https://www.owasp.org/index.php/HttpOnly) på alla sessions-och autentiseringskakor.

Se även [OWASP - Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP - Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) och [OWASP - Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

### A3 - Exponering av känslig data / Sensitive data exposure
 - För detaljer, se [OWASP - Sensitive data exposure](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure).

All form av känslig information (ex lösenord, kreditkortsuppgifter, GDPR-skyddade personuppgifter) som skickas i klartext på något sätt går att få ut i klartext från systemet (t.ex. klartext-/dåligt hashade lösenord i databasen) eller genom avlyssning.

#### Exempel

Här är en URL som har två problem. Dels så kör den inte över HTTPS och dels så har den känsligt persondata som lagras i webbläsarens historik då det är en del av URL:en

`http://example.com/search?person=121212-1212`

#### Hur skyddar du systemet?

* Identifiera vilken data som är känslig (t.ex. GDPR-skyddad) och hur datan hanteras, lagras eller överförs och hitta lämpliga sätt att skydda datan.
* Spara inte känslig information om det inte absolut behövs. Data som inte sparas kan inte blir stulet.
* Kryptera all trafik med en modern konfiguration av TLS (version 1.1 eller högre). Det går att testa om servern har en bra TLS-konfiguration på [SSL Labs](https://www.ssllabs.com/ssltest/).
* Använd HSTS för att förhindra nedgradering av HTTPS (TLS) till HTTP (utan TLS) och kontrollera att din TLS-implementation inte har kända sårbarheter. Se [OWASP Cheatsheets - Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html).
* Lägg aldrig känslig data i URL:er, det fastnar i webbläsarhistoriken.
* [Stäng av cache för data med känslig information](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html#prevent-caching-of-sensitive-data).
* Spara lösenord saltade och med en stark envägsfunktion som tar tid att köra. Exempel på sådana funktioner är [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) eller [PBKDF2](https://wikipedia.org/wiki/PBKDF2).

<div style="page-break-after: always;"></div>

### A4 - Externa XML-entiteter (XXE) / XML external Entities (XXE)
- För detaljer, se [XML external Entities (XXE)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))

Om en server accepterar XML som input finns det risk att den är sårbar för en XXE-attack. Det kräver dock att XML-hanteringen är konfigurerad att hantera externa XML-entiteter, vilket kan leda till en överbelastningsattack (Denial of Service), att känslig data läses ut, eller till och med möjligheten att valfri kod kan köra på servern (Remote Code Execution). Det skulle kunna vara ett REST-API som accepterar XML, SOAP-gränssnitt eller filuppladdning av XML.

#### Exempel

DoS med [Billion laughs attack](https://en.wikipedia.org/wiki/Billion_laughs_attack):

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

---

Några exempel på läsning av känslig information:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
<foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///dev/random" >]>
<foo>&xxe;</foo>
```

---

<div style="page-break-after: always;"></div>

Remote code execution på en server med PHP där expect-modulen är installerad.

```xml
<!-- If fortune is on our side,
and the PHP "expect" module is loaded, we can get RCE.
Let’s modify the payload -->

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
 <user>&xxe;</user>
 <pass>mypass</pass>
</creds>
```

#### Hur skyddar du systemet?

Undvik att använda funktionalitet med XML eller se till att konfigurationen för XML-hanteringen är korrekt inställd, se [OWASP Cheatsheets - XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

### A5 - Trasig åtkomstkontroll / Broken access control
- För detaljer, se [OWASP - Broken access control](https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control).

En angripare (anonym eller inloggad) lyckas ta sig förbi åtkomstkontroller eller ökar sina privilegier genom att exempelvis ändra följande i anrop till servern:

* URL
* POST-data
* Kakor
* HTTP-metod
* Andra HTTP-headers

#### Exempel

Ändra query:n i URL:en, exempelvis genom att sätta `<notmyacct>` till ID:t av någon annans konto:

```http
GET /app/accountInfo?acct=<notmyacct> HTTP/1.1
Host: www.example.com
```

Anta att det finns en admin-version av en URL som du kommer åt som vanlig användare.

```http
GET /app/getappInfo HTTP/1.1
```

```http
GET /app/admin_getappInfo HTTP/1.1
```

---

Ändra på POST-data, som exempelvis `<otherGroupId>` här:

```http
POST /user/viewOrder.jsp HTTP/1.1
Host: www.example.com

groupID=<otherGroupId>&orderID=0001
```

---

Om en fil pekas ut, ändra sökvägen till en annan fil med känsligt innehåll.

```http
GET /getUserProfile?file=../../../../etc/passwd HTTP/1.1
```

---

Ändra på JSON-objektet vid uppdatering av användarprofilen så att användaren uppgraderar till att vara administratör.

```http
POST /userPofile HTTP/1.1
Accept: application/json

{"username":"alice", "isAdmin":true}
```

#### Hur skyddar du systemet?

Testa om följande är möjligt och åtgärda problemen du hittar. Gärna i automatiska integrationstester, som körs regelbundet för att problemen inte ska uppstå igen:
* Kommer anonyma användare åt funktioner/data som bara är tänkt att kommas åt som som inloggad?
* Kommer vanliga användare åt funktioner/data som bara är tänkta att kommas åt som administratör eller annan roll?
* Kan användare ändra/läsa andra användares data?
* Kan en användare öka sina privilegier genom att ändra sin egen användarprofil?
* Går det att komma åt filer på webbservern som inte var tänkt att gå att komma åt eller inte som inte borde vara där, t.ex. en `.git`-mapp eller sökvägar utanför webbroten?
* Går det komma åt API:et från andra domäner än vad som är tänkt när [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) används? Se exempel på [felkonfiguration av CORS](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties).

Se även [OWASP - Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html).

### A6 - Felkonfigurerad säkerhet / Security misconfiguration
 - För detaljer, se [OWASP - Security misconfiguration](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration).

Servrar och applikationer som inte är korrekt konfigurerade för att användas i produktion kan ha funktioner som som är bekväma att ha vid utveckling men som blir sårbarheter om de körs i produktion.

#### Exempel

* Onödiga funktioner aktiverade eller installerade
    - T.ex. portar, tjänster, sidor, konton eller privilegier. T.ex:
        - SQL-konto med full tillgång till alla databaser.
* Standardkonton med standardlösenord
* Felmeddelanden som visas på sidan vid fel
    - T.ex. spårutskrifter eller SQL-felmeddelanden.
* Serverns programvara/operativsystem och versionsnummer, vilket talar om för en angripare att servern är sårbar om kända sårbarheter finns. Att ta bort denna information ger i sig själv inget skydd, mer än att det ger en lägre sannolikhet för en automatisk attack om versionen har en känd sårbarhet.
    - Server: nginx/1.14.0 (Ubuntu)
* Applikationsservrar, ramverk eller bibliotek är konfigurerade med osäkra värden
* Avsaknad av HTTP-säkerhetsheaders till webbläsaren (Content Security Policy etc.)

<div style="page-break-after: always;"></div>

#### Hur skyddar du systemet?

Läs på internet om hur du konfigurerar systemet säkert, här är några exempel: [OWASP - Secure Configuration Guide](https://www.owasp.org/index.php/Secure_Configuration_Guide) (Apache, ngingx, django m.fl)

Konfigurera HTTP-säkerhetsheaders för att förbättra säkerheten i webbläsaren, se [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers) och [OWASP - Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html). Det går även testa sidan med [securityheaders.com](https://securityheaders.com) alternativt ett av flera tillgängliga verktyg (t.ex. [securityheaders](https://github.com/koenbuyens/securityheaders) och [shcheck](https://github.com/meliot/shcheck) m.fl.) som man kan köra lokalt för att göra motsvarande analys mot localhost.

Ta bort funktioner/system som inte används.

### A7 - Korssideskriptning (XSS) / Cross-site scripting (XSS)
 - För detaljer, se [OWASP - Cross-site scripting (XSS)](https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_(XSS)).

XSS gör det möjligt för en angripare att köra kod i en annan användares webbläsare, vilket kan utnyttjas för t.ex. att stjäla uppgifter från användaren.

Det finns tre typer av XSS-attacker:
* DOM XSS
    - Bara i webbläsaren, når aldrig servern
* Reflekterad/Reflected XSS
    - Går till server och direkt tillbaka till webbläsaren
    - Vanligtvis genom felmeddelande, sökresultat, annan respons som inkluderar indata från användaren
* Lagrad/Stored XSS
    - Sparas exempelvis i databasen och kan sedan drabba en annan användare som går in på siten.
    - Allvarligast av alla XSS-sårbarheter.

#### Exempel

Exempel på en DOM XSS-sårbarhet som kan drabba vissa äldre webbläsare där javascript gick att köras i CSS:

```html
<a id="a1">Click me</a>
<script>
if (location.hash.slice(1)) {
  document.getElementById("a1").style.cssText =
            "color: " + location.hash.slice(1);
}
</script>

<!--
Opera [8,12]:
example.com/#red;-o-link:'javascript:alert(1)';-o-link-source:current;

IE 7/8:
example.com/#red;-:expression(alert(URL=1));
-->
```

---

<div style="page-break-after: always;"></div>

Reflekterad XSS-sårbarhet med PHP/HTML:

```php
<?php $search = isset($_GET['search']) ? $_GET['search'] : ''; ?>

<form action="" method="get" accept-charset="utf-8">
  <input type="text" name="search" value="<?php echo $search; ?>">
</form>

<!--
som vi sätter search till följande,
    search="><script>alert(1)</script><input name="
får vi detta resultat:
-->
<input type="text" name="search" value="">
  <script>alert(1)</script>
<input name="">
```

---

Lagrad  XSS-sårbarhet med PHP/HTML:

```php
<?php $query= mysql_query("SELECT * FROM City"); ?>
<ul>
<?php while ($result = $db->fetchByAssoc($query)): ?>
  <li><?php echo $result['cityName'] ?></li>
<?php endwhile ?>
</ul>
```

#### Hur skyddar du systemet?

Använd ett ramverk som med inbyggt skydd mot XSS, såsom många moderna Javascript-ramverk (React, Angular, Vue etc.) har idag. Tänk dock på att att även om de har skydd så är skyddet inte alltid komplett, se exempel på [React XSS](https://stackoverflow.com/questions/33644499/what-does-it-mean-when-they-say-react-is-xss-protected) eller [Avoiding XSS in React is Still Hard](https://medium.com/javascript-security/avoiding-xss-in-react-is-still-hard-d2b5c7ad9412).

Att vitlista säkra värden i modeller istället för att tillåta vad som helst i strängar är ett bra komplementerande skydd mot XSS. Reguljära uttryck kan vara ett bra sätt att definiera vilka värden som är tillåtna, men säkerställ att du inte introducerar [ReDoS-sårbarheter](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS).

Testa applikationen, här finns exempel på olika XSS-strängar: [xsses.rocks](https://xsses.rocks/sample-page/) och [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).

Läs mer hur du skyddar systemet mot XSS här [OWASP - XSS Prevention Cheat Sheet ](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

Se även [OWASP - AJAX Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html) och [OWASP - HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html).

<div style="page-break-after: always;"></div>

### A8 - Osäker deserialisering / Insecure deserialization
 - För detaljer, se [OWASP - Insecure deserialization](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization).

Objekt som serialiseras och är tillgängligt för en angripare kan ändras, vilket eventuellt kan leda till att åtkomstkontroller kringgås eller i värsta fall att skadlig kod körs när objektet sedan deserialiseras på servern.

#### Exempel

Exempel i PHP (serialize/unserialize) där uppgradering av användarrättigheterna kan ske genom att ändra namn (till Alice) och roll (till admin).

```javascript
a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
// =>
a:4:{i:0;i:132;i:1;s:7:"Alice";i:2;s:4:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```

#### Hur skyddar du systemet?

Undvik att acceptera serialiserad data från osäkra källor, men om det inte är möjligt se till att implementera integritetscheckar eller [annan åtgärd](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization) för att göra deserialiseringen säkrare.

Läs mer på [OWASP - Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).

### A9 - Använda komponenter med kända sårbarheter / Using components with known vulnerabilities
 - För detaljer, se [OWASP - Using components with known vulnerabilities](https://www.owasp.org/index.php/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities)

Om någon mjukvara i ditt system är föråldrat eller har en känd sårbarhet utgör det en risk för dit system.

#### Exempel

Exempel i node.js på hur `npm audit` kan användas för att användas analysera om några npm-paket har kända sårbarheter:

```bash
$ npm audit

                       === npm audit security report ===

# Run  npm update lodash --depth 1  to resolve 1 vulnerability
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ High          │ Prototype Pollution                                          │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ lodash                                                       │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ lodash                                                       │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ lodash                                                       │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/1065                            │
└───────────────┴──────────────────────────────────────────────────────────────┘

found 1 high severity vulnerability in 1 scanned package
  run `npm audit fix` to fix 1 of them.
```

<div style="page-break-after: always;"></div>

#### Hur skyddar du systemet?

Uppdatera kontinuerligt systemen när nya sårbarheter dyker upp:

* Se till att ditt OS och installerad programvara har nyaste säkerhetsuppdateringarna genom ditt systems uppdateringsverktyg/pakethanterare (Windows Update/Store/`chocolatey` i Windows; `apt` i Debian-baserade Linux-distributioner, `rpm` i Red Hat-baserade, `pacman` i Arch Linux; etc)
* De program är installerade utanför systemets pakethanterare måste även de uppdateras regelbundet.
* Uppdatera de paket som används i ditt webbsystem, med exempelvis `npm` i Node.js och `pip` i Python.

Kontrollera om du har kända sårbarheter i dina tredjepartspaket med ett verktyg, integrera verktyget i ditt CI-flöde för att automatiskt kolla om det dyker upp några nya kända sårbarheter. Här är några exempel på verktyg som analyserar om det finns sårbara paket installerade:

* För Paket i Java och .NET (+ experimentellt stöd för Ruby, Node.js, Python, C/C++) kan du använda [OWASP Dependency check](https://www.owasp.org/index.php/OWASP_Dependency_Check).
* För Python kan [Safety](https://pyup.io/safety/) användas.
* För Node.js kan det inbyggda `npm audit` användas.
* [Snyk](https://snyk.io) stödjer [ett antal olika språk](https://snyk.io/docs).

### A10 - Otillräcklig loggning och övervakning / Insufficient Logging & Monitoring
 - För detaljer, se [OWASP - Insufficient Logging & Monitoring](https://www.owasp.org/index.php/Top_10-2017_A10-Insufficient_Logging%26Monitoring).

För att veta om en angripare attackerar ditt system är det viktigt att övervaka systemet och logga vad som händer. Om du inte vet vad som händer i systemet så vet du inte heller vad en angripare gör på systemet.

#### Exempel

Exempel på otillräcklig loggning:

* Händelser såsom godkända och felaktiga inloggningar, och viktiga transaktioner är inte loggade
* Varningar och fel loggas inte eller loggas dåligt
* Misstänkt aktivitet loggas inte
* Loggar sparas bara lokalt
* Larm skickas inte vid angrepp

#### Hur skyddar du systemet?

* Logga felaktiga inloggningar, indatavalideringsfel, etc; allting som kan tyda på att man gör något som man inte ska.
* Logga viktiga transaktioner på ett sätta som inte går att redigera i efterhand.
* Använd verktyg för att övervaka och upptäcka intrångsförsök, t.ex. [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project).

Se även [OWASP - Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

<div style="page-break-after: always;"></div>

## OWASP Topp 10 från tidigare år

OWASP top 10 har uppdaterats med åren och i de tidigare topplistorna finns sårbarheter som fallit bort från den senaste topptiolistan men som är värda att nämna. Även om de är ovanligare idag finns det fortfarande en risk att de uppstår i en ny eller legacy-applikation.

Länkar till tidigare OWASP Top 10:

* [OWASP Top Ten 2013](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_2013_Project)
* [OWASP Top Ten 2010](https://www.owasp.org/index.php/Top_10_2010-Main)

### 2013-A8 Korssidesförfrågningsförfalskning (CSRF) / Cross-Site Request Forgery (CSRF)
 - För detaljer, se [OWASP - Cross-Site Request Forgery](https://www.owasp.org/index.php/Top_10_2013-A8-Cross-Site_Request_Forgery_(CSRF)).

Ja, visst är det en vacker översättning. CSRF gör det möjligt för en angripare att göra förfrågningar från en sida som användaren besöker till en annan sida och på så sätt genomföra transaktioner på den andra sidan som den användaren (förutsatt att användaren är inloggad). Angriparen utnyttjar att webbläsaren under vissa omständigheter automatiskt skickar autentiseringsuppgifter tillsammans med begäran till den andra sidan, om dessa lagras i kakor.

#### Exempel

Genom en länk eller en osynlig bild görs en banktransaktion.

```html
<a href="http://bank.com/transfer.do?acct=MARIA&amount=100000">
    View my Pictures!
</a>

<img src="http://bank.com/transfer.do?acct=MARIA&amount=100000"
    width="0" height="0" border="0" />
```

---

Genom ett formulär görs ett POST-anrop för att genomföra en banktransaktion på användarens bank.


```html
<body onload="document.forms[0].submit()">

<form action="http://bank.com/transfer.do" method="POST">
    <input type="hidden" name="acct" value="MARIA"/>
    <input type="hidden" name="amount" value="100000"/>
    <input type="submit" value="View my pictures"/>
</form>
```

```http
POST http://bank.com/transfer.do HTTP/1.1

acct=BOB&amount=100
```

---

<div style="page-break-after: always;"></div>

En PUT-request skickas till banken för att göra en banktransaktion. Detta kräver dock att servern har tillåtande [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)-inställning.

```html
<script>
function put() {
var x = new XMLHttpRequest();
x.open("PUT","http://bank.com/transfer.do",true);
x.setRequestHeader("Content-Type", "application/json");
x.send(JSON.stringify({"acct":"BOB", "amount":100}));
}
</script>
<body onload="put()">
<!-- Kräver HTTP-headern: Access-Control-Allow-Origin: * -->
```

```http
PUT http://bank.com/transfer.do HTTP/1.1

{ "acct":"BOB", "amount":100 }
```

#### Hur skyddar du systemet?

Använd en slumpmässig sträng (CSRF-token) som måste skickas med i varje förfrågan. Det finns verktyg/bibliotek till olika plattformar som kan hjälpa att skydda systemet.

Lägg till [attributet `SameSite`](https://www.owasp.org/index.php/SameSite) till alla känsliga kakor med värdet `Lax` eller `Strict`.

Se även [OWASP - CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

### 2013-A10 Ovaliderade omdirigeringar och vidarebefordringar / Unvalidated Redirects and Forwards
 - För detaljer, se [OWASP - Unvalidated Redirects and Forwards](https://www.owasp.org/index.php/Top_10_2013-A10-Unvalidated_Redirects_and_Forwards).

Om en omdirigering görs där indata avgör vart omdirigeringen ska göras riskerar användaren att bli skickad till en angripares sida; t.ex. en användare klickar på en länk som ser ut att vara äkta men blir sedan sedan omdirigerad till angriparens webbsida.

Alternativt så görs en vidarebefordring internt i applikationen till en sida som ej är tänkt att vara åtkomlig.

#### Exempel

Här omdirigeras användaren från example.com till angriparens server evil.com:

`https://www.example.com/redirect?url=evil.com`

---

Vidarebefordring till admin.jsp genom boring.jsp:

`http://www.example.com/boring.jsp?fwd=admin.jsp`

#### Hur skyddar du systemet?

Undvik att använda omdirigeringar eller vidarebefordringar som baseras på användarindata. Alternativt vitlista strikt bara de alternativ som är tillåtna.

Se även [OWASP - Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

<div style="page-break-after: always;"></div>

## Fler sårbarheter

Här listar vi några fler exempel som inte finns med i OWASP top 10:s lista, men som ändå kan vara bra att känna till.

### Buffer Overflow

I systemnära lågnivåspråk som exempelvis C/C++ är det risk för buffer overflow om inte indata hanteras korrekt. Det är inte vanligt med webbsystem skrivna i C/C++ men det är inte helt ovanligt att skriva IoT-klienter med som ansluter via HTTP med exempelvis [libcurl](https://curl.haxx.se/libcurl) eller via meddelandeprotokoll som [AMQP](https://en.wikipedia.org/wiki/Advanced_Message_Queuing_Protocol) eller [MQTT](https://en.wikipedia.org/wiki/MQTT) till en server. För att inte riskera en buffer overflow är det viktigt att all data från servern, användaren eller andra system tas om hand på ett korrekt sätt.

Buffer overflow kan i bästa fall orsaka en krasch och i värsta fall göra det möjligt för angriparen att köra valfri kod.

#### Exempel

Här ser vi ett exempel där vi får en buffer overflow på stacken (en stack overflow), när `buffer` får ett värde som är 21 tecken långt (avslutande NULL inräknat). De 11 tecken som inte ryms i `buffer` kommer skriva över viktiga värden på stacken.

```c
#include <string.h>

void f(char* s) {
    char buffer[10];
    strcpy(buffer, s);
}

void main(void) {
    f("01234567890123456789");
}

```

```shell
[root /tmp]# ./stacktest

Segmentation fault
```

---

<div style="page-break-after: always;"></div>

Här ser vi ett exempel på hur `scanf` och `printf` kan utnyttjas för att skriva och läsa på stacken. Skrivningen på stacken med `scanf` begränsar inte hur lång sträng som ska läsas in till `str`. Första argumentet i `printf` ska aldrig tas från indata, då det kan användas för att läsa från stacken och även läsa och skriva var som helst i minnet.

```c
int main() {
    char str[30];
    scanf("%s", str);
    printf(str);
}

// scanf:
// 123456789012345678901234567890
// => Stack overflow

// printf:
// str=%08x.%08x.%08x.%08x.%08x
// prints 5 first entries in the stack
```

Genom att begränsa antal tecken `scanf` tar in och inte använda indata som första argument till `printf` så skyddar vi koden.

```c
int main() {
    char str[50];
    scanf("%29s", str);
    printf("%s", str);
}
```

---

Exempel på en buffer overflow på heapen, även kallat heap overflow.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define BSIZE 16
#define OVERSIZE 8 /* overflow buf2 by OVERSIZE bytes */

void main(void) {
  u_long b_diff;
  char *buf0 = (char*)malloc(BSIZE);		// create two buffers
  char *buf1 = (char*)malloc(BSIZE);

  b_diff = (u_long)buf1 - (u_long)buf0;	// difference between locations
  printf("Initial values:  ");
  printf("buf0=%p, buf1=%p, b_diff=0x%x bytes\n", buf0, buf1, b_diff);

  memset(buf1, 'A', BUFSIZE-1), buf1[BUFSIZE-1] = '\0';
  printf("Before overflow: buf1=%s\n", buf1);

  memset(buf0, 'B', (u_int)(diff + OVERSIZE));
  printf("After overflow:  buf1=%s\n", buf1);
}

```

```shell
[root /tmp]# ./heaptest

Initial values:  buf0=0x9322008, buf1=0x9322020, diff=0xff0 bytes
Before overflow: buf1=AAAAAAAAAAAAAAA
After overflow:  buf1=BBBBBBBBAAAAAAA
```

---

Här är ett exempel på hur en integer overflow leder till en buffer overflow.


```c
#include <stdio.h>
#include <string.h>

void main(int argc, char *argv[]) {
    int i = atoi(argv[1]);         // input from user
    unsigned short s = i;          // truncate to a short
    char buf[50];                  // large buffer

    if (s > 50) {                  // check we're not greater than 50
        return;
    }

    memcpy(buf, argv[2], i);       // copy i bytes to the buffer
    buf[i] = '\0';                 // add a null byte to the buffer
    printf("%s\n", buf);           // output the buffer contents

    return;
}
```

Integer-värdet 65580 blir 45 när det konverteras till en short som är mindre än 50 men senare används integer-värdet 65580 vid kopiering av bufferten vilket resulterar i en krasch:

```shell
[root /tmp]# ./inttest 65580 foobar
Segmentation fault
```

#### Hur skyddar du systemet?

Använd ett högnivåspråk istället som inte tillåter direktaccess till minnet.

Se till att validera indata så att det exempelvis inte är för långt eller innehåller "skräpdata".

Läs mer om buffer overflow på [Wikipedia](https://en.wikipedia.org/wiki/Buffer_overflow) och [OWASP](https://www.owasp.org/index.php/Buffer_Overflows).

Se även mer info om `printf` och säkerhet på [OWASP - Format string attack](https://www.owasp.org/index.php/Format_string_attack) eller  [cis.syr.edu - Format String Vulnerability](http://www.cis.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf).

Läs om hur du förbättrar säkerheten när du bygger C-baserad kod på [OWASP - C-Based Toolchain Hardening Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html).

### Pinning av publik nyckel i IoT-klienter

För att undvika man-i-mitten-attacker (man-in-the-middle attacks) i exempelvis IoT-klienter, går det att låsa vilken publik nyckel på servern som accepteras, detta kallas pinning. Läs mer om hur du implementerar pinning i klienten på [OWASP - Pinning Cheat Sheet ](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html).

### Skiftlägesokänsliga URL:er

Om webbservern hanterar URL:er skiftlägesokänsligt (case insensitive), ex `/admin` är ekvivalent med `/AdmiN`, och du begränsar tillgång till `/admin` i ex. nginx så kommer fortfarande `/Admin` etc. fortfarande vara tillgängliga.

Exempel på servrar som har skiftlägesokänslig hantering av URL:er: [ExpressJS](http://expressjs.com/en/api.html#express.router) och [IIS+ASP.NET](https://stackoverflow.com/questions/5811021/how-to-enable-case-sensitivity-under-iis-express).

<div style="page-break-after: always;"></div>

### Denial of Service (DoS)

DoS-attacker innebär att en tjänst slutar svara pga av att den överbelastad eller att servern kraschar. Detta kan exempelvis vara möjligt om vissa frågor tar väldigt mycket tid/resurser att svara på, vilket låser ute riktiga användare som vill komma åt tjänsten.

Läs mer på [OWASP - Denial of Service](https://www.owasp.org/index.php/Denial_of_Service) och [OWASP - Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html).

## Verktyg

För att testa din webbapplikation kan det vara bra att känna till lite verktyg som är användbara:

* Web Developer Tools i Chrome, Firefox, Safari m.fl. - Med dessa går det att göra väldigt mycket. Kolla på all HTTP(S)-trafik, skapa fetch-förfrågningar som går att skicka med konsolen, exportera förfrågningar som cURL-kommandon m.m.
* [Curl](https://curl.haxx.se) – kommandoradsvektyg som göra alla anrop en webbläsare och än mer avancerade/anpassade för behoven om en så önskar.
* [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) – Verktyg som gör det enklare att penetrationstesta webbsidor.
* [Burp Suite](https://portswigger.net/burp) – Kommersiellt verktyg som är välanvänt bland pentestare.

## Länkar

Här är några bra utgångspunkter för att fördjupa sig mer i säkerhet:

* https://www.owasp.org – Open Web Application Security Project
* https://cheatsheetseries.owasp.org - OWASP:s lathundar för att öka säkerheten i applikationer.

## Författare och licens

Detta dokument är tillgängligt under [Creative Commons Attribution-ShareAlike](https://creativecommons.org/licenses/by-sa/4.0/), då mycket material kommer från [OWASP](https://www.owasp.org) kräver att materialet släpps under samma licens.

Denna guide har skapats av [David Granqvist](https://github.com/hacker112) och [Niklas Holm](https://github.com/niklasholm) på [Attentec](https://www.attentec.se).
