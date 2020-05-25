# AGHO_Blind_kryptlib

Eine kryptographische Bibliothek, welche die auf der AGHO Signatur basierende restriktive AGHO Blindsignatur, sowie eine prototypische Implementierung eines Client-Server Modells bereitstellt.

## Requirements

- Installation von Python3
- Installation der Charm Library (siehe Referenzen)
- Installation von virtualenv (Virtuelle Umgebung für Python)

```sh
pip3 install virtualenv
```

- Installation von flask (RESTFul Programmieren mit Python)

```sh
pip3 install flask flask-jsonpify flask-sqlalchemy flask-restful
```

```sh
pip3 install requests
```

- Installieren eines DB Browsers für SQLite (Empfohlen für das Erstellen von Datenbanken)

- Insgesamt werden 4 SQLite Datenbanken im selben Ordner wie der Server mit folgenden Namen benötigt
  - AKeyData (zur Speicherung der ElGamal Schlüssel)
  - WKeyData (zur Speicherung der Signaturschlüssel)
  - WVoterData (die Datenbank, welche die Wählerdaten enthält)
  - AVoteData (die Datenbank in der die EVs abgelegt werden)

Um die Applikation zu starten muss für den Server eine virtuelle Umgebung geschaffen werden, also für einen ausgewählten Ordner

```sh
virtualenv bspdir
source bspdir/bin/activate
```

Anschließend müssen die Libraries (Charm, flask, und diese AGHO Library) auch hier noch einmal hineingezogen werden, damit sie auch in der virtuellen Umgebung vorhanden sind.

Der Server (also das Wahlamt bzw. die Auszählbehörde) kann dann folgendermaßen gestartet werden.

```sh
python3 BackendVoteAPI.py
```

Der Server hört nun auf ***localhost:5002***. es werden beim erstmaligen starten automatisch zwei Testuser mit den folgenden Zugangsdaten erzeugt:

User 1:

- Username: testuser1
- Passwort: supersecurepassword123

User 2:

- Username: testuser2
- Passwort: reallysecurepassword123

Der Client kann folgendermaßen gestartet werden:

```sh
python3 PythonVoterAPI.py
```

## Schnittstellen der kryptographischen Bibliothek

Die kryptographische Bibliothek ist aus mehreren Komponenten aufgebaut und besteht aus den folgenden Scripts:

- ElGamalImpl.py
- AGHOSignature.py (für die weitere Erstellung der AGHO Blindsigantur implementiert)
- AGHOBild.py
- ZKP.py

Durch eine Instanz der ElGamal Klasse in ElGamalImpl.py können folgende Funktionen aufgerufen werden:

- keygen (Erstellen eines ElGamal Schlüsselpaars)
- encrypt (Einen String Klartext der ElGamal-Verschlüsselung unterziehen)
- decrypt (Einen ElGamal Ciphertext entschlüsseln)
- ZKPsk (Erstellen eines Zero-Knowledge Proofs über die korrekte Entschlüsselung der ElGamal verschlüsselten Stimmen)
- ZKPsk_verify (Verifizieren eines Zero-Knowledge Proofs über die korrekte Entschlüsselung der ElGamal verschlüsselten Stimmen)

Durch die Instanz einer AGHOBlindsignatur, welche als Input eine ElGamal Instanz erwartet, können folgende Funktionen aufgerufen werden:

- keygen (erstellen eines Signatur Schlüsselpaares für die AGHO Blindsigantur)
- blind (verbilden eines ElGamal Ciphertextes)
- sign (signieren eines verblindeten ElGamal Ciphertextes)
- deblind (entblinden einer AGHO Bildsignatur)
- verify (Verifizieren einer AGHO Signatur)
- ZKPU (Erstellen eines Zero-Knowledge Proofs über das korrekte Format des Stimmzettels vom User)
- ZKPU_verify (Verfifzieren eines Zero-Knowledge Proofs über das korrekte Format des Stimmzettels vom User)
- ZKPS (Erstellen eines Zero-Knowledge Proofs über das korrekte Verhalten des Untzerzeichners (Wahlamt))
- ZKPS_verify (Verifizieren eines Zero-Knowledge Proofs über das korrekte Verhalten des Untzerzeichners (Wahlamt))

Durch die ZKP Klasse, welche auch von der AGHOBlind Instanz und der ElGamal Instanz verwendet wird, können folgende Funktionen aufgerufen werden:

- ZKP_correctFormatU (Erstellen eines Zero-Knowledge Proofs über das korrekte Format des Stimmzettels vom User)
- verifyZKP_FormatU (Verifizieren eines Zero-Knowledge Proofs über das korrekte Format des Stimmzettels vom User)
- ZKP_correctFormatS (Erstellen eines Zero-Knowledge Proofs über das korrekte Verhalten des Untzerzeichners (Wahlamt))
- verifyZKP_FormatS (Verifizieren eines Zero-Knowledge Proofs über das korrekte Verhalten des Untzerzeichners (Wahlamt))
- ZKP_correctVote (Erstellen eines Zero-Knowledge Proofs über die korrekte Entschlüsselung der ElGamal verschlüsselten Stimmen)
- verifyZKP_correctVote (Verifizieren eines Zero-Knowledge Proofs über die korrekte Entschlüsselung der ElGamal verschlüsselten Stimmen)

## Schnittstellen des Servers

Wenn der bestehende Server verwendet wird, kann dieser über eine REST API über Requests angesprochen werden (Port 5002). Gedacht wäre dabei eine Aufteilung des Servers auf zwei Instanzen (Wahlamt und Auszählbehörde). Es ist darauf zu achten, dass der Client und der Server so verfasst wurden, um eine Wahl mit zwei Attributen (Stimme (3 Kandidaten) und Geschlecht (2 Optionen)) ausgelegt ist. Dies kann jedoch leicht erweitert werden. Ansprechbar sind diese über folgende API:

Wahlamt:

- /pkSig (GET Request - gibt den öffentlichen Signatur-Schlüssel zurück, welcher für die Verifikation der AGHO Bildsignatur gebraucht wird)
- /sign (POST Request - signiert einen verblindeten ElGamal verschlüsselten Stimmzettel, wenn die gegebene Person noch keine Stimme abgegeben hat und die Wahl noch läuft). Für die Signatur müssen folgende Parameter an den Server übermittelt werden:
  - username (Username der Zugangsdaten des Wählers)
  - password (Passwort der Zugangsdaten des Wählers)
  - c11, c12, c21, c22 (Komponenten der verblindeten ElGamal Verschlüsselung)
  - P11, P12, P21, P22 (Komponenten des verblindeten Pads)
  - g, vk (der öffentliche Parameter g aus G1 und der Verifikationsschlüssel)
  - G1, G2, G3 (die Client-seitigen Rauschfaktoren)
  - ch, r1, r2, r3, r4, r5 (Challenge und Responses für den Zero-Knowledge Proof)
  - m (die Nachricht bestehend aus den nicht privaten Attributen)

- /reset (GET Request - setzt die Wähler-Datenbank und die Stimmzettel-Datenbank sowie den Wahlstatus zurück)

Auszählbehörde:

- /pkEV (GET Request - gibt den öffentlichen Verschlüsselungs-Schlüssel zurück, welcher für die Verschlüsselung des Stimmzettels gebraucht wird)
- /vote (POST Request - um eine signierte Encrypted Vote an die Auszählbehörde weiterzuleiten). Für das Abgeben des Stimmzettels müssen folgende Parameter an den Server übermittelt werden:
  - c11, c12, c21, c22 (der ElGamal verschlüsselte Stimmzettel)
  - R, S, T (die AGHO Signatur)
  - V, W0, W1, W2, W3, Z (der öffentliche Signatur-Schlüssel für die AGHO Blindsignatur)
  - h (der öffentlich bekannte Parameter aus G2)
- /count (POST Request - um eine Auszählung der Wahl zu indizieren). Für das Auszählen der Stimmen müssen folgende Parameter an den Server übermittelt werden:
  - cand1, cand2, cand3 (die Kandidaten, welche zur Auswahl stehen)
  - sex1, sex2 (die Geschlechter, welche zur Auswahl stehen)
- /reset (GET Request - setzt die Wähler-Datenbank und die Stimmzettel-Datenbank sowie den Wahlstatus zurück)
- /wbb (POST Request - gibt die Daten für das Web Bulletin Board zurück). Für das Erhalten der Daten für das Web Bullein Board müssen folgende Parameter an den Server übermittelt werden:
  - cand1, cand2, cand3 (die Kandidaten, welche zur Auswahl stehen)
  - sex1, sex2 (die Geschlechter, welche zur Auswahl stehen)

Zu beachten ist, dass die Parameter immer die serialisierten Varianten der Elemente aus G1, G2, GT oder ZR sein müssen.

## Bedienung des Clients

Wenn der vorhandene Client verwendet werden soll und gestartet wird, so stehen 5 Optionen zur Auswahl

- Eine Stimme abgeben
- Auszählung starten
- Web Bulletin Board anzeigen lassen
- Den Wahlstatus zurücksetzen
- Das Programm verlassen

Bei jedem der Auswahlmöglichkeiten ist die benötigte Vorgehensweise im Programm beschrieben. Sollte ein Fehler auftreten, wird ausgegeben, was die Ursache für diesen Fehler ist.

## Testen

Um die kryptographische Bibliothek zu testen werden 4 Testklassen zur Verfügung gestellt:

- charmLibraryTests.py
- ElGemaltests.py
- AGHOTests.py
- ZKPTests.py

Um die einzelnen Tests durchzuführen, können die jeweiligen Testklassen folgendermaßen aufgerufen werden:

```sh
python3 testKlassenName.py
```

Achtung!: bei der Testklasse ***charmLibraryTests.py*** produziert der Single Exponent Proof der Gruppe G2 einen Fehler aufgrund eines Serialisierungsfehlers in der Charm Library.

## Referenzen

***AGHO Signatur:*** Masayuki Abe, Jens Groth, Kristiyan Haralambiev, and Miyako Ohkubo. Optimal Structure-Preserving Signatures in Assymetric Bilinear Groups. Lecture Notes in Computer Science, 6841, 2011

***Restriktive AGHO Blindsignatur:*** Ulrich Haböck and Stephan Krenn. Breaking and Fixing Anonymous Credentials for the Cloud. Cryptology and Network Security, pages 249–269, 2019.

***Charm Library:*** Mattew Green. Charm: A Framework for Rapidly Prototyping Cryptosystems, 2019. https://github.com/JHUISI/charm 
