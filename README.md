# AGHO_Blind_kryptlib

Eine Kryptographische Bibliothek, welche die auf der AGHO Signatur basierende restriktive AGHO Blindsignatur, sowie eine prototypische Implementierung eines Client-Server Modells bereitstellt.

## Requirements

- Installation von Python3
- Installation der Charm Library ()
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
Username: testuser2
Passwort: reallysecurepassword123

Der Client kann folgendermaßen gestartet werden:

```sh
python3 PythonVoterAPI.py
```

## Referenzen

***AGHO Signatur:*** Masayuki Abe, Jens Groth, Kristiyan Haralambiev, and Miyako Ohkubo. Optimal Structure-Preserving Signatures in Assymetric Bilinear Groups. Lecture Notes in Computer Science, 6841, 2011

***Restriktive AGHO Blindsignatur:*** Ulrich Haböck and Stephan Krenn. Breaking and Fixing Anonymous Creden- tials for the Cloud. Cryptology and Network Security, pages 249–269, 2019.

***Charm Library:*** Mattew Green. Charm: A Framework for Rapidly Prototyping Cryptosystems, 2019. https://github.com/JHUISI/charm 