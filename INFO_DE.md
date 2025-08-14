Der Google Workspace Target Connector ermöglicht es, Google Workspace — ehemals bekannt als Google G Suite — über die Identity & Access Management (IAM)-Lösung HelloID von Tools4ever an verschiedene Quellsysteme anzubinden. Mithilfe dieser Integration verbessern Sie unter anderem die Verwaltung von Zugriffsrechten und Benutzerkonten. Die Anbindung automatisiert diese Prozesse in Google Workspace, wobei die Daten aus Ihrem Quellsystem immer maßgeblich sind. So sparen Sie nicht nur Zeit, sondern stellen auch sicher, dass Sie fehlerfrei arbeiten. In diesem Artikel erfahren Sie mehr über diese Anbindung und die Möglichkeiten.

## Was ist Google Workspace?

Google Workspace ist ein umfassendes Softwarepaket, das Ihr Unternehmen unterstützt. Das Paket macht für viele Unternehmen alle benötigte Software auf einmal verfügbar, was die Softwaresuite besonders attraktiv macht. Google Workspace ist aus der Cloud verfügbar, was bedeutet, dass keine lokale Installation der Software erforderlich ist. Die Softwaresuite unterstützt zudem neue Formen der Zusammenarbeit, die die Produktivität auf ein höheres Niveau heben können.

## Warum ist die Google Workspace-Anbindung nützlich?

Mitarbeiter benötigen Zugang zu den richtigen Systemen und Daten, um optimal produktiv zu sein, was die richtigen Benutzerkonten und Berechtigungen erfordert. Die Verwaltung von Konten ist ein wichtiger Bestandteil des IDU-Prozesses (Onboarding, Versetzung und Offboarding) und bringt zusätzliche Aufgaben mit sich. Gleichzeitig ist Compliance ein entscheidender Punkt; Sie möchten gewährleisten und nachweisen können, dass Sie Berechtigungen zur richtigen Zeit erteilen und entziehen. Die Anbindung von Google Workspace an Ihre Quellsysteme über HelloID hilft dabei und nimmt Ihnen Arbeit ab.

Sie können Google Workspace über den Google Workspace Connector unter anderem mit folgenden Systemen verbinden:

* AFAS
* Somtoday/Magister

Weitere Details zur Anbindung mit diesen Quellsystemen sind im weiteren Verlauf des Artikels zu finden.

## HelloID für Google Workspace hilft Ihnen bei

**Einheitlichem Kontomanagement:** Der Google Workspace Target Connector bietet Ihnen die Sicherheit eines einheitlichen Kontomanagements. Der Connector sorgt dafür, dass Sie Konten konsistent verwalten und verhindert dabei Fehler. So können Sie sicher sein, dass Benutzer immer rechtzeitig über ein Google Workspace-Konto verfügen, um optimal produktiv zu sein.

**Eingliederung in den IDU-Prozess der Organisation:** Ihre Organisation ist ständig in Bewegung. Das gilt auch für Ihre Belegschaft. So treten neue Mitarbeiter ein, Mitarbeiter wechseln die Position und Personal verlässt die Organisation. Der Google Workspace Target Connector gewährleistet, dass das Management der Benutzerkonten immer vollständig im Einklang mit dem IDU-Prozess Ihrer Organisation steht.

**Verbesserte Effizienz:** Mit einer Anbindung zwischen Ihren Quellsystemen und Google Workspace können Sie Google Workspace-Konten schneller erstellen und diese Konten effizienter verwalten. Die Integration automatisiert maßgeblich die Kontoprovisionierung. Sobald ein neues Konto in Ihrem Quellsystem hinzugefügt wird, erkennt HelloID diese Änderung und erstellt automatisch ein Google Workspace-Konto. So können Mitarbeiter schneller anfangen zu arbeiten und früher produktiv sein.

**Verbesserte Compliance:** Durch die Anbindung Ihrer Quellsysteme an Google Workspace über HelloID verfügen Sie über einen vollständigen Audit-Trail. Die IAM-Lösung zeichnet alle Aktionen und Änderungen detailliert auf. So behalten Sie immer die Kontrolle und können die Einhaltung von Gesetzen und Vorschriften nachweisen.

## Wie HelloID mit Google Workspace integriert

Der Google Workspace Connector nutzt die Google Admin API, wobei es sich speziell um die directory/V1-Endpunkte für Benutzer, Gruppen und Kunden handelt. Der Google Workspace Connector verwendet personenbezogene Daten aus HelloID und erstellt daraufhin ein Benutzerkonto. Nur das resultierende Konto wird an die Google API gesendet.

| Änderung im Quellsystem | Prozedur in Google Workspace |
| ----------------------- | --------------------------- | 
| **Neuer Mitarbeiter**   | Tritt ein neuer Mitarbeiter ein, muss dieser schnellstmöglich arbeitsfähig sein. Dies erfordert die richtigen Konten und Berechtigungen. Dank der Integration zwischen Ihrem Quellsystem und Google Workspace kann HelloID automatisch ein Benutzerkonto in Google Workspace erstellen, ohne dass Sie sich darum kümmern müssen. Auch weist HelloID direkt die erforderlichen Berechtigungen zu. |
| **Änderung der Position eines Mitarbeiters** | Ändert ein Mitarbeiter seine Position? Dies kann auch Auswirkungen auf die benötigten Berechtigungen haben. Dank der Anbindung verarbeitet HelloID die Positionsänderung direkt in den Berechtigungen für Google Workspace. |
| **Mitarbeiter verlässt das Unternehmen** | Bei Austritt deaktiviert HelloID automatisch das Benutzerkonto in Google Workspace und informiert darüber die relevanten Personen. Nach einer gewissen Zeit wird das Google Workspace-Konto des ehemaligen Mitarbeiters automatisch von HelloID gelöscht. |

Der Connector unterstützt dynamische Berechtigungen. Wichtig zu beachten ist dabei, dass dynamische Berechtigungen in HelloID immer vollständig auf Basis der Quelldaten arbeiten. So können Sie beispielsweise mithilfe einer einzigen Business Rule alle Abteilungsgruppen einrichten. Um dies zu ermöglichen, sucht HelloID nach Korrelationen zwischen den Quelldaten und den jeweiligen Gruppen.

Im Gegensatz zu nicht-dynamischen Berechtigungen passen sich dynamische Berechtigungen immer an Veränderungen in der Organisationsstruktur an. Gründet man beispielsweise eine neue Abteilung, erkennt HelloID diese Änderung im Quellsystem, erstellt bei Bedarf die richtigen Gruppen und weist dann im Rahmen des IDU-Prozesses Konten den passenden Gruppen zu. Ein vollständiger Audit-Trail dieses Prozesses ist in HelloID verfügbar.

## Maßgeschneiderter Datenaustausch

Ein wesentlicher Vorteil von HelloID ist, dass Sie immer am Steuer sitzen und die Kontrolle behalten. Die Integration Ihrer Quellsysteme mit Google Workspace bildet da keine Ausnahme. Sie bestimmen immer bis ins Detail, welche Daten Sie austauschen und wie Sie dies tun. Die Konfiguration des Google Workspace Connector bestimmt genau, wie ein Konto aufgebaut wird. Sie können die Art der Aktualisierung vollständig auf die Updateroutine des Connectors abstimmen.

Tools4ever unterstützt Sie selbstverständlich bei der Einrichtung des Connectors. Dies geht stets mit einer Aufnahme- und Designsitzung einher. Dabei legen wir in einem Aufnahmedokument genau fest, wie ein Konto erstellt werden muss. Auch klären wir Namenskonventionen, mit denen wir spezifizieren, wie Sie einen Benutzernamen aufbauen möchten und was HelloID tun soll, falls dieser Benutzername nicht verfügbar ist.

## Google Workspace über HelloID mit Systemen verbinden

HelloID ermöglicht die Integration verschiedener Quellsysteme mit Google Workspace. Die Anbindungen heben die Verwaltung von Benutzern und Berechtigungen auf ein höheres Niveau. Einige häufige Integrationen sind:

**AFAS - Google Workspace Anbindung:** Diese Anbindung hält AFAS und Google Workspace vollständig synchron. Sie können wichtige Attribute aus AFAS wie den Namen, die Funktion und die Abteilung des Personals in Google Workspace übernehmen. So vereinfachen Sie das Management von Konten und Berechtigungen für Mitarbeiter.

**Somtoday/Magister - Google Workspace Anbindung:** Schulen nutzen oft Somtoday oder Magister. Mit dem Google Workspace Target Connector verbinden Sie diese elektronischen Lernumgebungen problemlos mit Google Workspace. So stellen Sie sicher, dass Schüler zur richtigen Zeit über die richtigen Konten und Berechtigungen verfügen, um optimal ihre Ausbildung zu verfolgen.

HelloID unterstützt über 200 Connectoren. Ein breites Spektrum an Integrationsmöglichkeiten zwischen Google Workspace und anderen Quellen- und Zielsystemen ist somit verfügbar. Wir erweitern unser Angebot an Connectoren und Integrationen kontinuierlich, sodass Sie mit allen gängigen Systemen integrieren können.