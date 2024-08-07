De Google Workspace Target Connector maakt het mogelijk Google Workspace - voorheen beschikbaar als Google G Suite - via de Identity & Access Management (IAM)-oplossing HelloID van Tools4ever aan diverse bronsystemen te koppelen. Met behulp van deze integratie verbeter je onder meer het beheer van toegangsrechten en gebruikersaccounts. De koppeling automatiseert deze processen in Google Workspace, waarbij gegevens uit je bronsysteem altijd leidend zijn. Niet alleen bespaar je zo tijd, ook stel je zeker dat je foutloos werkt. In dit artikel lees je meer over deze koppeling en de mogelijkheden.

## Wat is Google Workspace?

Google Workspace is een allesomvattend softwarepakket dat jouw bedrijf ondersteunt. Het pakket maakt voor veel bedrijven alle software die zij nodig hebben in één keer beschikbaar, wat de softwaresuite extra aantrekkelijk maakt. Google Workspace is vanuit de cloud beschikbaar, wat betekent dat je geen software lokaal hoeft te installeren. De softwaresuite ondersteunt daarnaast nieuwe manieren van samenwerken, die de productiviteit naar een hoger niveau kunnen tillen. 

## Waarom is Google Workspace koppeling handig?

Werknemers hebben toegang tot de juiste systemen en data nodig om optimaal productief te zijn, wat vraagt om de juiste gebruikersaccounts en autorisaties. Het beheer van accounts is een belangrijk onderdeel van het IDU-proces (Instroom, Doorstroom en Uitstroom), en brengt extra handelingen met zich mee. Tegelijkertijd is compliance een cruciaal aandachtspunt; je wilt borgen en kunnen aantonen dat je autorisaties op het juiste moment toekent en ontneemt. Het koppelen van Google Workspace aan je bronsystemen via HelloID helpt hierbij en neemt je werk uit handen.

Je kunt Google Workspace via de Google Workspace connector onder meer koppelen aan:

*	AFAS
*	Somtoday/Magister

Verdere details over de koppeling met deze bronsystemen zijn te vinden verderop in het artikel.

## HelloID voor Google Workspace helpt je met

**Uniform accountbeheer:** De Google Workspace Target Connector biedt je de zekerheid van uniform accountbeheer. De connector zorgt dat je accounts op consistente wijze beheert, en voorkomt daarbij fouten. Zo weet je zeker dat gebruikers altijd op het juiste moment over een Google Workspace-account beschikken, zodat zij optimaal productief kunnen zijn.

**Aansluiting op het IDU-proces van de organisatie:** Je organisatie is continu in beweging. Dat geldt ook voor je personeelsbestand. Zo stromen nieuwe werknemers in, veranderen medewerkers van functie en verlaat personeel de organisatie. De Google Workspace Target Connector zorgt dat het beheer van gebruikersaccount altijd volledig in lijn is met het IDU-proces binnen je organisatie. 

**Verbeterde efficiëntie:** Met een koppeling tussen je bronsystemen en Google Workspace kan je Google Workspace-accounts sneller aanmaken en deze accounts efficiënter beheren. De integratie automatiseert account provisioning in belangrijke mate. Zodra een nieuw account is toegevoegd aan je bronsysteem, detecteert HelloID deze wijziging en maakt automatisch een Google Workspace-account aan. Zo kunnen medewerkers sneller aan de slag en zijn zij eerder productief.

**Verbeterde compliance:** Door je bronsystemen via HelloID met Google Workspace te koppelen beschik je over een volledige audittrail. De IAM-oplossing legt alle acties en mutaties tot in details vast. Zo ben je altijd in control en kan je compliance met wet- en regelgeving aantonen.

## Hoe HelloID integreert met Google Workspace

De Google Workspace connector maakt gebruik van de Google Admin API, waarbij het specifiek gaat om de directory/V1 endpoints voor users, groups en customers. De Google Workspace connector gebruikt persoonsgegevens uit HelloID, en creëert op basis hiervan een gebruikersaccount. Uitsluitend het resulterende account wordt naar de Google API gestuurd.

| Wijziging in bronsysteem |	Procedure in Google Workspace |
| ------------------------- | ----------------------------- | 
| **Nieuwe medewerker**	| Indien een nieuwe medewerker in dienst treedt, moet deze gebruiker zo snel mogelijk aan de slag kunnen. Dit vraagt om de juiste accounts en autorisaties. Dankzij de integratie tussen je bronsystemen en Google Workspace kan HelloID automatisch een gebruikersaccount aanmaken in Google Workspace, zonder dat je hiernaar omkijken hebt. Ook kent HelloID direct de benodigde autorisaties toe.|
| **Andere functie medewerker**	| Wijzigt de functie van een medewerker? Dan kan dit ook van invloed zijn op autorisaties die deze gebruiker nodig heeft. Dankzij de koppeling verwerkt HelloID de functiewijziging direct in de autorisaties voor Google Workspace.|
| **Medewerker treedt uit dienst** |	HelloID deactiveert bij uitdiensttreding automatisch het gebruikersaccount in Google Workspace en informeert betrokkenen hierover. Na verloop van tijd verwijdert HelloID automatisch het Google Workspace-account van de oud-medewerker.| 

De connector ondersteunt dynamische permissies. Belangrijk om daarbij op te merken is dat dynamische permissies in HelloID altijd volledig op basis van brondata werken. Zo kan je bijvoorbeeld met behulp van één business rule alle afdelingsgroepen inregelen. Om dit mogelijk te maken zoekt HelloID naar correlaties tussen de brongegevens en desbetreffende groepen. 

In tegenstelling tot niet-dynamische permissies bewegen dynamische permissies altijd mee met veranderingen in de structuur van je organisatie. Richt je bijvoorbeeld een nieuwe afdeling op? Dan herkent HelloID deze wijziging in je bronsysteem, maakt indien nodig de juiste groepen aan en wijst vervolgens tijdens het IDU-proces accounts toe aan de juiste groepen. Een volledig audittrail van dit proces is beschikbaar in HelloID.

## Gegevensuitwisseling op maat

Een belangrijk voordeel van HelloID is dat je altijd aan de knoppen staat en de controle behoudt. De integratie van je bronsystemen en Google Workspace is daarop geen uitzondering. Je bepaalt dan ook altijd tot in detail welke gegevens je uitwisselt, en hoe je dit doet. De configuratie van de Google Workspace connector bepaalt exact hoe een account wordt opgebouwd. Je kunt de manier van bijwerken volledig afstemmen op de updateroutine van de connector. 

Tools4ever ondersteunt je uiteraard bij het inrichten van de connector. Zo gaat dit altijd gepaard met een intake- en designsessie. Daarbij leggen we in een intake-document exact vast hoe een account moet worden aangemaakt. Ook bepalen we naamgevingsconventies, waarmee we specificeren hoe je een gebruikersnaam wilt opbouwen en wat HelloID moet doen indien deze gebruikersnaam niet beschikbaar is. 

## Google Workspace via HelloID koppelen met systemen

HelloID maakt het integreren van diverse bronsystemen met Google Workspace mogelijk. De koppelingen tillen het beheer van gebruikers en autorisaties naar een hoger niveau. Enkele veelvoorkomende integraties zijn:

**AFAS - Google Workspace koppeling:** Deze koppeling houdt AFAS en Google Workspace volledig in sync. Je kunt belangrijke attributen uit AFAS zoals de naam, functie en afdeling van personeel overnemen in Google Workspace. Zo stroomlijn je het beheer van accounts en autorisaties voor werknemers.

**Somtoday/Magister - Google Workspace koppeling:** Vaak maken scholen gebruik van Somtoday of Magister. Met behulp van de Google Workspace Target Connector koppel je deze elektronische leeromgevingen eenvoudig aan Google Workspace. Zo weet je zeker dat leerlingen op het juiste moment over de juiste accounts en autorisaties beschikken om optimaal hun opleiding te volgen.  

HelloID ondersteunt ruim 200 connectoren. Een breed scala aan integratiemogelijkheden tussen Google Workspace en andere bron- en doelsystemen is dan ook beschikbaar. We breiden ons aanbod aan connectoren en integraties continu uit, waardoor je met alle populaire systemen kunt integreren.
