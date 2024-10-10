
Le Connecteur cible Google Workspace permet de connecter Google Workspace, anciennement connu sous le nom de Google G Suite, à divers systèmes sources via la solution de gestion des identités et des accès (GIA) HelloID de Tools4ever. Grâce à cette intégration, vous améliorez la gestion des droits d'accès et des comptes utilisateurs, tout en automatisant ces processus dans Google Workspace. Les données provenant de votre système source sont toujours prioritaires, vous permettant ainsi de gagner du temps tout en assurant un fonctionnement sans erreurs. Dans cet article, nous vous présentons cette intégration et ses possibilités.

## Qu’est-ce que Google Workspace ?

Google Workspace est une suite logicielle complète qui regroupe l’ensemble des outils logiciels dont la plupart des entreprises ont besoin, ce qui le rend particulièrement attrayant. Google Workspace est accessible depuis le cloud, ce qui signifie qu’il n’y a pas besoin d’installer de logiciels en local. De plus, cette suite facilite de nouvelles méthodes de collaboration, améliorant ainsi la productivité. 

## Pourquoi connecter Google Workspace est-il avantageux ?

Pour que vos employés soient pleinement productifs, ils ont besoin d'un accès rapide aux systèmes et aux données appropriés, ce qui implique de disposer des bons comptes utilisateurs et des bonnes autorisations. La gestion des comptes est un aspect clé du processus IES (Intégration, Évolution, Sortie) et peut être fastidieuse. Parallèlement, la conformité est un enjeu crucial : vous devez garantir et démontrer que vous attribuez et retirez les droits d'accès au bon moment. En connectant Google Workspace à vos systèmes sources via HelloID, vous facilitez cette tâche tout en réduisant votre charge de travail.

Vous pouvez connecter Google Workspace à des systèmes tels que :

*	ADP
*	SAP RH
*	ASTRE RH
*	CYRILL
*	YPAREO
*	Etc.

Des informations supplémentaires sur l'intégration avec ces systèmes sources sont disponibles plus loin dans cet article.

## Comment HelloID améliore votre gestion de Google Workspace ?

**Gestion unifiée des comptes :** Le connecteur cible Google Workspace vous assure une gestion uniforme des comptes utilisateurs. Elle permet une gestion cohérente et prévient les erreurs, garantissant ainsi que les utilisateurs disposent de leur compte Google Workspace au bon moment pour être pleinement productifs.

**Alignement sur le processus IES de l’organisation :** Votre organisation évolue constamment, et il en va de même pour votre personnel. Des employés rejoignent l’entreprise, d'autres changent de poste, et certains la quittent. Le connecteur cible Google Workspace garantit que la gestion des comptes utilisateurs est toujours en phase avec le processus IES de votre organisation.

**Amélioration de l’efficacité :** En connectant vos systèmes sources à Google Workspace, vous pouvez créer des comptes utilisateurs plus rapidement et les gérer plus efficacement. L'intégration permet d’automatiser une grande partie de la gestion des comptes. Dès qu’un nouveau compte est ajouté à votre système source, HelloID détecte ce changement et crée automatiquement un compte Google Workspace, permettant ainsi à vos employés de commencer leur travail sans délai.

**Amélioration de la conformité :** En connectant vos systèmes sources à Google Workspace via HelloID, vous disposez d’un audit complet de toutes les actions effectuées. La solution de GIA enregistre toutes les actions et modifications dans le détail, vous permettant ainsi de démontrer votre conformité aux lois et réglementations en vigueur.

## Comment HelloID s’intègre à Google Workspace ?

Nous utilisons l’API de Google directory/V1 pour les utilisateurs, les groupes et les clients. Le connecteur utilise les données issues d'HelloID pour créer des comptes utilisateurs, et seul le compte résultant est transmis à l’API Google.

Voici comment HelloID gère les changements dans le système source et leur impact dans Google Workspace :

| Changement dans le système source |	Procédure dans Google Workspace |
| -------------------------------- | -------------------------------- | 
| Nouvel employé |	Lorsqu'un nouvel employé rejoint l'entreprise, il doit être opérationnel le plus rapidement possible. Cela nécessite la création des bons comptes et l'attribution des autorisations appropriées. Grâce à l'intégration entre vos systèmes sources et Google Workspace, HelloID crée automatiquement un compte utilisateur dans Google Workspace, sans intervention manuelle. HelloID attribue également les autorisations nécessaires à l'utilisateur.|
| Changement de fonction |	Si un employé change de poste, cela peut affecter les autorisations dont il a besoin. Grâce à la connexion, HelloID ajuste immédiatement les autorisations dans Google Workspace en fonction du nouveau poste. |
| Départ de l'employé |	Lorsqu'un employé quitte l'entreprise, HelloID désactive automatiquement le compte utilisateur dans Google Workspace et en informe les parties concernées. Après une certaine période, HelloID supprime automatiquement le compte Google Workspace de l'ancien employé.|


Le connecteur prend également en charge les permissions dynamiques. Il est important de noter que ces permissions sont toujours basées sur les données sources. Par exemple, vous pouvez configurer une règle métier qui gère automatiquement les groupes de services et/ou de département. HelloID recherche des corrélations entre les données sources et les groupes concernés, puis attribue les comptes aux bons groupes pendant le processus IES.

Contrairement aux permissions statiques, les permissions dynamiques s’adaptent aux changements dans la structure organisationnelle. Par exemple, si vous créez un nouveau département ou service, HelloID détecte ce changement dans le système source, crée les groupes nécessaires, et attribue les comptes utilisateurs aux bons groupes. Un audit complet de ce processus est disponible dans HelloID.

## Échange de données sur mesure

Un des avantages majeurs d'HelloID est que vous gardez toujours le contrôle. L’intégration entre vos systèmes sources et Google Workspace ne fait pas exception. Vous avez la possibilité de définir précisément quelles données sont échangées et comment. La configuration du connecteur Google Workspace détermine exactement comment un compte est créé, et vous pouvez adapter cette configuration pour correspondre à vos besoins spécifiques.

Tools4ever vous accompagne également dans la mise en place du connecteur. Ce processus inclut une session d'évaluation et de conception, pendant laquelle nous définissons précisément la manière dont les comptes doivent être créés. Nous établissons également des conventions de nommage, pour déterminer comment un nom d’utilisateur doit être structuré et comment HelloID doit réagir si ce nom d’utilisateur est déjà assigné (doublon). 

## Intégration de Google Workspace avec d’autres systèmes
HelloID permet d’intégrer plusieurs systèmes sources à Google Workspace. Ces intégrations améliorent considérablement la gestion des utilisateurs et des autorisations. Parmi les intégrations les plus courantes, on trouve :

* **Intégration ADP – Google Workspace :** Cette intégration assure la synchronisation complète entre ADP et Google Workspace. Vous pouvez transférer des attributs importants d’ADP, tels que le nom, le poste et le département, directement dans Google Workspace. Cela permet de rationaliser la gestion des comptes et des autorisations des employés.

* **YPAREO – Google Workspace :** De nombreuses écoles utilisent YPAREO comme environnement d’apprentissage numérique. Le connecteur cible Google Workspace vous permet de connecter facilement ces plateformes à Google Workspace, garantissant ainsi que les étudiants ont les bons comptes et autorisations pour suivre leur formation.

HelloID prend en charge plus de 200 connecteurs. Cela vous offre un large éventail de possibilités d’intégration entre Google Workspace et d’autres systèmes sources ou cibles. Nous continuons d’élargir notre gamme de connecteurs et d’intégrations, vous permettant ainsi de connecter tous les systèmes populaires. 
