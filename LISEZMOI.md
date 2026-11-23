# SignaPro — signature de documents

Application web installable (PWA) pour signer des PDF et des photos de documents :
signature, paraphe, cachet, date et texte. Tout se passe sur l'appareil : aucun fichier n'est envoyé sur internet.
Elle fonctionne sur Android, Windows, Mac, Linux et iPhone/iPad, et aussi sans connexion après la première ouverture.

## Mettre l'application en ligne gratuitement (GitHub Pages)

À faire une seule fois, depuis un ordinateur (c'est plus simple qu'avec un téléphone).

1. Créez un compte gratuit sur **github.com**.
2. Cliquez sur **New repository**. Nom : `signapro`. Choisissez **Public** (obligatoire pour l'hébergement gratuit). Cliquez sur **Create repository**.
3. Sur la page du dépôt, cliquez sur **uploading an existing file**.
4. Dézippez `signapro.zip`, puis **glissez tout le contenu du dossier `signapro`** dans la page
   (les fichiers `index.html`, `app.js`, `style.css`, `sw.js`, `manifest.webmanifest` **et** les dossiers `lib` et `icons`).
   GitHub ne dézippe pas lui-même : il faut déposer les fichiers, pas le zip.
5. Cliquez sur **Commit changes**.
6. Allez dans **Settings › Pages**. Sous *Build and deployment*, choisissez **Deploy from a branch**,
   branche **main**, dossier **/ (root)**, puis **Save**.
7. Attendez 1 à 2 minutes. L'adresse apparaît en haut de la page :
   `https://VOTRE-NOM.github.io/signapro/`

Le dépôt est public : n'importe qui peut voir le code de l'application. Il ne contient aucune donnée de l'entreprise
(votre signature n'est jamais dans le dépôt, elle reste sur chaque appareil).

## Installer sur chaque appareil

- **Android (Chrome)** : ouvrez l'adresse, menu ⋮ › **Installer l'application**.
- **PC (Chrome ou Edge)** : ouvrez l'adresse, cliquez sur l'icône d'installation dans la barre d'adresse.
- **iPhone / iPad (Safari)** : bouton Partager › **Sur l'écran d'accueil**.

Ouvrez l'application une première fois avec internet : elle se met en cache et marche ensuite sans connexion.

## Utilisation

1. **Ouvrir** un PDF ou une photo. Un fichier Word doit d'abord être enregistré en PDF.
2. **Signature** : la première fois, dessinez-la (doigt, stylet ou souris). Puis touchez la page à l'endroit voulu.
3. Glissez pour déplacer, tirez le point bleu pour agrandir, touchez × pour supprimer.
4. **Cachet** : importez une photo du cachet (fond blanc rendu transparent automatiquement).
5. **Date** et **Texte** (« Lu et approuvé », « Bon pour accord »…).
6. **Exporter**, puis **Télécharger** ou **Partager** (WhatsApp, e-mail).

La signature, le paraphe et le cachet sont enregistrés dans le navigateur de chaque appareil.
Il faut les refaire une fois sur chaque appareil, et ils disparaissent si vous effacez les données du site.

## Sécurité (code PIN)

Dans **Réglages › Sécurité › Activer un code PIN** (4 à 8 chiffres) :
- l'application démarre verrouillée ;
- elle se verrouille seule après 3 minutes d'inactivité, ou si elle reste plus d'une minute en arrière-plan ;
- la signature, le paraphe et le cachet sont **chiffrés** sur l'appareil (AES-256) : sans le code, ils sont illisibles ;
- après 5 codes faux, l'application impose une attente de plus en plus longue.

Si le code est oublié, personne ne peut le récupérer : « Code oublié ? » efface la signature et le cachet enregistrés,
et il faut les refaire.

## Commandes Git (option, à la place du dépôt par glisser-déposer)

Si Git est installé sur le PC, depuis le dossier `signapro` :

```
git init
git add .
git commit -m "SignaPro"
git branch -M main
git remote add origin https://github.com/VOTRE-NOM/signapro.git
git push -u origin main
```

Ensuite, activez **Settings › Pages** comme indiqué plus haut.

## Limites

- La signature est une image posée sur le PDF, comme une signature scannée. Ce n'est pas une signature électronique certifiée
  (pas de certificat, pas d'horodatage vérifiable).
- Les PDF protégés par mot de passe ne sont pas pris en charge.
- Les fichiers Word, Excel et PowerPoint doivent être convertis en PDF avant.

## Mise à jour

Pour modifier l'application, remplacez les fichiers dans le dépôt GitHub. Dans `sw.js`, changez `signapro-v2` en `signapro-v3`
pour que les appareils récupèrent la nouvelle version.

## Technique

HTML, CSS et JavaScript sans framework. Bibliothèques incluses dans `lib/` : pdf.js (affichage, licence Apache 2.0)
et pdf-lib (écriture du PDF signé, licence MIT).
