# Failles de securite

Les lignes indiquees correspondent a la version vulnerable avant correction.

## 1. XSS stockee dans les commentaires

Fichier : [Views/Home/Comments.cshtml](sanssoussi/Sanssoussi/Views/Home/Comments.cshtml#L14)

```cshtml
@Html.Raw(comment)
```

Le commentaire est rendu comme du HTML sans encodage. Un script injecte dans un commentaire est execute par le navigateur de chaque visiteur.

Impact : fenetres modales, vol de donnees du navigateur et actions executees avec la session de la victime.

## 2. XSS stockee dans la recherche

Fichier : [Views/Home/Search.cshtml](sanssoussi/Sanssoussi/Views/Home/Search.cshtml#L17)

```cshtml
@Html.Raw(result)
```

Les resultats de recherche sont rendus sans encodage. Un commentaire malveillant est donc execute aussi depuis cette page.

## 3. Injection SQL dans la lecture des commentaires

Fichier : [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L50)

```csharp
var cmd = new SqliteCommand($"Select Comment from Comments where UserId ='{user.Id}'", this._dbConnection);
```

La requete est construite par interpolation au lieu d'utiliser un parametre SQL.

## 4. Injection SQL dans l'ajout d'un commentaire

Fichier : [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L76-L78)

```csharp
var cmd = new SqliteCommand(
    $"insert into Comments (UserId, CommentId, Comment) Values ('{user.Id}','{Guid.NewGuid()}','" + comment + "')",
    this._dbConnection);
```

`comment` vient directement de la requete POST et est concatene dans la requete SQL. Un guillemet dans la valeur peut en modifier la structure.

## 5. Injection SQL dans la recherche

Fichier : [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L98)

```csharp
var cmd = new SqliteCommand($"Select Comment from Comments where UserId = '{user.Id}' and Comment like '%{searchData}%'", this._dbConnection);
```

`searchData` vient du parametre HTTP et est concatene dans la requete SQL.

## 6. CSRF sur la creation d'un commentaire

Fichier : [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L65-L82)

L'action POST `Comments` ne possedait pas `[ValidateAntiForgeryToken]`. L'appel AJAX n'envoyait pas non plus de jeton antiforgery.

Un site externe pouvait tenter de faire envoyer une requete POST par un navigateur deja authentifie.

## 7. Controle d'acces insuffisant pour les adresses courriel

Fichier : [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L112-L132)

Le role etait verifie uniquement dans le corps de l'action :

```csharp
var roles = await this._userManager.GetRolesAsync(user);
if (roles.Contains("admin"))
{
    // Lecture des adresses courriel
}
```

L'action ne possedait pas `[Authorize(Roles = "admin")]`. La regle d'acces n'etait donc pas declarative au niveau de l'action.

## 8. XSS DOM dans l'affichage des courriels

Fichier : [wwwroot/js/emails.js](sanssoussi/Sanssoussi/wwwroot/js/emails.js#L8-L9)

```javascript
emails += item + "<br/>";
$("#emailData").html(emails);
```

Les valeurs recues de l'API etaient inserees dans le DOM comme du HTML. Une valeur malveillante pouvait donc etre executee dans le navigateur de l'administrateur.

## 9. Connexion SQLite partagee et non fermee

Fichier : [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L20) et [Controllers/HomeController.cs](sanssoussi/Sanssoussi/Controllers/HomeController.cs#L79-L82)

La connexion SQLite etait conservee dans un champ du controleur. L'action POST l'ouvrait sans la fermer apres `ExecuteNonQueryAsync()`.

Impact : fuite de ressource et erreurs lors de requetes concurrentes.

---

# Mesures de securite ajoutees

## A. Correctifs de code (OWASP Top 10)

### Failles 1, 2 et 8 : XSS (commentaires, recherche, courriels)
- Categorie OWASP : A03 Injection
- Correctif : `@Html.Raw` remplace par `@comment` et `@result` (encodage Razor); `.html()` remplace par `.text()` dans `emails.js`.

### Failles 3, 4 et 5 : injection SQL
- Categorie OWASP : A03 Injection
- Correctif : requetes parametrees (`$userId`, `$comment`, `$search`).

### Faille 6 : CSRF
- Categorie OWASP : A01 Broken Access Control / A04 Insecure Design
- Correctif : `[ValidateAntiForgeryToken]` sur le POST, jeton present dans les vues et envoye par l'appel AJAX.

### Faille 7 : controle d'acces
- Categorie OWASP : A01 Broken Access Control
- Correctif : `[Authorize]` sur Comments et Search, `[Authorize(Roles = "admin")]` sur Emails.

### Faille 9 : connexion SQLite partagee
- Categorie OWASP : A05 Security Misconfiguration
- Correctif : une connexion par action, fermee avec `await using`.

## B. Cookies et Web Storage

**Cookie d'authentification** (`Startup.cs`) : `HttpOnly` (illisible par JavaScript, donc un XSS ne peut pas le voler), `Secure` (jamais envoye en HTTP) et `SameSite=Lax` (non envoye lors d'un POST venant d'un autre site, ce qui complete la protection CSRF).

**Web Storage** (`wwwroot/js/site.js`) : l'etat de navigation qui n'a pas besoin d'aller au serveur est maintenant garde dans `sessionStorage` plutot que dans des cookies :

- le brouillon d'un commentaire non envoye (`sanssoussi.commentDraft`), restaure si on change de page puis qu'on revient, et efface apres l'envoi;
- le dernier terme recherche (`sanssoussi.lastSearch`).

Pourquoi c'est plus sur qu'un cookie pour ces donnees :

- les cookies sont envoyes automatiquement a chaque requete, ce qui les expose au CSRF et a l'interception; le Web Storage n'est lu que par le script de la page et n'est jamais transmis au serveur;
- `sessionStorage` est limite a un onglet et a une origine, et disparait a la fermeture de l'onglet (`localStorage` aurait garde les donnees indefiniment);
- la capacite est bien plus grande (environ 5 Mo contre 4 Ko par cookie).

Limite connue : le Web Storage est lisible par n'importe quel script de la meme origine, donc un XSS pourrait le lire. C'est pourquoi on n'y met aucun jeton ni identifiant (la session reste dans le cookie `HttpOnly`) et que les valeurs ne sont relues que par `.val()`, jamais injectees comme HTML. Les acces sont dans des `try/catch` pour que le site fonctionne meme si le stockage est desactive.

## C. En-tetes de securite (`Startup.cs`)

### Content-Security-Policy
- Valeur : `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`
- Role : le navigateur refuse tout script ou style qui ne vient pas du site, ce qui limite fortement l'effet d'un XSS qui aurait echappe a l'encodage.

### X-Content-Type-Options
- Valeur : `nosniff`
- Role : empeche le navigateur de deviner un autre type MIME (par exemple executer un fichier texte comme du script).

### X-Frame-Options
- Valeur : `DENY`
- Role : empeche d'afficher le site dans une iframe (clickjacking).

### Referrer-Policy
- Valeur : `strict-origin-when-cross-origin`
- Role : limite les informations envoyees dans l'en-tete Referer.

### Permissions-Policy
- Valeur : `camera=(), microphone=(), geolocation=()`
- Role : desactive des API sensibles inutilisees.

Pour que la CSP puisse interdire les scripts en ligne, le code a ete adapte :

- le script en ligne de `_Layout.cshtml` a ete retire; l'URL de base passe par l'attribut `data-base-url` du `<body>` et `ResolveUrl` est dans `site.js`;
- les attributs `onclick` de `Comments.cshtml` et `Search.cshtml` sont remplaces par des ecouteurs `.on("click", ...)` dans `site.js`;
- les attributs `style` (`Comments.cshtml`, `TwoFactorAuthentication.cshtml`) sont remplaces par les classes Bootstrap `d-none` et `d-inline-block`.

Le parametre de recherche est aussi encode avec `encodeURIComponent` avant d'etre place dans l'URL.

## D. Politique de mots de passe et verrouillage de compte

Configures dans `Areas/Identity/IdentityHostingStartup.cs` (OWASP A07 Identification and Authentication Failures) :

- mot de passe : 12 caracteres minimum, avec majuscule, minuscule, chiffre et caractere special, et au moins 4 caracteres differents (la validation de `Register.cshtml.cs` a ete alignee sur 12);
- verrouillage : apres 5 echecs de connexion, le compte est bloque 15 minutes. `Login.cshtml.cs` utilise maintenant `lockoutOnFailure: true`; avant, les echecs n'etaient jamais comptes, ce qui permettait de deviner un mot de passe sans limite;
- `RequireUniqueEmail = true` et confirmation du courriel obligatoire (`RequireConfirmedAccount`, deja present).

## E. HTTPS, HSTS et CORS

- **HTTPS** : `UseHttpsRedirection()` redirige tout le trafic HTTP vers HTTPS, et `launchSettings.json` expose `https://localhost:5001`.
- **HSTS** : `UseHsts()` (hors developpement) indique au navigateur de n'utiliser que HTTPS pour ce site, ce qui empeche le retrogradage vers HTTP.
- **CORS** (`Startup.cs`) : par defaut un navigateur interdit a une page d'un autre site de lire les reponses de l'application. La politique configuree n'autorise que les origines listees dans `Cors:AllowedOrigins` (aucune par defaut), les methodes GET et POST et les en-tetes `Content-Type` et `RequestVerificationToken`. Cela evite d'ouvrir l'application a n'importe quel domaine.
- **Lien avec le CSRF** : CORS ne remplace pas le jeton antiforgery (un formulaire d'un autre site peut quand meme envoyer un POST), c'est pourquoi les deux sont presents, avec le cookie `SameSite`.

## F. Authentification deleguee : OpenID Connect avec Google

L'identite est basee sur les revendications (claims) et l'authentification est deleguee a Google, qui implemente OpenID Connect (couche d'identite au-dessus d'OAuth 2.0). Le site ne recoit jamais le mot de passe de l'utilisateur.

- paquet `Microsoft.AspNetCore.Authentication.Google` et `AddGoogle(...)` dans `Startup.cs`;
- le `ClientId` et le `ClientSecret` ne sont pas dans le code : ils sont dans les secrets utilisateur (`dotnet user-secrets`, `UserSecretsId` dans le `.csproj`), lus via `Authentication:Google:*`;
- URI de redirection autorisee dans la console Google : `https://localhost:5001/signin-google`;
- la page de connexion affiche le bouton Google, et le compte est lie a un utilisateur Identity local.

Flux : l'utilisateur clique sur Google, est redirige vers Google, s'authentifie, puis revient sur `/signin-google` avec un code echange cote serveur contre un jeton d'identite (claims : identifiant, courriel). ASP.NET Identity cree ensuite la session locale.

## G. Gains de securite de la migration vers ASP.NET Core

- **Anti-CSRF integre** : jetons antiforgery generes par les Tag Helpers de formulaire et attribut `[ValidateAntiForgeryToken]` (ou filtre global `AutoValidateAntiforgeryToken`).
- **Encodage de sortie par defaut** : Razor encode en HTML toute valeur affichee; il faut ecrire `Html.Raw` explicitement pour contourner la protection.
- **ASP.NET Core Identity** : hachage des mots de passe (PBKDF2 avec sel et iterations), verrouillage, 2FA, confirmation de courriel, connexion externe.
- **Autorisation declarative** : `[Authorize]`, roles, politiques et revendications.
- **Protection des donnees (Data Protection API)** : chiffrement et signature des cookies d'authentification et des jetons, avec rotation des cles.
- **HTTPS et HSTS** : integres au pipeline (`UseHttpsRedirection`, `UseHsts`), certificat de developpement.
- **CORS** : integre au pipeline, politiques par defaut ou nommees.
- **Authentification externe** : fournisseurs OpenID Connect / OAuth2 (Google, Microsoft, Facebook) via des paquets officiels.
- **Pipeline de middlewares explicite** : on voit et controle l'ordre des protections (en-tetes, authentification, autorisation).
- **Plus de ViewState** : disparition de classes d'attaques propres a Web Forms (ViewState falsifie).
- **Framework maintenu** : correctifs de securite reguliers (.NET 9), alors que ASP.NET classique (.NET Framework) n'evolue plus.
- **Configuration et secrets** : secrets utilisateur en developpement, variables d'environnement ou coffre-fort en production, sans mot de passe dans le code.
- **Pages d'erreur** : `UseExceptionHandler` en production pour ne pas exposer les traces de pile.
