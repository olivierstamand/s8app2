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
