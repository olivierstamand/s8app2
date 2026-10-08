using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using Sanssoussi.Areas.Identity.Data;
using Sanssoussi.Models;

namespace Sanssoussi.Controllers
{
    public class HomeController : Controller
    {
        private readonly string _connectionString;

        private readonly ILogger<HomeController> _logger;

        private readonly UserManager<SanssoussiUser> _userManager;

        public HomeController(ILogger<HomeController> logger, UserManager<SanssoussiUser> userManager, IConfiguration configuration)
        {
            this._logger = logger;
            this._userManager = userManager;
            this._connectionString = configuration.GetConnectionString("SanssoussiContextConnection");
        }

        public IActionResult Index()
        {
            this.ViewData["Message"] = "Parce que marcher devrait se faire SansSoussi";
            return this.View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Comments()
        {
            var comments = new List<string>();

            var user = await this._userManager.GetUserAsync(this.User);
            if (user == null)
            {
                return this.View(comments);
            }

            await using var dbConnection = new SqliteConnection(this._connectionString);
            await dbConnection.OpenAsync();
            await using var cmd = new SqliteCommand(
                "SELECT Comment FROM Comments WHERE UserId = $userId",
                dbConnection);
            cmd.Parameters.AddWithValue("$userId", user.Id);
            await using var rd = await cmd.ExecuteReaderAsync();

            while (rd.Read())
            {
                comments.Add(rd.GetString(0));
            }

            return this.View(comments);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Comments(string comment)
        {
            var user = await this._userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new InvalidOperationException("Vous devez vous connecter");
            }

            await using var dbConnection = new SqliteConnection(this._connectionString);
            await dbConnection.OpenAsync();
            await using var cmd = new SqliteCommand(
                "INSERT INTO Comments (UserId, CommentId, Comment) VALUES ($userId, $commentId, $comment)",
                dbConnection);
            cmd.Parameters.AddWithValue("$userId", user.Id);
            cmd.Parameters.AddWithValue("$commentId", Guid.NewGuid().ToString());
            cmd.Parameters.AddWithValue("$comment", comment ?? string.Empty);
            await cmd.ExecuteNonQueryAsync();

            return this.Ok("Commentaire ajouté");
        }

        [Authorize]
        public async Task<IActionResult> Search(string searchData)
        {
            var searchResults = new List<string>();

            var user = await this._userManager.GetUserAsync(this.User);
            if (user == null || string.IsNullOrEmpty(searchData))
            {
                return this.View(searchResults);
            }

            await using var dbConnection = new SqliteConnection(this._connectionString);
            await dbConnection.OpenAsync();
            await using var cmd = new SqliteCommand(
                "SELECT Comment FROM Comments WHERE UserId = $userId AND Comment LIKE $search",
                dbConnection);
            cmd.Parameters.AddWithValue("$userId", user.Id);
            cmd.Parameters.AddWithValue("$search", $"%{searchData}%");
            await using var rd = await cmd.ExecuteReaderAsync();
            while (rd.Read())
            {
                searchResults.Add(rd.GetString(0));
            }

            return this.View(searchResults);
        }

        public IActionResult About()
        {
            return this.View();
        }

        public IActionResult Privacy()
        {
            return this.View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return this.View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? this.HttpContext.TraceIdentifier });
        }

        [HttpGet]
        [Authorize(Roles = "admin")]
        public IActionResult Emails()
        {
            return this.View();
        }

        [HttpPost]
        [Authorize(Roles = "admin")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Emails(object form)
        {
            var searchResults = new List<string>();

            await using var dbConnection = new SqliteConnection(this._connectionString);
            await dbConnection.OpenAsync();
            await using var cmd = new SqliteCommand("SELECT Email FROM AspNetUsers", dbConnection);
            await using var rd = await cmd.ExecuteReaderAsync();
            while (rd.Read())
            {
                searchResults.Add(rd.GetString(0));
            }

            return this.Json(searchResults);
        }
    }
}