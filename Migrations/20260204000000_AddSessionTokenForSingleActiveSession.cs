using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureWebApp.Migrations
{
    /// <inheritdoc />
    public class AddSessionTokenForSingleActiveSession : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CurrentSessionToken",
                table: "AspNetUsers",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "SessionIssuedAtUtc",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CurrentSessionToken",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "SessionIssuedAtUtc",
                table: "AspNetUsers");
        }
    }
}
