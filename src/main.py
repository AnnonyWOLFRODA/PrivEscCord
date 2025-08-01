import discord
import asyncio
import traceback
from discord import app_commands
from discord.ext import commands
from discord.ext.commands import Context
from dotenv import dotenv_values
from language_handler import language_handler

token = dotenv_values(".env")["TOKEN"]

_orig_print = print
def print(*args, **kwargs):
    _orig_print(*args, flush=True, **kwargs)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(
    intents=intents,
    activity=discord.Game(name="Testing Discord guild's security"),
    command_prefix=["$"],
)

@bot.event
async def on_command_error(ctx: Context, error: Exception):
    """Handle command errors."""
    print(f"❌ Error in command '{ctx.command}': {error}")
    if isinstance(error, commands.MissingPermissions):
        await ctx.send(language_handler.get_text(ctx.guild.id, "errors.missing_permissions"))
    elif isinstance(error, commands.CommandNotFound):
        await ctx.send(language_handler.get_text(ctx.guild.id, "errors.command_not_found"))
    else:
        await ctx.send(language_handler.get_text(ctx.guild.id, "errors.generic_error"))
        traceback.print_exception(type(error), error, error.__traceback__)

async def load_cogs():
    """Load all cogs for the bot."""
    try:
        print("🔄 Loading critical checks cog...")
        await bot.load_extension("cogs.criticals")
        print("✅ Critical checks cog loaded successfully")
        
        print("🔄 Loading medium checks cog...")
        await bot.load_extension("cogs.medium")
        print("✅ Medium checks cog loaded successfully")

        critical_commands = [cmd for cmd in bot.commands if cmd.cog_name == "CriticalsChecks"]
        medium_commands = [cmd for cmd in bot.commands if cmd.cog_name == "MediumChecks"]
        
        print(f"📋 Loaded critical commands: {[cmd.name for cmd in critical_commands]}")
        print(f"📋 Loaded medium commands: {[cmd.name for cmd in medium_commands]}")

    except Exception as e:
        print(f"❌ Failed to load cogs: {e}")
        traceback.print_exc()

@bot.hybrid_command(
    name="reload_cogs",
    brief="Recharge tous les cogs du bot.",
    usage="reload_cogs",
    description="Recharge ou charge tous les cogs principaux du bot (Criticals, Medium).",
    help="""Recharge tous les cogs du bot pour appliquer les modifications sans redémarrer le bot.

    FONCTIONNALITÉ :
    - Tente de recharger les cogs s'ils sont déjà chargés
    - Les charge s'ils ne sont pas encore chargés
    - Affiche un message de confirmation ou d'erreur

    RESTRICTIONS :
    - Réservé aux administrateurs uniquement

    EXEMPLE :
    - `reload_cogs` : Recharge tous les cogs principaux du bot
    """,
    hidden=True,
    enabled=True,
    case_insensitive=True,
)
@commands.has_permissions(administrator=True)
async def reload_cogs(ctx):
    """Reload all cogs (Admin only)."""
    try:
        # Try to reload, if not loaded then load it
        try:
            await bot.reload_extension("cogs.criticals")
            await bot.reload_extension("cogs.medium")
            await ctx.send(
                "✅ Criticals and Medium cogs reloaded successfully!"
            )
        except commands.ExtensionNotLoaded:
            await bot.load_extension("cogs.criticals")
            await bot.load_extension("cogs.medium")
            await ctx.send(
                "✅ Criticals and Medium cogs loaded successfully!"
            )
    except Exception as e:
        await ctx.send(f"❌ Failed to reload/load cogs: {e}")
        
@bot.hybrid_command(
    name="all_checks",
    brief="Exécute toutes les vérifications critiques et moyennes.",
    usage="all_checks",
    description="Exécute toutes les vérifications critiques et moyennes sur le serveur.",
    help="""Exécute toutes les vérifications critiques et moyennes sur le serveur.
    FONCTIONNALITÉ :
    - Exécute les vérifications critiques et moyennes
    - Affiche les résultats dans des embeds successivement envoyés
    RESTRICTIONS :
    - Réservé aux administrateurs uniquement
    EXEMPLE :
    - `all_checks` : Exécute toutes les vérifications critiques et moyennes sur le serveur
    """,
    hidden=False,
    enabled=True,
    case_insensitive=True,
)
@commands.has_permissions(administrator=True)
async def all_checks(ctx: Context):
    """Execute all critical and medium checks."""
    await ctx.defer()  # Defer the response to avoid timeout
    try:
        # Execute critical checks
        criticals_cog = bot.get_cog("CriticalsChecks")
        if criticals_cog:
            await criticals_cog.execute_checks(ctx)
        else:
            await ctx.send("❌ CriticalsChecks cog not found!")

        # Execute medium checks
        medium_cog = bot.get_cog("MediumChecks")
        if medium_cog:
            await medium_cog.execute_checks(ctx)
        else:
            await ctx.send("❌ MediumChecks cog not found!")

    except Exception as e:
        await ctx.send(f"❌ An error occurred while executing checks: {e}")

@bot.hybrid_command(
    name="set_language",
    brief="Sets the language for bot responses",
    usage="set_language <language_code>",
    description="Sets the language for bot responses in this server. Available: en, fr, es, de, it",
    help="""Sets the language for bot responses in this server.

    AVAILABLE LANGUAGES:
    - en (English)
    - fr (Français)
    - es (Español)
    - de (Deutsch)
    - it (Italiano)

    RESTRICTIONS:
    - Reserved for administrators only

    EXAMPLE:
    - `set_language fr` : Set language to French
    - `set_language en` : Set language to English
    """,
    hidden=False,
    enabled=True,
    case_insensitive=True,
)
@commands.has_permissions(administrator=True)
@commands.guild_only()
@app_commands.choices(
    language_code=[
        app_commands.Choice(name=language_handler.get_language_name(code), value=code)
        for code in language_handler.get_supported_languages()
    ]
)
async def set_language(ctx: Context, language_code: str = None):
    """Set server language (Admin only)."""
    guild_id = ctx.guild.id
    
    if language_code is None:
        # Show current language and available options
        current_lang = language_handler.get_server_language(guild_id)
        current_lang_name = language_handler.get_language_name(current_lang)
        supported_langs = language_handler.get_supported_languages()
        
        embed = discord.Embed(
            title=language_handler.get_text(guild_id, "set_language_title"),
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name=language_handler.get_text(guild_id, "set_language_current", language=current_lang_name),
            value="",
            inline=False
        )
        
        lang_list = "\n".join([f"• `{code}` - {language_handler.get_language_name(code)}" for code in supported_langs])
        embed.add_field(
            name="Available Languages",
            value=lang_list,
            inline=False
        )
        
        embed.add_field(
            name="Usage",
            value=f"Usage: `{ctx.prefix}set_language <language_code>`",
            inline=False
        )
        
        await ctx.send(embed=embed)
        return
    
    # Validate language code
    language_code = language_code.lower()
    if language_code not in language_handler.get_supported_languages():
        supported_langs = ", ".join(language_handler.get_supported_languages())
        message = language_handler.get_text(guild_id, "set_language_invalid", languages=supported_langs)
        await ctx.send(message)
        return
    
    # Set new language
    if language_handler.set_server_language(guild_id, language_code):
        lang_name = language_handler.get_language_name(language_code)
        message = language_handler.get_text(guild_id, "set_language_success", language=lang_name)
        await ctx.send(message)
    else:
        supported_langs = ", ".join(language_handler.get_supported_languages())
        message = language_handler.get_text(guild_id, "set_language_invalid", languages=supported_langs)
        await ctx.send(message)

@bot.event
async def on_ready():
    """Event triggered when the bot is ready."""
    print(f"✅ Bot is ready! Logged in as {bot.user}")
    print("🔧 Utilities already initialized")

    await load_cogs()
    await bot.tree.sync()

bot.run(token)
