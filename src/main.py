import discord
import time
from pyutil import filereplace
from datetime import datetime, timedelta, timezone
import asyncio
import discord.utils
import json
from discord.ext import commands
from discord.ext.commands import has_role, Context, Converter, BadArgument
from discord.ext import tasks
import urllib.request
import random
import aiohttp
import os
import re
import shutil
import events
from typing import Union
import interactions
from PIL import Image
import pytz
import io
import string
import locale
import traceback
import requests
from dotenv import dotenv_values
import contextlib
from discord.ui import Button, View, Modal, TextInput
from discord import message, emoji, Webhook, SyncWebhook, app_commands

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
    hidden=False,
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

@bot.event
async def on_ready():
    """Event triggered when the bot is ready."""
    print(f"✅ Bot is ready! Logged in as {bot.user}")
    print("🔧 Utilities already initialized")

    await load_cogs()
    await bot.tree.sync()

bot.run(token)
