"""
AdminUtilities cog for NEBot.
Contains all administrative utility commands.
"""

import discord
from discord.ext import commands
import asyncio
import aiohttp
import contextlib
import io
import json
from typing import Union
from datetime import datetime, timedelta, timezone
from dotenv import dotenv_values

class CriticalsChecks(commands.Cog):
    """Critical security checks for Discord guild vulnerabilities."""

    def __init__(self, bot):
        self.bot = bot
        self._role_cache = {}
     
    async def get_roles_with_perms(self, guild, permissions):
        """Cache et optimise les requêtes de rôles"""
        cache_key = f"{guild.id}_{hash(tuple(permissions))}"
        if cache_key not in self._role_cache:
            roles = [role for role in guild.roles 
                    if any(getattr(role.permissions, perm) for perm in permissions)]
            self._role_cache[cache_key] = roles
        return self._role_cache[cache_key]   
        
    @commands.hybrid_command(
        name="role_hierarchy_check",
        brief="Vérifie la hiérarchie des rôles pour détecter les problèmes critiques",
        description="Détecte si des rôles décoratifs sont placés au-dessus de rôles avec des permissions importantes"
    )
    @commands.has_permissions(administrator=True)
    async def role_hierarchy_check(self, ctx):
        """Vérifie la hiérarchie des rôles pour détecter les problèmes de sécurité."""
        guild = ctx.guild
        issues = []
        
        # Get roles with dangerous permissions
        dangerous_perms = [
            'administrator', 'ban_members', 'kick_members', 'manage_guild', 
            'manage_roles', 'manage_channels', 'manage_webhooks'
        ]
        
        roles_with_perms = []
        for role in guild.roles:
            if role.name == "@everyone":
                continue
            role_perms = [perm for perm, value in role.permissions if value and perm in dangerous_perms]
            if role_perms:
                roles_with_perms.append((role, role_perms))
        
        # Check for decorative roles above permission roles
        for role, perms in roles_with_perms:
            higher_roles = [r for r in guild.roles if r.position > role.position and not any(getattr(r.permissions, perm) for perm in dangerous_perms)]
            if higher_roles:
                for higher_role in higher_roles:
                    issues.append(f"⚠️ Rôle décoratif `{higher_role.name}` (pos: {higher_role.position}) au-dessus du rôle avec permissions `{role.name}` (pos: {role.position}, perms: {', '.join(perms)})")
        
        embed = discord.Embed(
            title="🔍 Vérification de la hiérarchie des rôles",
            color=discord.Color.red() if issues else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if issues:
            embed.description = f"**{len(issues)} problème(s) détecté(s) :**\n" + "\n".join(issues[:10])
            if len(issues) > 10:
                embed.add_field(name="Note", value=f"... et {len(issues) - 10} autres problèmes", inline=False)
        else:
            embed.description = "✅ Aucun problème de hiérarchie détecté"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="admin_leak_check",
        brief="Détecte les fuites de permissions administrateur",
        description="Vérifie si des rôles ont la permission Administrator sans surveillance appropriée"
    )
    @commands.has_permissions(administrator=True)
    async def admin_leak_check(self, ctx):
        """Détecte les rôles avec permissions administrateur potentiellement dangereuses."""
        guild = ctx.guild
        admin_roles = []
        
        for role in guild.roles:
            if role.permissions.administrator and role.name != "@everyone":
                # Check if it's a decorative role (no other meaningful permissions)
                other_perms = [perm for perm, value in role.permissions if value and perm != 'administrator']
                admin_roles.append({
                    'role': role,
                    'members': len(role.members),
                    'other_perms': len(other_perms),
                    'position': role.position
                })
        
        embed = discord.Embed(
            title="🛡️ Vérification des permissions Administrator",
            color=discord.Color.red() if admin_roles else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if admin_roles:
            description = f"**{len(admin_roles)} rôle(s) avec Administrator détecté(s) :**\n"
            for role_info in admin_roles:
                role = role_info['role']
                risk_level = "🔴" if role_info['members'] > 5 else "🟡"
                description += f"{risk_level} `{role.name}` - {role_info['members']} membre(s), position {role_info['position']}\n"
            embed.description = description
            
            # Add warning for high-risk roles
            high_risk = [r for r in admin_roles if r['members'] > 5]
            if high_risk:
                embed.add_field(
                    name="⚠️ Rôles à risque élevé", 
                    value=f"{len(high_risk)} rôle(s) avec beaucoup de membres.",
                    inline=False
                )
        else:
            embed.description = "✅ Aucun rôle avec permission Administrator détecté"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="dangerous_perm_check",
        brief="Liste tous les rôles avec des permissions dangereuses",
        description="Scanne tous les rôles pour détecter les permissions critiques"
    )
    @commands.has_permissions(administrator=True)
    async def dangerous_perm_check(self, ctx):
        """Analyse tous les rôles pour détecter les permissions dangereuses."""
        guild = ctx.guild
        dangerous_perms = {
            'administrator': '👑 Administrator',
            'manage_guild': '⚙️ Manage Guild',
            'manage_roles': '🎭 Manage Roles',
            'manage_channels': '📁 Manage Channels',
            'manage_webhooks': '🔗 Manage Webhooks',
            'ban_members': '🔨 Ban Members',
            'kick_members': '👢 Kick Members',
            'manage_messages': '📝 Manage Messages'
        }
        
        dangerous_roles = []
        for role in guild.roles:
            if role.name == "@everyone":
                continue
            
            role_dangerous_perms = []
            for perm, display_name in dangerous_perms.items():
                if getattr(role.permissions, perm):
                    role_dangerous_perms.append(display_name)
            
            if role_dangerous_perms:
                dangerous_roles.append({
                    'role': role,
                    'perms': role_dangerous_perms,
                    'members': len(role.members)
                })
        
        embed = discord.Embed(
            title="⚠️ Rôles avec permissions dangereuses",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if dangerous_roles:
            # Sort by number of dangerous permissions
            dangerous_roles.sort(key=lambda x: len(x['perms']), reverse=True)
            
            description = f"**{len(dangerous_roles)} rôle(s) avec permissions critiques :**\n\n"
            for role_info in dangerous_roles[:15]:  # Limit to 15 roles
                role = role_info['role']
                perms_list = ', '.join(role_info['perms'][:3])  # Show first 3 perms
                if len(role_info['perms']) > 3:
                    perms_list += f" (+{len(role_info['perms']) - 3} autres)"
                
                description += f"**{role.name}** ({role_info['members']} membres)\n{perms_list}\n\n"
            
            if len(dangerous_roles) > 15:
                description += f"... et {len(dangerous_roles) - 15} autres rôles"
                
            embed.description = description
        else:
            embed.description = "✅ Aucun rôle avec permissions dangereuses détecté"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="everyone_perm_check",
        brief="Vérifie les permissions du rôle @everyone",
        description="Analyse les permissions du rôle @everyone dans tous les salons"
    )
    @commands.has_permissions(administrator=True)
    async def everyone_perm_check(self, ctx):
        """Vérifie les permissions dangereuses du rôle @everyone."""
        guild = ctx.guild
        everyone_role = guild.default_role
        issues = []
        
        # Check guild-level permissions
        dangerous_guild_perms = [
            'administrator', 'ban_members', 'kick_members', 'manage_guild',
            'manage_roles', 'manage_channels', 'manage_webhooks'
        ]
        
        guild_issues = []
        for perm in dangerous_guild_perms:
            if getattr(everyone_role.permissions, perm):
                guild_issues.append(f"🔴 {perm}")
        
        if guild_issues:
            issues.append(f"**Permissions globales dangereuses :** {', '.join(guild_issues)}")
        
        # Check channel-level permissions
        problematic_channels = []
        for channel in guild.channels:
            if isinstance(channel, (discord.TextChannel, discord.VoiceChannel)):
                overwrites = channel.overwrites_for(everyone_role)
                channel_issues = []
                
                if isinstance(channel, discord.TextChannel):
                    if overwrites.send_messages and overwrites.mention_everyone:
                        channel_issues.append("mention_everyone + send_messages")
                    if overwrites.manage_messages:
                        channel_issues.append("manage_messages")
                    if overwrites.manage_webhooks:
                        channel_issues.append("manage_webhooks")
                
                if overwrites.manage_channels:
                    channel_issues.append("manage_channels")
                
                if channel_issues:
                    problematic_channels.append(f"#{channel.name}: {', '.join(channel_issues)}")
        
        embed = discord.Embed(
            title="👥 Vérification des permissions @everyone",
            color=discord.Color.red() if (guild_issues or problematic_channels) else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if issues or problematic_channels:
            description = ""
            if issues:
                description += "\n".join(issues) + "\n\n"
            
            if problematic_channels:
                description += f"**Salons avec permissions dangereuses ({len(problematic_channels)}) :**\n"
                description += "\n".join(problematic_channels[:10])
                if len(problematic_channels) > 10:
                    description += f"\n... et {len(problematic_channels) - 10} autres salons"
            
            embed.description = description
        else:
            embed.description = "✅ Aucune permission dangereuse détectée pour @everyone"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="unprotected_webhooks",
        brief="Vérifie les salons vulnérables aux abus de webhooks",
        description="Détecte les salons où les webhooks peuvent être abusés"
    )
    @commands.has_permissions(administrator=True)
    async def unprotected_webhooks(self, ctx):
        """Vérifie les vulnérabilités liées aux webhooks."""
        guild = ctx.guild
        vulnerable_channels = []
        
        for channel in guild.text_channels:
            # Check roles that can both manage webhooks and send messages
            vulnerable_roles = []
            
            for role in guild.roles:
                if role.name == "@everyone":
                    overwrites = channel.overwrites_for(role)
                    if (overwrites.manage_webhooks or role.permissions.manage_webhooks) and \
                       (overwrites.send_messages or role.permissions.send_messages):
                        vulnerable_roles.append(role.name)
                else:
                    # Check if role has both permissions
                    overwrites = channel.overwrites_for(role)
                    has_webhook_perm = overwrites.manage_webhooks or role.permissions.manage_webhooks
                    has_send_perm = overwrites.send_messages or role.permissions.send_messages
                    
                    if has_webhook_perm and has_send_perm and len(role.members) > 0:
                        vulnerable_roles.append(f"{role.name} ({len(role.members)} membres)")
            
            if vulnerable_roles:
                # Check existing webhooks
                try:
                    webhooks = await channel.webhooks()
                    webhook_count = len(webhooks)
                except:
                    webhook_count = "Erreur"
                
                vulnerable_channels.append({
                    'channel': channel,
                    'roles': vulnerable_roles,
                    'webhook_count': webhook_count
                })
        
        embed = discord.Embed(
            title="🔗 Vérification des vulnérabilités webhook",
            color=discord.Color.red() if vulnerable_channels else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if vulnerable_channels:
            description = f"**{len(vulnerable_channels)} salon(s) vulnérable(s) détecté(s) :**\n\n"
            
            for channel_info in vulnerable_channels[:10]:
                channel = channel_info['channel']
                roles = channel_info['roles']
                webhook_count = channel_info['webhook_count']
                
                risk_level = "🔴" if len(roles) > 3 or "@everyone" in str(roles) else "🟡"
                description += f"{risk_level} **#{channel.name}** ({webhook_count} webhooks)\n"
                description += f"Rôles à risque: {', '.join(roles[:3])}"
                if len(roles) > 3:
                    description += f" (+{len(roles) - 3} autres)"
                description += "\n\n"
            
            if len(vulnerable_channels) > 10:
                description += f"... et {len(vulnerable_channels) - 10} autres salons"
            
            embed.description = description
        else:
            embed.description = "✅ Aucune vulnérabilité webhook détectée"
        
        await ctx.send(embed=embed)
        
    async def execute_checks(self, ctx):
        """Execute all critical checks."""
        tasks = [
            self.role_hierarchy_check(ctx),
            self.admin_leak_check(ctx),
            self.dangerous_perm_check(ctx),
            self.everyone_perm_check(ctx),
            self.unprotected_webhooks(ctx)
        ]
        return asyncio.gather(*tasks)

async def setup(bot):
    """Setup function for the cog."""
    await bot.add_cog(CriticalsChecks(bot))