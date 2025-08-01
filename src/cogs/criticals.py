"""
Critical security checks cog for PrivEscCord.
Contains commands for detecting severe security vulnerabilities.
"""

import discord
import asyncio
from discord.ext import commands
from datetime import datetime, timezone

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

    @commands.hybrid_command(
        name="server_settings_check",
        brief="Vérifie les paramètres de sécurité du serveur",
        description="Analyse les paramètres de sécurité globaux du serveur (2FA, niveau de vérification, etc.)"
    )
    @commands.has_permissions(administrator=True)
    async def server_settings_check(self, ctx):
        """Vérifie les paramètres de sécurité critiques du serveur."""
        guild = ctx.guild
        security_issues = []
        security_good = []
        
        # Check MFA requirement for moderation actions
        if guild.mfa_level == discord.MFALevel.disabled:
            security_issues.append("🔴 **2FA désactivé** - Les modérateurs n'ont pas besoin de 2FA")
        else:
            security_good.append("✅ **2FA activé** - 2FA requis pour les actions de modération")
        
        # Check verification level
        verification_levels = {
            discord.VerificationLevel.none: ("🔴 **Aucune vérification**", "Aucune restriction sur les nouveaux membres"),
            discord.VerificationLevel.low: ("🟡 **Vérification faible**", "Email vérifié requis"),
            discord.VerificationLevel.medium: ("🟡 **Vérification moyenne**", "Inscription Discord > 5 minutes"),
            discord.VerificationLevel.high: ("🟢 **Vérification élevée**", "Membre du serveur > 10 minutes"),
            discord.VerificationLevel.highest: ("🟢 **Vérification maximale**", "Numéro de téléphone vérifié requis")
        }
        
        level_info = verification_levels.get(guild.verification_level)
        if level_info:
            if guild.verification_level in [discord.VerificationLevel.none, discord.VerificationLevel.low]:
                security_issues.append(f"{level_info[0]} - {level_info[1]}")
            else:
                security_good.append(f"{level_info[0]} - {level_info[1]}")
        
        # Check explicit content filter
        content_filter_levels = {
            discord.ContentFilter.disabled: ("🔴 **Filtre de contenu désactivé**", "Aucun scan des images/vidéos"),
            discord.ContentFilter.no_role: ("🟡 **Filtre partiel**", "Scan seulement pour les membres sans rôle"),
            discord.ContentFilter.all_members: ("🟢 **Filtre complet**", "Scan pour tous les membres")
        }
        
        filter_info = content_filter_levels.get(guild.explicit_content_filter)
        if filter_info:
            if guild.explicit_content_filter == discord.ContentFilter.disabled:
                security_issues.append(f"{filter_info[0]} - {filter_info[1]}")
            elif guild.explicit_content_filter == discord.ContentFilter.no_role:
                security_issues.append(f"{filter_info[0]} - {filter_info[1]}")
            else:
                security_good.append(f"{filter_info[0]} - {filter_info[1]}")
        
        # Check default notifications
        if guild.default_notifications == discord.NotificationLevel.all_messages:
            security_issues.append("🟡 **Notifications par défaut** - Tous les messages (peut être spam)")
        else:
            security_good.append("✅ **Notifications** - Seulement mentions (recommandé)")
        
        # Check NSFW level (if available)
        if hasattr(guild, 'nsfw_level'):
            if guild.nsfw_level == discord.NSFWLevel.explicit:
                security_issues.append("🔴 **Serveur NSFW explicite** - Contenu pour adultes")
            elif guild.nsfw_level == discord.NSFWLevel.safe:
                security_good.append("✅ **Serveur sûr** - Pas de contenu NSFW")
        
        # Check if server has community features enabled
        if "COMMUNITY" in guild.features:
            security_good.append("✅ **Serveur communautaire** - Fonctionnalités de modération avancées")
            
            # Check if server has moderation features
            if "AUTO_MODERATION" in guild.features:
                security_good.append("✅ **AutoMod activé** - Modération automatique disponible")
        else:
            security_issues.append("🟡 **Pas de fonctionnalités communautaires** - Modération limitée")
        
        # Check server features for security-related ones
        security_features = []
        if "VERIFIED" in guild.features:
            security_features.append("✅ Serveur vérifié")
        if "PARTNERED" in guild.features:
            security_features.append("✅ Serveur partenaire")
        if "AUTO_MODERATION" in guild.features:
            security_features.append("✅ AutoModération")
        if "RAID_ALERTS_DISABLED" in guild.features:
            security_issues.append("🔴 **Alertes de raid désactivées**")
        
        # Check server size vs verification level (risk assessment)
        member_count = guild.member_count
        if member_count > 1000 and guild.verification_level in [discord.VerificationLevel.none, discord.VerificationLevel.low]:
            security_issues.append(f"🔴 **Serveur large ({member_count} membres) avec vérification faible** - Risque de raid élevé")
        elif member_count > 100 and guild.verification_level == discord.VerificationLevel.none:
            security_issues.append(f"🟡 **Serveur moyen ({member_count} membres) sans vérification** - Vulnérable aux raids")
        
        # Create embed
        embed = discord.Embed(
            title="🛡️ Vérification des paramètres de sécurité",
            color=discord.Color.red() if security_issues else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        # Add server info
        embed.add_field(
            name="📊 Informations du serveur",
            value=f"**Nom:** {guild.name}\n**Membres:** {member_count}\n**Créé:** <t:{int(guild.created_at.timestamp())}:R>",
            inline=False
        )
        
        # Add security issues
        if security_issues:
            issues_text = "\n".join(security_issues[:10])
            if len(security_issues) > 10:
                issues_text += f"\n... et {len(security_issues) - 10} autres problèmes"
            embed.add_field(
                name=f"⚠️ Problèmes de sécurité ({len(security_issues)})",
                value=issues_text,
                inline=False
            )
        
        # Add good security practices
        if security_good:
            good_text = "\n".join(security_good[:8])
            if len(security_good) > 8:
                good_text += f"\n... et {len(security_good) - 8} autres"
            embed.add_field(
                name=f"✅ Bonnes pratiques ({len(security_good)})",
                value=good_text,
                inline=False
            )
        
        # Add special features if any
        if security_features:
            embed.add_field(
                name="🌟 Fonctionnalités de sécurité",
                value="\n".join(security_features),
                inline=False
            )
        
        # Add risk assessment
        risk_score = len(security_issues)
        if risk_score == 0:
            risk_text = "🟢 **Faible** - Configuration sécurisée"
        elif risk_score <= 2:
            risk_text = "🟡 **Moyen** - Quelques améliorations recommandées"
        elif risk_score <= 4:
            risk_text = "🟠 **Élevé** - Plusieurs problèmes à corriger"
        else:
            risk_text = "🔴 **Critique** - Configuration dangereuse"
        
        embed.add_field(
            name="📈 Niveau de risque",
            value=risk_text,
            inline=False
        )
        
        await ctx.send(embed=embed)
        
    async def execute_checks(self, ctx):
        """Execute all critical checks."""
        tasks = [
            self.role_hierarchy_check(ctx),
            self.admin_leak_check(ctx),
            self.dangerous_perm_check(ctx),
            self.everyone_perm_check(ctx),
            self.unprotected_webhooks(ctx),
            self.server_settings_check(ctx)
        ]
        return asyncio.gather(*tasks)

async def setup(bot):
    """Setup function for the cog."""
    await bot.add_cog(CriticalsChecks(bot))