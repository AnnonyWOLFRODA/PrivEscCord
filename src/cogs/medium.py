"""
Medium-level security checks cog for PrivEscCord.
Contains commands for detecting moderate security vulnerabilities.
"""

import discord
import asyncio
from discord.ext import commands
from datetime import datetime, timezone

class MediumChecks(commands.Cog):
    """Medium-level security checks for Discord guild vulnerabilities."""

    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_command(
        name="spam_perm_check",
        brief="Vérifie les permissions de spam potentielles",
        description="Analyse les rôles pouvant spammer via diverses permissions"
    )
    @commands.has_permissions(administrator=True)
    async def spam_perm_check(self, ctx):
        """Vérifie les rôles avec des permissions de spam."""
        guild = ctx.guild
        spam_perms = {
            'mention_everyone': '📢 Mention Everyone',
            'send_messages': '💬 Send Messages',
            'add_reactions': '😄 Add Reactions',
            'external_emojis': '😎 External Emojis',
            'send_tts_messages': '🔊 Send TTS Messages'
        }
        
        risky_roles = []
        for role in guild.roles:
            if role.name == "@everyone":
                continue
            
            role_spam_perms = []
            for perm, display_name in spam_perms.items():
                if getattr(role.permissions, perm):
                    role_spam_perms.append(display_name)
            
            # Consider risky if has multiple spam permissions or mention_everyone
            if len(role_spam_perms) >= 3 or any('Mention Everyone' in perm for perm in role_spam_perms):
                risky_roles.append({
                    'role': role,
                    'perms': role_spam_perms,
                    'members': len(role.members)
                })
        
        embed = discord.Embed(
            title="📢 Vérification des permissions de spam",
            color=discord.Color.orange() if risky_roles else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if risky_roles:
            description = f"**{len(risky_roles)} rôle(s) à risque de spam détecté(s) :**\n\n"
            
            for role_info in risky_roles[:10]:
                role = role_info['role']
                perms = role_info['perms']
                members = role_info['members']
                
                risk_level = "🔴" if members > 10 or any('Mention Everyone' in perm for perm in perms) else "🟡"
                description += f"{risk_level} **{role.name}** ({members} membres)\n"
                description += f"Permissions: {', '.join(perms)}\n\n"
            
            if len(risky_roles) > 10:
                description += f"... et {len(risky_roles) - 10} autres rôles"
                
            embed.description = description
        else:
            embed.description = "✅ Aucun rôle à risque de spam détecté"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="mass_mention_check",
        brief="Vérifie les permissions de mention massive",
        description="Analyse les permissions de mention @everyone dans les salons"
    )
    @commands.has_permissions(administrator=True)
    async def mass_mention_check(self, ctx):
        """Vérifie les vulnérabilités de mention massive."""
        guild = ctx.guild
        vulnerable_channels = []
        
        for channel in guild.text_channels:
            # Check @everyone permissions in this channel
            everyone_overwrites = channel.overwrites_for(guild.default_role)
            
            channel_issues = []
            if everyone_overwrites.mention_everyone or guild.default_role.permissions.mention_everyone:
                channel_issues.append("@everyone peut mentionner massivement")
            
            # Check other roles with mention permissions
            risky_roles = []
            for role in guild.roles:
                if role.name == "@everyone":
                    continue
                
                overwrites = channel.overwrites_for(role)
                if (overwrites.mention_everyone or role.permissions.mention_everyone) and len(role.members) > 0:
                    risky_roles.append(f"{role.name} ({len(role.members)} membres)")
            
            if risky_roles:
                channel_issues.append(f"Rôles à risque: {', '.join(risky_roles[:3])}")
                if len(risky_roles) > 3:
                    channel_issues[-1] += f" (+{len(risky_roles) - 3} autres)"
            
            if channel_issues:
                vulnerable_channels.append({
                    'channel': channel,
                    'issues': channel_issues
                })
        
        embed = discord.Embed(
            title="📣 Vérification des mentions massives",
            color=discord.Color.orange() if vulnerable_channels else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if vulnerable_channels:
            description = f"**{len(vulnerable_channels)} salon(s) vulnérable(s) aux mentions massives :**\n\n"
            
            for channel_info in vulnerable_channels[:15]:
                channel = channel_info['channel']
                issues = channel_info['issues']
                
                description += f"**#{channel.name}**\n"
                description += "\n".join(f"• {issue}" for issue in issues)
                description += "\n\n"
            
            if len(vulnerable_channels) > 15:
                description += f"... et {len(vulnerable_channels) - 15} autres salons"
                
            embed.description = description
        else:
            embed.description = "✅ Aucune vulnérabilité de mention massive détectée"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="webhook_overflow_check",
        brief="Vérifie le nombre de webhooks par salon",
        description="Compte les webhooks actifs dans chaque salon (limite recommandée: 10)"
    )
    @commands.has_permissions(administrator=True)
    async def webhook_overflow_check(self, ctx):
        """Vérifie le nombre de webhooks dans chaque salon."""
        guild = ctx.guild
        webhook_data = []
        total_webhooks = 0
        
        for channel in guild.text_channels:
            try:
                webhooks = await channel.webhooks()
                webhook_count = len(webhooks)
                total_webhooks += webhook_count
                
                if webhook_count > 0:
                    webhook_data.append({
                        'channel': channel,
                        'count': webhook_count,
                        'webhooks': webhooks
                    })
            except discord.Forbidden:
                webhook_data.append({
                    'channel': channel,
                    'count': 'Accès refusé',
                    'webhooks': []
                })
        
        # Sort by webhook count
        webhook_data.sort(key=lambda x: x['count'] if isinstance(x['count'], int) else 0, reverse=True)
        
        embed = discord.Embed(
            title="🔗 Vérification des webhooks par salon",
            color=discord.Color.red() if any(isinstance(item['count'], int) and item['count'] > 10 for item in webhook_data) else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if webhook_data:
            description = f"**Total: {total_webhooks} webhooks dans {len([w for w in webhook_data if isinstance(w['count'], int) and w['count'] > 0])} salons**\n\n"
            
            # Show channels with webhooks
            for channel_info in webhook_data[:15]:
                channel = channel_info['channel']
                count = channel_info['count']
                
                if isinstance(count, int) and count > 0:
                    risk_indicator = "🔴" if count > 10 else "🟡" if count > 5 else "🟢"
                    description += f"{risk_indicator} **#{channel.name}**: {count} webhook(s)"
                    
                    if count > 10:
                        description += " ⚠️ LIMITE DÉPASSÉE"
                    
                    # Show webhook details for problematic channels
                    if count > 5 and len(channel_info['webhooks']) > 0:
                        webhook_names = [wh.name for wh in channel_info['webhooks'][:3]]
                        description += f"\n   Webhooks: {', '.join(webhook_names)}"
                        if len(channel_info['webhooks']) > 3:
                            description += f" (+{len(channel_info['webhooks']) - 3} autres)"
                    
                    description += "\n\n"
                elif count == 'Accès refusé':
                    description += f"🔒 **#{channel.name}**: Accès refusé\n\n"
            
            if len(webhook_data) > 15:
                remaining = len([w for w in webhook_data[15:] if isinstance(w['count'], int) and w['count'] > 0])
                if remaining > 0:
                    description += f"... et {remaining} autres salons avec webhooks"
                    
            embed.description = description
        else:
            embed.description = "✅ Aucun webhook détecté dans le serveur"
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="voice_damage_check",
        brief="Vérifie les permissions vocales dangereuses",
        description="Analyse les rôles pouvant causer des dommages dans les salons vocaux"
    )
    @commands.has_permissions(administrator=True)
    async def voice_damage_check(self, ctx):
        """Vérifie les permissions vocales potentiellement dangereuses."""
        guild = ctx.guild
        voice_perms = {
            'mute_members': '🔇 Mute Members',
            'deafen_members': '🔈 Deafen Members',
            'move_members': '↔️ Move Members',
            'manage_channels': '⚙️ Manage Voice Channels',
            'priority_speaker': '📢 Priority Speaker'
        }
        
        risky_roles = []
        for role in guild.roles:
            if role.name == "@everyone":
                continue
            
            role_voice_perms = []
            for perm, display_name in voice_perms.items():
                if getattr(role.permissions, perm):
                    role_voice_perms.append(display_name)
            
            # Consider risky if has multiple voice permissions or manage_channels
            if len(role_voice_perms) >= 2 or any('Manage' in perm for perm in role_voice_perms):
                risky_roles.append({
                    'role': role,
                    'perms': role_voice_perms,
                    'members': len(role.members)
                })
        
        # Also check voice channels for specific overwrites
        problematic_channels = []
        for channel in guild.voice_channels:
            channel_issues = []
            
            # Check @everyone overwrites
            everyone_overwrites = channel.overwrites_for(guild.default_role)
            if everyone_overwrites.mute_members or everyone_overwrites.move_members:
                channel_issues.append("@everyone a des permissions vocales")
            
            # Count roles with voice permissions in this channel
            roles_with_voice_perms = 0
            for role in guild.roles:
                if role.name == "@everyone":
                    continue
                overwrites = channel.overwrites_for(role)
                if any(getattr(overwrites, perm) for perm in voice_perms.keys()) and len(role.members) > 0:
                    roles_with_voice_perms += 1
            
            if roles_with_voice_perms > 3:
                channel_issues.append(f"{roles_with_voice_perms} rôles avec permissions vocales")
            
            if channel_issues:
                problematic_channels.append({
                    'channel': channel,
                    'issues': channel_issues
                })
        
        embed = discord.Embed(
            title="🎤 Vérification des permissions vocales",
            color=discord.Color.orange() if (risky_roles or problematic_channels) else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        description = ""
        
        if risky_roles:
            description += f"**Rôles avec permissions vocales dangereuses ({len(risky_roles)}) :**\n"
            for role_info in risky_roles[:8]:
                role = role_info['role']
                perms = role_info['perms']
                members = role_info['members']
                
                risk_level = "🔴" if members > 15 else "🟡"
                description += f"{risk_level} **{role.name}** ({members} membres)\n"
                description += f"   {', '.join(perms)}\n"
            
            if len(risky_roles) > 8:
                description += f"   ... et {len(risky_roles) - 8} autres rôles\n"
            description += "\n"
        
        if problematic_channels:
            description += f"**Salons vocaux problématiques ({len(problematic_channels)}) :**\n"
            for channel_info in problematic_channels[:5]:
                channel = channel_info['channel']
                issues = channel_info['issues']
                description += f"🔊 **{channel.name}**: {', '.join(issues)}\n"
            
            if len(problematic_channels) > 5:
                description += f"   ... et {len(problematic_channels) - 5} autres salons\n"
        
        if not risky_roles and not problematic_channels:
            description = "✅ Aucune permission vocale dangereuse détectée"
        
        embed.description = description
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="channel_deletion_check",
        brief="Vérifie les risques de suppression de salons",
        description="Analyse les rôles pouvant supprimer/modifier des salons"
    )
    @commands.has_permissions(administrator=True)
    async def channel_deletion_check(self, ctx):
        """Vérifie les rôles avec permissions de gestion de salons."""
        guild = ctx.guild
        dangerous_roles = []
        
        for role in guild.roles:
            if role.name == "@everyone":
                continue
            
            if role.permissions.manage_channels:
                # Calculate risk based on position and member count
                risk_factors = []
                
                if len(role.members) > 10:
                    risk_factors.append(f"{len(role.members)} membres")
                
                if role.position > len(guild.roles) * 0.7:  # High in hierarchy
                    risk_factors.append("position élevée")
                
                # Check if role has other dangerous permissions
                other_dangerous = []
                if role.permissions.administrator:
                    other_dangerous.append("Administrator")
                if role.permissions.manage_guild:
                    other_dangerous.append("Manage Guild")
                if role.permissions.manage_roles:
                    other_dangerous.append("Manage Roles")
                
                dangerous_roles.append({
                    'role': role,
                    'members': len(role.members),
                    'position': role.position,
                    'risk_factors': risk_factors,
                    'other_perms': other_dangerous
                })
        
        # Sort by risk (position + member count)
        dangerous_roles.sort(key=lambda x: (x['position'], x['members']), reverse=True)
        
        embed = discord.Embed(
            title="📁 Vérification des permissions de gestion de salons",
            color=discord.Color.red() if len(dangerous_roles) > 5 else discord.Color.orange() if dangerous_roles else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if dangerous_roles:
            description = f"**{len(dangerous_roles)} rôle(s) avec Manage Channels :**\n\n"
            
            for role_info in dangerous_roles[:12]:
                role = role_info['role']
                members = role_info['members']
                position = role_info['position']
                risk_factors = role_info['risk_factors']
                other_perms = role_info['other_perms']
                
                # Determine risk level
                if len(risk_factors) >= 2 or members > 20:
                    risk_level = "🔴"
                elif len(risk_factors) >= 1 or members > 5:
                    risk_level = "🟡"
                else:
                    risk_level = "🟢"
                
                description += f"{risk_level} **{role.name}**\n"
                description += f"   👥 {members} membres • Pos. {position}"
                
                if risk_factors:
                    description += f" • ⚠️ {', '.join(risk_factors)}"
                
                if other_perms:
                    description += f"\n   🔒 Autres permissions: {', '.join(other_perms)}"
                
                description += "\n\n"
            
            if len(dangerous_roles) > 12:
                description += f"... et {len(dangerous_roles) - 12} autres rôles"
            
            # Add summary
            high_risk = len([r for r in dangerous_roles if len(r['risk_factors']) >= 2 or r['members'] > 20])
            if high_risk > 0:
                description += f"\n⚠️ **{high_risk} rôle(s) à risque élevé détecté(s)**"
                
            embed.description = description
        else:
            embed.description = "✅ Aucun rôle avec permission Manage Channels détecté"
        
        await ctx.send(embed=embed)
    
    async def execute_checks(self, ctx: commands.Context):
        """Execute all medium-level checks."""
        tasks = [
            self.spam_perm_check(ctx),
            self.mass_mention_check(ctx),
            self.webhook_overflow_check(ctx),
            self.voice_damage_check(ctx),
            self.channel_deletion_check(ctx)
        ]
        return await asyncio.gather(*tasks)

async def setup(bot):
    """Setup function for the cog."""
    await bot.add_cog(MediumChecks(bot))