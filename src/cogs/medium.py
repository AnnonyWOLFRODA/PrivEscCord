"""
Medium-level security checks cog for PrivEscCord.
Contains commands for detecting moderate security vulnerabilities.
"""

import discord
import asyncio
from discord.ext import commands
from datetime import datetime, timezone
from language_handler import language_handler

class MediumChecks(commands.Cog):
    """Medium-level security checks for Discord guild vulnerabilities."""

    def __init__(self, bot):
        self.bot = bot
        self._role_cache = {}
    
    async def get_roles_with_perms(self, guild, permissions):
        """Cache and optimize role queries"""
        cache_key = f"{guild.id}_{hash(tuple(permissions))}"
        if cache_key not in self._role_cache:
            roles = [role for role in guild.roles 
                    if any(getattr(role.permissions, perm) for perm in permissions)]
            self._role_cache[cache_key] = roles
        return self._role_cache[cache_key]
    
    def clear_cache(self, guild_id=None):
        """Clear role cache for a specific guild or all guilds"""
        if guild_id:
            keys_to_remove = [key for key in self._role_cache.keys() if key.startswith(f"{guild_id}_")]
            for key in keys_to_remove:
                del self._role_cache[key]
        else:
            self._role_cache.clear()

    @commands.hybrid_command(
        name="spam_perm_check",
        brief="Check potential spam permissions",
        description="Analyze roles that can spam via various permissions"
    )
    @commands.has_permissions(administrator=True)
    async def spam_perm_check(self, ctx):
        """Check roles with spam permissions."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        spam_perms = {
            'mention_everyone': '📢 Mention Everyone',
            'send_messages': '💬 Send Messages',
            'add_reactions': '😄 Add Reactions',
            'external_emojis': '😎 External Emojis',
            'send_tts_messages': '🔊 Send TTS Messages'
        }
        
        risky_roles = []
        
        # Use cached method to get roles with spam-related permissions
        spam_permission_roles = await self.get_roles_with_perms(guild, list(spam_perms.keys()))
        
        for role in spam_permission_roles:
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
            title=language_handler.get_text(ctx.guild.id, "spam_perm_title"),
            color=discord.Color.orange() if risky_roles else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if risky_roles:
            description = language_handler.get_text(ctx.guild.id, "spam_perm_found").format(count=len(risky_roles)) + "\n\n"
            
            for role_info in risky_roles[:10]:
                role = role_info['role']
                perms = role_info['perms']
                members = role_info['members']
                
                risk_level = "🔴" if members > 10 or any('Mention Everyone' in perm for perm in perms) else "🟡"
                description += f"{risk_level} **{role.name}** ({members} {language_handler.get_text(ctx.guild.id, 'members')})\n"
                description += f"{language_handler.get_text(ctx.guild.id, 'permissions_label')}: {', '.join(perms)}\n\n"
            
            if len(risky_roles) > 10:
                description += language_handler.get_text(ctx.guild.id, "spam_perm_more").format(count=len(risky_roles) - 10)
                
            embed.description = description
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "spam_perm_safe")
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="mass_mention_check",
        brief="Check mass mention permissions",
        description="Analyze @everyone mention permissions in channels"
    )
    @commands.has_permissions(administrator=True)
    async def mass_mention_check(self, ctx):
        """Check mass mention vulnerabilities."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        vulnerable_channels = []
        
        # Get roles that can mention everyone using cache
        mention_everyone_roles = await self.get_roles_with_perms(guild, ['mention_everyone'])
        
        for channel in guild.text_channels:
            # Check @everyone permissions in this channel
            everyone_overwrites = channel.overwrites_for(guild.default_role)
            
            channel_issues = []
            if everyone_overwrites.mention_everyone or guild.default_role.permissions.mention_everyone:
                channel_issues.append(language_handler.get_text(ctx.guild.id, "mass_mention_everyone_can"))
            
            # Check other roles with mention permissions
            risky_roles = []
            for role in mention_everyone_roles:
                if role.name == "@everyone":
                    continue
                
                overwrites = channel.overwrites_for(role)
                if (overwrites.mention_everyone or role.permissions.mention_everyone) and len(role.members) > 0:
                    risky_roles.append(f"{role.name} ({len(role.members)} {language_handler.get_text(ctx.guild.id, 'members')})")
            
            if risky_roles:
                channel_issues.append(f"{language_handler.get_text(ctx.guild.id, 'mass_mention_risky_roles')}: {', '.join(risky_roles[:3])}")
                if len(risky_roles) > 3:
                    channel_issues[-1] += f" (+{len(risky_roles) - 3} {language_handler.get_text(ctx.guild.id, 'others')})"
            
            if channel_issues:
                vulnerable_channels.append({
                    'channel': channel,
                    'issues': channel_issues
                })
        
        embed = discord.Embed(
            title=language_handler.get_text(ctx.guild.id, "mass_mention_title"),
            color=discord.Color.orange() if vulnerable_channels else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if vulnerable_channels:
            description = language_handler.get_text(ctx.guild.id, "mass_mention_found").format(count=len(vulnerable_channels)) + "\n\n"
            
            for channel_info in vulnerable_channels[:15]:
                channel = channel_info['channel']
                issues = channel_info['issues']
                
                description += f"**#{channel.name}**\n"
                description += "\n".join(f"• {issue}" for issue in issues)
                description += "\n\n"
            
            if len(vulnerable_channels) > 15:
                description += language_handler.get_text(ctx.guild.id, "mass_mention_more").format(count=len(vulnerable_channels) - 15)
                
            embed.description = description
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "mass_mention_safe")
        
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
        brief="Check dangerous voice permissions",
        description="Analyze roles that can cause damage in voice channels"
    )
    @commands.has_permissions(administrator=True)
    async def voice_damage_check(self, ctx):
        """Check potentially dangerous voice permissions."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        voice_perms = {
            'mute_members': '🔇 Mute Members',
            'deafen_members': '🔈 Deafen Members',
            'move_members': '↔️ Move Members',
            'manage_channels': '⚙️ Manage Voice Channels',
            'priority_speaker': '📢 Priority Speaker'
        }
        
        risky_roles = []
        
        # Use cached method to get roles with voice permissions
        voice_permission_roles = await self.get_roles_with_perms(guild, list(voice_perms.keys()))
        
        for role in voice_permission_roles:
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
                channel_issues.append(language_handler.get_text(ctx.guild.id, "voice_damage_everyone_perms"))
            
            # Count roles with voice permissions in this channel
            roles_with_voice_perms = 0
            for role in voice_permission_roles:
                if role.name == "@everyone":
                    continue
                overwrites = channel.overwrites_for(role)
                if any(getattr(overwrites, perm) for perm in voice_perms.keys()) and len(role.members) > 0:
                    roles_with_voice_perms += 1
            
            if roles_with_voice_perms > 3:
                channel_issues.append(language_handler.get_text(ctx.guild.id, "voice_damage_roles_count").format(count=roles_with_voice_perms))
            
            if channel_issues:
                problematic_channels.append({
                    'channel': channel,
                    'issues': channel_issues
                })
        
        embed = discord.Embed(
            title=language_handler.get_text(ctx.guild.id, "voice_damage_title"),
            color=discord.Color.orange() if (risky_roles or problematic_channels) else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        description = ""
        
        if risky_roles:
            description += language_handler.get_text(ctx.guild.id, "voice_damage_risky_roles").format(count=len(risky_roles)) + "\n"
            for role_info in risky_roles[:8]:
                role = role_info['role']
                perms = role_info['perms']
                members = role_info['members']
                
                risk_level = "🔴" if members > 15 else "🟡"
                description += f"{risk_level} **{role.name}** ({members} {language_handler.get_text(ctx.guild.id, 'members')})\n"
                description += f"   {', '.join(perms)}\n"
            
            if len(risky_roles) > 8:
                description += language_handler.get_text(ctx.guild.id, "voice_damage_more_roles").format(count=len(risky_roles) - 8) + "\n"
            description += "\n"
        
        if problematic_channels:
            description += language_handler.get_text(ctx.guild.id, "voice_damage_problematic_channels").format(count=len(problematic_channels)) + "\n"
            for channel_info in problematic_channels[:5]:
                channel = channel_info['channel']
                issues = channel_info['issues']
                description += f"🔊 **{channel.name}**: {', '.join(issues)}\n"
            
            if len(problematic_channels) > 5:
                description += language_handler.get_text(ctx.guild.id, "voice_damage_more_channels").format(count=len(problematic_channels) - 5) + "\n"
        
        if not risky_roles and not problematic_channels:
            description = language_handler.get_text(ctx.guild.id, "voice_damage_safe")
        
        embed.description = description
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="channel_deletion_check",
        brief="Check channel deletion risks",
        description="Analyze roles that can delete/modify channels"
    )
    @commands.has_permissions(administrator=True)
    async def channel_deletion_check(self, ctx):
        """Check potentially dangerous channel management permissions."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        dangerous_roles = []
        
        # Use cached method to get roles with manage_channels permission
        manage_channel_roles = await self.get_roles_with_perms(guild, ['manage_channels'])
        
        for role in manage_channel_roles:
            if role.name == "@everyone":
                continue
            
            # Calculate risk based on position and member count
            risk_factors = []
            
            if len(role.members) > 10:
                risk_factors.append(f"{len(role.members)} {language_handler.get_text(ctx.guild.id, 'members')}")
            
            if role.position > len(guild.roles) * 0.7:  # High in hierarchy
                risk_factors.append(language_handler.get_text(ctx.guild.id, "channel_deletion_high_position"))
            
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
            title=language_handler.get_text(ctx.guild.id, "channel_deletion_title"),
            color=discord.Color.red() if len(dangerous_roles) > 5 else discord.Color.orange() if dangerous_roles else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if dangerous_roles:
            description = language_handler.get_text(ctx.guild.id, "channel_deletion_found").format(count=len(dangerous_roles)) + "\n\n"
            
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
                description += f"   👥 {members} {language_handler.get_text(ctx.guild.id, 'members')} • {language_handler.get_text(ctx.guild.id, 'position')} {position}"
                
                if risk_factors:
                    description += f" • ⚠️ {', '.join(risk_factors)}"
                
                if other_perms:
                    description += f"\n   🔒 {language_handler.get_text(ctx.guild.id, 'channel_deletion_other_perms')}: {', '.join(other_perms)}"
                
                description += "\n\n"
            
            if len(dangerous_roles) > 12:
                description += language_handler.get_text(ctx.guild.id, "channel_deletion_more").format(count=len(dangerous_roles) - 12)
            
            # Add summary
            high_risk = len([r for r in dangerous_roles if len(r['risk_factors']) >= 2 or r['members'] > 20])
            if high_risk > 0:
                description += f"\n{language_handler.get_text(ctx.guild.id, 'channel_deletion_high_risk_summary').format(count=high_risk)}"
                
            embed.description = description
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "channel_deletion_safe")
        
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