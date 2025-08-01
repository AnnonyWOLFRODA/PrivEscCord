"""
Critical security checks cog for PrivEscCord.
Contains commands for detecting severe security vulnerabilities.
"""

import discord
import asyncio
import random
from discord.ext import commands
from datetime import datetime, timezone
from language_handler import language_handler

class CriticalsChecks(commands.Cog):
    """Critical security checks for Discord guild vulnerabilities."""

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
        name="role_hierarchy_check",
        brief="Check role hierarchy for critical issues",
        description="Detect if decorative roles are placed above roles with important permissions"
    )
    @commands.has_permissions(administrator=True)
    async def role_hierarchy_check(self, ctx):
        """Check role hierarchy for security issues."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        issues = []
        
        # Get roles with dangerous permissions
        dangerous_perms = [
            'administrator', 'ban_members', 'kick_members', 'manage_guild', 
            'manage_roles', 'manage_channels', 'manage_webhooks'
        ]
        
        roles_with_perms = []
        
        # Use cached method to get roles with dangerous permissions
        roles_with_dangerous_perms = await self.get_roles_with_perms(guild, dangerous_perms)
        
        for role in roles_with_dangerous_perms:
            if role.name == "@everyone":
                continue
            role_perms = [perm for perm in dangerous_perms if getattr(role.permissions, perm)]
            if role_perms:
                roles_with_perms.append((role, role_perms))
        
        # Check for decorative roles above permission roles
        for role, perms in roles_with_perms:
            higher_roles = [r for r in guild.roles if r.position > role.position and not any(getattr(r.permissions, perm) for perm in dangerous_perms)]
            if higher_roles:
                for higher_role in higher_roles:
                    issues.append(language_handler.get_text(ctx.guild.id, "role_hierarchy_decorative_above").format(
                        decorative=higher_role.name, 
                        decorative_pos=higher_role.position,
                        perm_role=role.name,
                        perm_pos=role.position,
                        perms=', '.join(perms)
                    ))
        
        embed = discord.Embed(
            title=language_handler.get_text(ctx.guild.id, "role_hierarchy_title"),
            color=discord.Color.red() if issues else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if issues:
            embed.description = language_handler.get_text(ctx.guild.id, "role_hierarchy_issues_found").format(count=len(issues)) + "\n" + "\n".join(issues[:10])
            if len(issues) > 10:
                embed.add_field(
                    name=language_handler.get_text(ctx.guild.id, "note"), 
                    value=language_handler.get_text(ctx.guild.id, "role_hierarchy_more_issues").format(count=len(issues) - 10), 
                    inline=False
                )
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "role_hierarchy_safe")
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="admin_leak_check",
        brief="Detect administrator permission leaks",
        description="Check for roles with Administrator permission without proper oversight"
    )
    @commands.has_permissions(administrator=True)
    async def admin_leak_check(self, ctx):
        """Detect roles with potentially dangerous administrator permissions."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        admin_roles = []
        
        # Use cached method to get roles with administrator permissions
        admin_permission_roles = await self.get_roles_with_perms(guild, ['administrator'])
        
        for role in admin_permission_roles:
            if role.name != "@everyone":
                # Check if it's a decorative role (no other meaningful permissions)
                other_perms = [perm for perm, value in role.permissions if value and perm != 'administrator']
                admin_roles.append({
                    'role': role,
                    'members': len(role.members),
                    'other_perms': len(other_perms),
                    'position': role.position
                })
        
        embed = discord.Embed(
            title=language_handler.get_text(ctx.guild.id, "admin_leak_title"),
            color=discord.Color.red() if admin_roles else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if admin_roles:
            description = language_handler.get_text(ctx.guild.id, "admin_leak_found").format(count=len(admin_roles)) + "\n"
            for role_info in admin_roles:
                role = role_info['role']
                risk_level = "🔴" if role_info['members'] > 5 else "🟡"
                description += f"{risk_level} `{role.name}` - {role_info['members']} {language_handler.get_text(ctx.guild.id, 'members')}, position {role_info['position']}\n"
            embed.description = description
            
            # Add warning for high-risk roles
            high_risk = [r for r in admin_roles if r['members'] > 5]
            if high_risk:
                embed.add_field(
                    name=language_handler.get_text(ctx.guild.id, "admin_leak_high_risk"), 
                    value=language_handler.get_text(ctx.guild.id, "admin_leak_high_risk_desc").format(count=len(high_risk)),
                    inline=False
                )
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "admin_leak_safe")
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="dangerous_perm_check",
        brief="List all roles with dangerous permissions",
        description="Scan all roles to detect critical permissions"
    )
    @commands.has_permissions(administrator=True)
    async def dangerous_perm_check(self, ctx):
        """Analyze all roles to detect dangerous permissions."""
        lang = language_handler.get_server_language(ctx.guild.id)
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
        
        # Use cached method to get roles with any dangerous permissions
        roles_with_dangerous_perms = await self.get_roles_with_perms(guild, list(dangerous_perms.keys()))
        
        for role in roles_with_dangerous_perms:
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
            title=language_handler.get_text(ctx.guild.id, "dangerous_perm_title"),
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if dangerous_roles:
            # Sort by number of dangerous permissions
            dangerous_roles.sort(key=lambda x: len(x['perms']), reverse=True)
            
            description = language_handler.get_text(ctx.guild.id, "dangerous_perm_found").format(count=len(dangerous_roles)) + "\n\n"
            for role_info in dangerous_roles[:15]:  # Limit to 15 roles
                role = role_info['role']
                perms_list = ', '.join(role_info['perms'][:3])  # Show first 3 perms
                if len(role_info['perms']) > 3:
                    perms_list += f" (+{len(role_info['perms']) - 3} {language_handler.get_text(ctx.guild.id, 'others')})"
                
                description += f"**{role.name}** ({role_info['members']} {language_handler.get_text(ctx.guild.id, 'members')})\n{perms_list}\n\n"
            
            if len(dangerous_roles) > 15:
                description += language_handler.get_text(ctx.guild.id, "dangerous_perm_more").format(count=len(dangerous_roles) - 15)
                
            embed.description = description
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "dangerous_perm_safe")
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="everyone_perm_check",
        brief="Check @everyone role permissions",
        description="Analyze @everyone role permissions in all channels"
    )
    @commands.has_permissions(administrator=True)
    async def everyone_perm_check(self, ctx):
        """Check dangerous permissions of the @everyone role."""
        lang = language_handler.get_server_language(ctx.guild.id)
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
            issues.append(f"**{language_handler.get_text(ctx.guild.id, 'everyone_perm_global_dangerous')}:** {', '.join(guild_issues)}")
        
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
            title=language_handler.get_text(ctx.guild.id, "everyone_perm_title"),
            color=discord.Color.red() if (guild_issues or problematic_channels) else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if issues or problematic_channels:
            description = ""
            if issues:
                description += "\n".join(issues) + "\n\n"
            
            if problematic_channels:
                description += f"**{language_handler.get_text(ctx.guild.id, 'everyone_perm_channels_dangerous').format(count=len(problematic_channels))}:**\n"
                description += "\n".join(problematic_channels[:10])
                if len(problematic_channels) > 10:
                    description += f"\n{language_handler.get_text(ctx.guild.id, 'everyone_perm_more_channels').format(count=len(problematic_channels) - 10)}"
            
            embed.description = description
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "everyone_perm_safe")
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="unprotected_webhooks",
        brief="Check channels vulnerable to webhook abuse",
        description="Detect channels where webhooks can be abused"
    )
    @commands.has_permissions(administrator=True)
    async def unprotected_webhooks(self, ctx):
        """Check webhook-related vulnerabilities."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        vulnerable_channels = []
        
        # Get roles that can manage webhooks using cache
        webhook_roles = await self.get_roles_with_perms(guild, ['manage_webhooks'])
        
        for channel in guild.text_channels:
            # Check roles that can both manage webhooks and send messages
            vulnerable_roles = []
            
            for role in webhook_roles:
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
                        vulnerable_roles.append(f"{role.name} ({len(role.members)} {language_handler.get_text(ctx.guild.id, 'members')})")
            
            if vulnerable_roles:
                # Check existing webhooks
                try:
                    webhooks = await channel.webhooks()
                    webhook_count = len(webhooks)
                except:
                    webhook_count = language_handler.get_text(ctx.guild.id, "error")
                
                vulnerable_channels.append({
                    'channel': channel,
                    'roles': vulnerable_roles,
                    'webhook_count': webhook_count
                })
        
        embed = discord.Embed(
            title=language_handler.get_text(ctx.guild.id, "webhook_vuln_title"),
            color=discord.Color.red() if vulnerable_channels else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if vulnerable_channels:
            description = language_handler.get_text(ctx.guild.id, "webhook_vuln_found").format(count=len(vulnerable_channels)) + "\n\n"
            
            for channel_info in vulnerable_channels[:10]:
                channel = channel_info['channel']
                roles = channel_info['roles']
                webhook_count = channel_info['webhook_count']
                
                risk_level = "🔴" if len(roles) > 3 or "@everyone" in str(roles) else "🟡"
                description += f"{risk_level} **#{channel.name}** ({webhook_count} webhooks)\n"
                description += f"{language_handler.get_text(ctx.guild.id, 'webhook_vuln_risky_roles')}: {', '.join(roles[:3])}"
                if len(roles) > 3:
                    description += f" (+{len(roles) - 3} {language_handler.get_text(ctx.guild.id, 'others')})"
                description += "\n\n"
            
            if len(vulnerable_channels) > 10:
                description += language_handler.get_text(ctx.guild.id, "webhook_vuln_more").format(count=len(vulnerable_channels) - 10)
            
            embed.description = description
        else:
            embed.description = language_handler.get_text(ctx.guild.id, "webhook_vuln_safe")
        
        await ctx.send(embed=embed)

    @commands.hybrid_command(
        name="server_settings_check",
        brief="Check server security settings",
        description="Analyze global server security settings (2FA, verification level, etc.)"
    )
    @commands.has_permissions(administrator=True)
    async def server_settings_check(self, ctx):
        """Check critical server security settings."""
        lang = language_handler.get_server_language(ctx.guild.id)
        guild = ctx.guild
        security_issues = []
        security_good = []
        
        # Check MFA requirement for moderation actions
        if guild.mfa_level == discord.MFALevel.disabled:
            security_issues.append(f"🔴 **{language_handler.get_text(ctx.guild.id, 'server_settings_2fa_disabled')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_2fa_disabled_desc')}")
        else:
            security_good.append(f"✅ **{language_handler.get_text(ctx.guild.id, 'server_settings_2fa_enabled')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_2fa_enabled_desc')}")
        
        # Check verification level
        verification_texts = {
            discord.VerificationLevel.none: ("server_settings_verif_none", "server_settings_verif_none_desc"),
            discord.VerificationLevel.low: ("server_settings_verif_low", "server_settings_verif_low_desc"),
            discord.VerificationLevel.medium: ("server_settings_verif_medium", "server_settings_verif_medium_desc"),
            discord.VerificationLevel.high: ("server_settings_verif_high", "server_settings_verif_high_desc"),
            discord.VerificationLevel.highest: ("server_settings_verif_highest", "server_settings_verif_highest_desc")
        }
        
        verif_key, verif_desc = verification_texts.get(guild.verification_level, ("unknown", "unknown"))
        if guild.verification_level in [discord.VerificationLevel.none, discord.VerificationLevel.low]:
            security_issues.append(f"🔴 **{language_handler.get_text(ctx.guild.id, verif_key)}** - {language_handler.get_text(ctx.guild.id, verif_desc)}")
        else:
            security_good.append(f"🟢 **{language_handler.get_text(ctx.guild.id, verif_key)}** - {language_handler.get_text(ctx.guild.id, verif_desc)}")
        
        # Check explicit content filter
        content_filter_texts = {
            discord.ContentFilter.disabled: ("server_settings_filter_disabled", "server_settings_filter_disabled_desc"),
            discord.ContentFilter.no_role: ("server_settings_filter_partial", "server_settings_filter_partial_desc"),
            discord.ContentFilter.all_members: ("server_settings_filter_full", "server_settings_filter_full_desc")
        }
        
        filter_key, filter_desc = content_filter_texts.get(guild.explicit_content_filter, ("unknown", "unknown"))
        if guild.explicit_content_filter == discord.ContentFilter.disabled:
            security_issues.append(f"🔴 **{language_handler.get_text(ctx.guild.id, filter_key)}** - {language_handler.get_text(ctx.guild.id, filter_desc)}")
        elif guild.explicit_content_filter == discord.ContentFilter.no_role:
            security_issues.append(f"🟡 **{language_handler.get_text(ctx.guild.id, filter_key)}** - {language_handler.get_text(ctx.guild.id, filter_desc)}")
        else:
            security_good.append(f"🟢 **{language_handler.get_text(ctx.guild.id, filter_key)}** - {language_handler.get_text(ctx.guild.id, filter_desc)}")
        
        # Check default notifications
        if guild.default_notifications == discord.NotificationLevel.all_messages:
            security_issues.append(f"🟡 **{language_handler.get_text(ctx.guild.id, 'server_settings_notif_all')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_notif_all_desc')}")
        else:
            security_good.append(f"✅ **{language_handler.get_text(ctx.guild.id, 'server_settings_notif_mentions')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_notif_mentions_desc')}")
        
        # Check NSFW level (if available)
        if hasattr(guild, 'nsfw_level'):
            if guild.nsfw_level == discord.NSFWLevel.explicit:
                security_issues.append(f"🔴 **{language_handler.get_text(ctx.guild.id, 'server_settings_nsfw_explicit')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_nsfw_explicit_desc')}")
            elif guild.nsfw_level == discord.NSFWLevel.safe:
                security_good.append(f"✅ **{language_handler.get_text(ctx.guild.id, 'server_settings_nsfw_safe')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_nsfw_safe_desc')}")
        
        # Check if server has community features enabled
        if "COMMUNITY" in guild.features:
            security_good.append(f"✅ **{language_handler.get_text(ctx.guild.id, 'server_settings_community')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_community_desc')}")
            
            # Check if server has moderation features
            if "AUTO_MODERATION" in guild.features:
                security_good.append(f"✅ **{language_handler.get_text(ctx.guild.id, 'server_settings_automod')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_automod_desc')}")
        else:
            security_issues.append(f"🟡 **{language_handler.get_text(ctx.guild.id, 'server_settings_no_community')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_no_community_desc')}")
        
        # Check server features for security-related ones
        security_features = []
        if "VERIFIED" in guild.features:
            security_features.append(f"✅ {language_handler.get_text(ctx.guild.id, 'server_settings_verified')}")
        if "PARTNERED" in guild.features:
            security_features.append(f"✅ {language_handler.get_text(ctx.guild.id, 'server_settings_partnered')}")
        if "AUTO_MODERATION" in guild.features:
            security_features.append(f"✅ {language_handler.get_text(ctx.guild.id, 'server_settings_automod')}")
        if "RAID_ALERTS_DISABLED" in guild.features:
            security_issues.append(f"🔴 **{language_handler.get_text(ctx.guild.id, 'server_settings_raid_alerts_disabled')}**")
        
        # Check server size vs verification level (risk assessment)
        member_count = guild.member_count
        if member_count > 1000 and guild.verification_level in [discord.VerificationLevel.none, discord.VerificationLevel.low]:
            security_issues.append(language_handler.get_text(ctx.guild.id, 'server_settings_large_server_risk').format(count=member_count))
        elif member_count > 100 and guild.verification_level == discord.VerificationLevel.none:
            security_issues.append(language_handler.get_text(ctx.guild.id, 'server_settings_medium_server_risk').format(count=member_count))
        
        # Create embed
        embed = discord.Embed(
            title=language_handler.get_text(ctx.guild.id, "server_settings_title"),
            color=discord.Color.red() if security_issues else discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        # Add server info
        embed.add_field(
            name=language_handler.get_text(ctx.guild.id, "server_settings_info"),
            value=f"**{language_handler.get_text(ctx.guild.id, 'name')}:** {guild.name}\n**{language_handler.get_text(ctx.guild.id, 'members')}:** {member_count}\n**{language_handler.get_text(ctx.guild.id, 'created')}:** <t:{int(guild.created_at.timestamp())}:R>",
            inline=False
        )
        
        # Add security issues
        if security_issues:
            issues_text = "\n".join(security_issues[:10])
            if len(security_issues) > 10:
                issues_text += f"\n{language_handler.get_text(ctx.guild.id, 'server_settings_more_issues').format(count=len(security_issues) - 10)}"
            embed.add_field(
                name=language_handler.get_text(ctx.guild.id, "server_settings_security_issues").format(count=len(security_issues)),
                value=issues_text,
                inline=False
            )
        
        # Add good security practices
        if security_good:
            good_text = "\n".join(security_good[:8])
            if len(security_good) > 8:
                good_text += f"\n{language_handler.get_text(ctx.guild.id, 'server_settings_more_good').format(count=len(security_good) - 8)}"
            embed.add_field(
                name=language_handler.get_text(ctx.guild.id, "server_settings_good_practices").format(count=len(security_good)),
                value=good_text,
                inline=False
            )
        
        # Add special features if any
        if security_features:
            embed.add_field(
                name=language_handler.get_text(ctx.guild.id, "server_settings_security_features"),
                value="\n".join(security_features),
                inline=False
            )
        
        # Add risk assessment
        risk_score = len(security_issues)
        if risk_score == 0:
            risk_text = f"🟢 **{language_handler.get_text(ctx.guild.id, 'server_settings_risk_low')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_risk_low_desc')}"
        elif risk_score <= 2:
            risk_text = f"🟡 **{language_handler.get_text(ctx.guild.id, 'server_settings_risk_medium')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_risk_medium_desc')}"
        elif risk_score <= 4:
            risk_text = f"🟠 **{language_handler.get_text(ctx.guild.id, 'server_settings_risk_high')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_risk_high_desc')}"
        else:
            risk_text = f"🔴 **{language_handler.get_text(ctx.guild.id, 'server_settings_risk_critical')}** - {language_handler.get_text(ctx.guild.id, 'server_settings_risk_critical_desc')}"
        
        embed.add_field(
            name=language_handler.get_text(ctx.guild.id, "server_settings_risk_level"),
            value=risk_text,
            inline=False
        )
        
        await ctx.send(embed=embed)
        
    async def execute_checks(self, ctx):
        """Execute all critical checks with delays between each check."""
        checks = [
            self.role_hierarchy_check,
            self.admin_leak_check,
            self.dangerous_perm_check,
            self.everyone_perm_check,
            self.unprotected_webhooks,
            self.server_settings_check
        ]
        
        for i, check in enumerate(checks):
            await check(ctx)
            if i < len(checks) - 1:
                await asyncio.sleep(3.0)

async def setup(bot):
    """Setup function for the cog."""
    await bot.add_cog(CriticalsChecks(bot))