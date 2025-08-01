# 📋 Guide Complet des Commandes - PrivEscCord

> **Bot de sécurité Discord** pour détecter les vulnérabilités, escalations de privilèges et risques de raid.

## 🚨 Commandes Critiques

### `$role_hierarchy_check`
**🔍 Vérification de la hiérarchie des rôles**
- **Description** : Détecte si des rôles décoratifs sont placés au-dessus de rôles avec des permissions importantes
- **Risque** : Escalation de privilèges, bypass de sécurité
- **Usage** : `$role_hierarchy_check`
- **Permissions requises** : Administrateur

### `$admin_leak_check`
**🛡️ Détection des fuites administrateur**
- **Description** : Vérifie si des rôles ont la permission Administrator sans surveillance appropriée
- **Risque** : Accès administratif non contrôlé, takeover de serveur
- **Usage** : `$admin_leak_check`
- **Permissions requises** : Administrateur

### `$dangerous_perm_check`
**⚠️ Scan des permissions dangereuses**
- **Description** : Liste tous les rôles avec des permissions critiques (ban, manage_guild, etc.)
- **Risque** : Abus de permissions modérateur/admin
- **Usage** : `$dangerous_perm_check`
- **Permissions requises** : Administrateur

### `$everyone_perm_check`
**👥 Audit du rôle @everyone**
- **Description** : Analyse les permissions du rôle @everyone dans tous les salons
- **Risque** : Permissions globales dangereuses, bypass de restrictions
- **Usage** : `$everyone_perm_check`
- **Permissions requises** : Administrateur

### `$unprotected_webhooks`
**🔗 Vulnérabilités webhook**
- **Description** : Détecte les salons où les webhooks peuvent être abusés
- **Risque** : Spam webhook, impersonation, raid massif
- **Usage** : `$unprotected_webhooks`
- **Permissions requises** : Administrateur

---

## 🟡 Commandes Moyennes

### `$spam_perm_check`
**📢 Détection des risques de spam**
- **Description** : Analyse les rôles pouvant spammer via diverses permissions
- **Risque** : Spam de messages, mentions abusives, flood
- **Usage** : `$spam_perm_check`
- **Permissions requises** : Administrateur

### `$mass_mention_check`
**📣 Contrôle des mentions massives**
- **Description** : Analyse les permissions de mention @everyone dans les salons
- **Risque** : Ping storm, harassment, disruption
- **Usage** : `$mass_mention_check`
- **Permissions requises** : Administrateur

### `$webhook_overflow_check`
**🔗 Comptage des webhooks**
- **Description** : Compte les webhooks actifs dans chaque salon (limite recommandée: 10)
- **Risque** : Saturation webhook, performance dégradée
- **Usage** : `$webhook_overflow_check`
- **Permissions requises** : Administrateur

### `$voice_damage_check`
**🎤 Audit des permissions vocales**
- **Description** : Analyse les rôles pouvant causer des dommages dans les salons vocaux
- **Risque** : Mute/déconnexion massive, disruption vocale
- **Usage** : `$voice_damage_check`
- **Permissions requises** : Administrateur

### `$channel_deletion_check`
**📁 Risques de suppression de salons**
- **Description** : Analyse les rôles pouvant supprimer/modifier des salons
- **Risque** : Destruction de salons, perte de données
- **Usage** : `$channel_deletion_check`
- **Permissions requises** : Administrateur

---

## 🔧 Commandes Utilitaires

### `$all_checks`
**🔍 Audit complet**
- **Description** : Exécute toutes les vérifications critiques et moyennes sur le serveur
- **Usage** : `$all_checks`
- **Permissions requises** : Administrateur
- **Note** : Peut prendre du temps selon la taille du serveur

### `$reload_cogs`
**⚙️ Rechargement des modules**
- **Description** : Recharge tous les cogs du bot pour appliquer les modifications
- **Usage** : `$reload_cogs`
- **Permissions requises** : Administrateur
- **Note** : Utile pour les mises à jour sans redémarrage

---

## 📊 Interprétation des Résultats

### 🚦 Niveaux de Risque
- **🔴 Critique** : Risque immédiat de takeover/nuke
- **🟡 Élevé** : Risque significatif à surveiller
- **🟢 Faible** : Configuration normale

### 📈 Métriques Importantes
- **Nombre de membres** : Plus il y a de membres avec des permissions, plus le risque est élevé
- **Position hiérarchique** : Les rôles hauts dans la hiérarchie sont plus dangereux
- **Combinaisons de permissions** : Certaines combinaisons créent des vulnérabilités

### 🛡️ Recommandations Générales
1. **Principe du moindre privilège** : Ne donnez que les permissions nécessaires
2. **Hiérarchie stricte** : Les rôles décoratifs doivent être en bas
3. **Surveillance des @everyone** : Vérifiez régulièrement les permissions globales
4. **Limitation des webhooks** : Max 10 par salon, gestion stricte
5. **Audit régulier** : Lancez `$all_checks` périodiquement

---

## ⚠️ Avertissements

- **Commandes réservées aux administrateurs** : Toutes les commandes nécessitent des permissions d'administrateur
- **Résultats à interpréter** : Les résultats sont des indicateurs, pas des menaces confirmées
- **Contexte important** : Certaines configurations peuvent être intentionnelles selon l'usage du serveur
- **Sauvegarde recommandée** : Effectuez des sauvegardes avant de modifier les permissions

---

*PrivEscCord v1.0 - Bot de sécurité Discord développé pour la détection proactive des vulnérabilités*
