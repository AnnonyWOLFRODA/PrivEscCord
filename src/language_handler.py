"""
Language handler for PrivEscCord.
Manages server language preferences and translations.
"""

import json
import os
from typing import Dict, Any
import discord

class LanguageHandler:
    """Handles language preferences and translations for servers."""
    
    def __init__(self):
        self.config_file = "data/server_languages.json"
        self.translations_dir = "data/translations"
        self.default_language = "en"
        self.supported_languages = {"English": "en", "Français": "fr", "Español": "es", "Deutsch": "de", "Italiano": "it"}

        # Ensure data directories exist
        os.makedirs("data", exist_ok=True)
        os.makedirs(self.translations_dir, exist_ok=True)
        
        self.server_languages = self._load_server_languages()
        self.translations = self._load_translations()
    
    def _load_server_languages(self) -> Dict[int, str]:
        """Load server language preferences from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Convert string keys back to int (JSON keys are always strings)
                    return {int(k): v for k, v in data.items()}
            return {}
        except Exception:
            return {}
    
    def _save_server_languages(self):
        """Save server language preferences to file."""
        try:
            # Convert int keys to string for JSON
            data = {str(k): v for k, v in self.server_languages.items()}
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    
    def _load_translations(self) -> Dict[str, Dict[str, Any]]:
        """Load all translation files."""
        translations = {}
        
        for lang in self.supported_languages.values():
            file_path = os.path.join(self.translations_dir, f"{lang}.json")
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        translations[lang] = json.load(f)
                except Exception:
                    translations[lang] = {}
            else:
                translations[lang] = {}
        
        return translations
    
    def set_server_language(self, guild_id: int, language: str) -> bool:
        """Set language preference for a server."""
        if language not in self.supported_languages.values():
            return False
        
        self.server_languages[guild_id] = language
        self._save_server_languages()
        return True
    
    def get_server_language(self, guild_id: int) -> str:
        """Get language preference for a server."""
        return self.server_languages.get(guild_id, self.default_language)
    
    def get_text(self, guild_id: int, key: str, **kwargs) -> str:
        """Get translated text for a server."""
        language = self.get_server_language(guild_id)
        
        if language in self.translations and key in self.translations[language]:
            text = self.translations[language][key]
        elif self.default_language in self.translations and key in self.translations[self.default_language]:
            text = self.translations[self.default_language][key]
        else:
            text = key

        try:
            return text.format(**kwargs)
        except:
            return text
    
    def get_supported_languages(self) -> list:
        """Get list of supported language codes."""
        return list(self.supported_languages.values())

    def get_language_name(self, lang_code: str) -> str:
        """Get human-readable language name."""
        if lang_code not in self.supported_languages.values():
            return "Unknown Language"
        for name, code in self.supported_languages.items():
            if code == lang_code:
                return name
        return "Unknown Language"

# Global language handler instance
language_handler = LanguageHandler()
