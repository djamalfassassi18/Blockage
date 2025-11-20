from datetime import datetime
from dataclasses import dataclass
from typing import Optional

@dataclass
class LoginAttempt:
    """Modèle représentant une tentative de connexion"""
    id: Optional[int]
    ip_address: str
    username: str
    success: bool
    attempt_time: datetime
    
    @classmethod
    def from_db_row(cls, row):
        """Crée une instance à partir d'une ligne de base de données"""
        return cls(
            id=row[0],
            ip_address=row[1],
            username=row[2],
            success=bool(row[3]),
            attempt_time=datetime.fromisoformat(row[4]) if isinstance(row[4], str) else row[4]
        )

@dataclass
class BlockedIP:
    """Modèle représentant une IP bloquée"""
    id: Optional[int]
    ip_address: str
    block_reason: str
    block_time: datetime
    unblock_time: datetime
    
    @classmethod
    def from_db_row(cls, row):
        """Crée une instance à partir d'une ligne de base de données"""
        return cls(
            id=row[0],
            ip_address=row[1],
            block_reason=row[2],
            block_time=datetime.fromisoformat(row[3]) if isinstance(row[3], str) else row[3],
            unblock_time=datetime.fromisoformat(row[4]) if isinstance(row[4], str) else row[4]
        )
    
    @property
    def time_remaining(self) -> str:
        """Retourne le temps restant avant déblocage"""
        now = datetime.now()
        if now > self.unblock_time:
            return "Débloquée"
        
        delta = self.unblock_time - now
        minutes = delta.seconds // 60
        return f"{minutes} min"