"""
State storage for OAuth2 flow.
"""
import time
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod

from ..models.auth import StateRecord
from ..exceptions.auth_exceptions import StateStoreException, InvalidStateException
from ..config.settings import settings
from ..middleware.logging_config import LoggerMixin


class StateStore(ABC):
    """Abstract base class for state storage."""
    
    @abstractmethod
    async def store(self, state: str, record: StateRecord) -> None:
        """Store a state record."""
        pass
    
    @abstractmethod
    async def retrieve(self, state: str) -> Optional[StateRecord]:
        """Retrieve and remove a state record."""
        pass
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove expired state records. Returns count of removed records."""
        pass


class InMemoryStateStore(StateStore, LoggerMixin):
    """In-memory state store for development."""
    
    def __init__(self):
        self._store: Dict[str, StateRecord] = {}
        self.logger.warning("Using in-memory state store - not suitable for production")
    
    async def store(self, state: str, record: StateRecord) -> None:
        """Store a state record."""
        try:
            self._store[state] = record
            self.logger.debug(f"Stored state record for state: {state[:8]}...")
        except Exception as e:
            self.logger.error(f"Failed to store state: {e}")
            raise StateStoreException("Failed to store state")
    
    async def retrieve(self, state: str) -> Optional[StateRecord]:
        """Retrieve and remove a state record."""
        try:
            record = self._store.pop(state, None)
            if record:
                # Check if expired
                if time.time() - record.created_at > settings.state_ttl_seconds:
                    self.logger.warning(f"Retrieved expired state: {state[:8]}...")
                    raise InvalidStateException("State has expired")
                
                self.logger.debug(f"Retrieved state record for state: {state[:8]}...")
                return record
            else:
                self.logger.warning(f"State not found: {state[:8]}...")
                return None
        except InvalidStateException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to retrieve state: {e}")
            raise StateStoreException("Failed to retrieve state")
    
    async def cleanup_expired(self) -> int:
        """Remove expired state records."""
        try:
            current_time = time.time()
            expired_states = [
                state for state, record in self._store.items()
                if current_time - record.created_at > settings.state_ttl_seconds
            ]
            
            for state in expired_states:
                del self._store[state]
            
            if expired_states:
                self.logger.info(f"Cleaned up {len(expired_states)} expired state records")
            
            return len(expired_states)
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired states: {e}")
            return 0


# Global state store instance
state_store = InMemoryStateStore()
