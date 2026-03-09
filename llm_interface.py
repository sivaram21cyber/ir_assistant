"""
LLM Interface Module

Provides integration with Ollama for local LLM inference.
Handles connection status, error handling, and response streaming.
"""

import requests
import json
from typing import Optional, Dict, Any, Generator
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OllamaLLM:
    """
    Interface for Ollama local LLM.
    
    Provides methods for checking connection status, generating responses,
    and handling errors gracefully when Ollama is unavailable.
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2:3b",
        timeout: int = 120
    ):
        """
        Initialize the Ollama LLM interface.
        
        Args:
            base_url: Ollama API base URL
            model: Model name to use for generation
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout
        self._connection_status = None
        self._available_models = []
    
    def check_connection(self) -> Dict[str, Any]:
        """
        Check if Ollama is running and accessible.
        
        Returns:
            Dictionary with connection status and details
        """
        try:
            # Check if Ollama is running
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                self._available_models = [m.get('name', '') for m in data.get('models', [])]
                model_available = any(self.model in m for m in self._available_models)
                
                self._connection_status = {
                    'connected': True,
                    'model_available': model_available,
                    'available_models': self._available_models,
                    'message': 'Connected to Ollama' if model_available else f'Model {self.model} not found'
                }
            else:
                self._connection_status = {
                    'connected': False,
                    'model_available': False,
                    'available_models': [],
                    'message': f'Ollama returned status {response.status_code}'
                }
                
        except requests.exceptions.ConnectionError:
            self._connection_status = {
                'connected': False,
                'model_available': False,
                'available_models': [],
                'message': 'Cannot connect to Ollama. Is it running?'
            }
        except requests.exceptions.Timeout:
            self._connection_status = {
                'connected': False,
                'model_available': False,
                'available_models': [],
                'message': 'Connection to Ollama timed out'
            }
        except Exception as e:
            self._connection_status = {
                'connected': False,
                'model_available': False,
                'available_models': [],
                'message': f'Error connecting to Ollama: {str(e)}'
            }
        
        return self._connection_status
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get the cached connection status or check if not cached.
        
        Returns:
            Connection status dictionary
        """
        if self._connection_status is None:
            return self.check_connection()
        return self._connection_status
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048
    ) -> Dict[str, Any]:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: User prompt
            system_prompt: System prompt for context
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Dictionary with response or error
        """
        # Check connection first
        status = self.check_connection()
        if not status['connected']:
            return {
                'success': False,
                'error': status['message'],
                'response': None
            }
        
        if not status['model_available']:
            return {
                'success': False,
                'error': f"Model '{self.model}' is not available. Available models: {', '.join(self._available_models)}",
                'response': None
            }
        
        try:
            payload = {
                'model': self.model,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': temperature,
                    'num_predict': max_tokens
                }
            }
            
            if system_prompt:
                payload['system'] = system_prompt
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'response': data.get('response', ''),
                    'model': data.get('model', self.model),
                    'eval_count': data.get('eval_count', 0),
                    'eval_duration': data.get('eval_duration', 0)
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}: {response.text}',
                    'response': None
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timed out. The model may be processing a complex query.',
                'response': None
            }
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return {
                'success': False,
                'error': f'Error generating response: {str(e)}',
                'response': None
            }
    
    def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048
    ) -> Generator[str, None, None]:
        """
        Generate a streaming response from the LLM.
        
        Args:
            prompt: User prompt
            system_prompt: System prompt for context
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Yields:
            Response text chunks
        """
        # Check connection first
        status = self.check_connection()
        if not status['connected']:
            yield f"Error: {status['message']}"
            return
        
        if not status['model_available']:
            yield f"Error: Model '{self.model}' is not available."
            return
        
        try:
            payload = {
                'model': self.model,
                'prompt': prompt,
                'stream': True,
                'options': {
                    'temperature': temperature,
                    'num_predict': max_tokens
                }
            }
            
            if system_prompt:
                payload['system'] = system_prompt
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                stream=True,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if 'response' in data:
                                yield data['response']
                            if data.get('done', False):
                                break
                        except json.JSONDecodeError:
                            continue
            else:
                yield f"Error: API returned status {response.status_code}"
                
        except Exception as e:
            logger.error(f"Error in streaming response: {e}")
            yield f"Error: {str(e)}"
    
    def list_models(self) -> list:
        """
        List available models in Ollama.
        
        Returns:
            List of available model names
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return [m.get('name', '') for m in data.get('models', [])]
        except Exception as e:
            logger.error(f"Error listing models: {e}")
        return []


# Singleton instance for easy import
_llm_instance = None


def get_llm(
    base_url: str = "http://localhost:11434",
    model: str = "llama3.2:3b"
) -> OllamaLLM:
    """
    Get or create a singleton LLM instance.
    
    Args:
        base_url: Ollama API base URL
        model: Model name to use
        
    Returns:
        OllamaLLM instance
    """
    global _llm_instance
    if _llm_instance is None or _llm_instance.model != model:
        _llm_instance = OllamaLLM(base_url=base_url, model=model)
    return _llm_instance
