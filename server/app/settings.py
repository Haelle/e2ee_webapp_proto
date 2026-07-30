from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="E2EE_", env_file=".env", extra="ignore")

    # dev par défaut ; surchargé par variables d'environnement en conteneur.
    database_url: str = "postgresql://e2ee:e2ee@127.0.0.1:5432/e2ee"
    session_secret: str = "dev-only-not-secret-change-me"
    # origines autorisées pour le SPA (CORS + cookies)
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    cookie_secure: bool = False  # True derrière HTTPS


settings = Settings()
