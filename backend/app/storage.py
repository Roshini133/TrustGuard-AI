"""Artifact storage. local (persistent disk/volume) or s3 (S3-compatible: AWS S3, Cloudflare R2, Backblaze B2...).
Keys are opaque, never exposed as filesystem paths in API responses."""
import io
import os
from pathlib import Path

from .config import get_settings


class LocalStorage:
    def __init__(self):
        self.root = Path(get_settings().ARTIFACT_STORAGE_PATH).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _p(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if self.root not in p.parents and p != self.root:
            raise ValueError("invalid artifact key")
        return p

    def put(self, key: str, data: bytes):
        p = self._p(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)

    def get(self, key: str) -> bytes:
        return self._p(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._p(key).exists()


class S3Storage:
    def __init__(self):
        import boto3
        s = get_settings()
        self.bucket = s.S3_BUCKET
        self.c = boto3.client("s3", endpoint_url=s.S3_ENDPOINT_URL or None, aws_access_key_id=s.S3_ACCESS_KEY_ID,
                              aws_secret_access_key=s.S3_SECRET_ACCESS_KEY, region_name=s.S3_REGION)

    def put(self, key: str, data: bytes):
        self.c.put_object(Bucket=self.bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        return self.c.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def exists(self, key: str) -> bool:
        try:
            self.c.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False


_storage = None


def get_storage():
    global _storage
    if _storage is None:
        _storage = S3Storage() if get_settings().ARTIFACT_STORAGE_BACKEND == "s3" else LocalStorage()
    return _storage


def reset_storage():
    global _storage
    _storage = None
